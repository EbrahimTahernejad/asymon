// asymon client — runs INSIDE Iran.
//
// Bridges a local UDP app (KCP/QUIC/etc.) to the asymon server asymmetrically:
//   Uplink:   local UDP → [len:2][payload] frames → TCP via SOCKS5 → server
//   Downlink: spoofed UDP → recvConn (0.0.0.0:-myport) → local app
//
// Two UDP sockets:
//   localConn  binds -local            talks to your KCP/QUIC app
//   recvConn   binds 0.0.0.0:-myport   receives spoofed downlink from server
package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

const (
	maxPkt  = 65507
	sockBuf = 8 << 20
)

var (
	socksAddr  = flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy addr for uplink TCP")
	serverAddr = flag.String("server", "", "asymon server TCP addr (required)")
	localAddr  = flag.String("local", ":5555", "local UDP addr — your KCP/QUIC app connects here")
	myIP       = flag.String("myip", "", "your real external IPv4 (server sends spoofed UDP here)")
	myPort     = flag.Int("myport", 0, "UDP port to receive spoofed downlink on (0 = same as -local port)")
	verbose    = flag.Bool("v", false, "verbose logging (every packet, hex dumps)")
)

func vlog(f string, a ...any) {
	if *verbose {
		log.Printf("[V] "+f, a...)
	}
}

// recvPool holds buffers for incoming UDP packets.
var recvPool = sync.Pool{New: func() any {
	b := make([]byte, maxPkt)
	return &b
}}

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if *serverAddr == "" {
		log.Fatal("-server is required")
	}
	if *myIP == "" {
		log.Fatal("-myip is required (your real Iran-side IPv4)")
	}

	realIP4 := mustIP4(*myIP)

	laddr, err := net.ResolveUDPAddr("udp4", *localAddr)
	if err != nil {
		log.Fatalf("resolve local %q: %v", *localAddr, err)
	}

	udpPort := uint16(*myPort)
	if udpPort == 0 {
		udpPort = uint16(laddr.Port)
	}

	log.Printf("asymon client starting")
	log.Printf("  socks5 proxy  : %v", *socksAddr)
	log.Printf("  server        : %v", *serverAddr)
	log.Printf("  local UDP     : %v  (KCP/QUIC app here)", *localAddr)
	log.Printf("  downlink recv : 0.0.0.0:%d  (spoofed UDP arrives here)", udpPort)
	log.Printf("  my real IP    : %v:%d", net.IP(realIP4[:]), udpPort)
	if *verbose {
		log.Printf("  verbose       : ON")
	}

	// ── socket 1: local app ────────────────────────────────────────────────
	localConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatalf("listen local UDP %v: %v", laddr, err)
	}
	localConn.SetReadBuffer(sockBuf)
	localConn.SetWriteBuffer(sockBuf)
	log.Printf("localConn  ready on %v", laddr)

	// ── socket 2: downlink receiver ────────────────────────────────────────
	recvAddrStr := fmt.Sprintf("0.0.0.0:%d", udpPort)
	recvAddr, _ := net.ResolveUDPAddr("udp4", recvAddrStr)
	recvConn, err := net.ListenUDP("udp4", recvAddr)
	if err != nil {
		log.Fatalf("listen downlink UDP %v: %v", recvAddrStr, err)
	}
	recvConn.SetReadBuffer(sockBuf)
	recvConn.SetWriteBuffer(sockBuf)
	log.Printf("recvConn   ready on %v  (waiting for spoofed downlink)", recvAddrStr)

	// ── dial server via SOCKS5 ─────────────────────────────────────────────
	t0 := time.Now()
	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("socks5 dialer: %v", err)
	}
	tc, err := dialer.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("dial server via socks5: %v", err)
	}
	// Disable Nagle — our frames must go out immediately.
	if tcConn, ok := tc.(*net.TCPConn); ok {
		tcConn.SetNoDelay(true)
		tcConn.SetKeepAlive(true)
		tcConn.SetKeepAlivePeriod(30 * time.Second)
	}
	log.Printf("TCP connected to %v via socks5 %v (took %v)",
		*serverAddr, *socksAddr, time.Since(t0).Round(time.Millisecond))

	// ── handshake ──────────────────────────────────────────────────────────
	var hs [6]byte
	copy(hs[0:4], realIP4[:])
	binary.BigEndian.PutUint16(hs[4:6], udpPort)
	vlog("handshake: %s (ip=%v port=%d)", hex.EncodeToString(hs[:]), net.IP(realIP4[:]), udpPort)
	if _, err := tc.Write(hs[:]); err != nil {
		log.Fatalf("handshake write: %v", err)
	}
	log.Printf("handshake sent — %v:%d", net.IP(realIP4[:]), udpPort)

	var (
		appAddrMu sync.RWMutex
		appAddr   *net.UDPAddr

		uplinkPkts    atomic.Uint64
		uplinkBytes   atomic.Uint64
		downlinkPkts  atomic.Uint64
		downlinkBytes atomic.Uint64
		droppedPkts   atomic.Uint64
	)

	// lenPrefix is a 2-byte header reused (not shared between goroutines).
	var wg sync.WaitGroup
	wg.Add(2)

	// ── uplink: localConn → TCP frames ─────────────────────────────────────
	go func() {
		defer wg.Done()
		defer tc.Close()

		bp := recvPool.Get().(*[]byte)
		buf := *bp
		defer recvPool.Put(bp)

		var lenBuf [2]byte

		for {
			n, addr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				vlog("uplink: read error: %v", err)
				return
			}

			pktNum := uplinkPkts.Add(1)
			uplinkBytes.Add(uint64(n))

			appAddrMu.Lock()
			changed := appAddr == nil || appAddr.String() != addr.String()
			appAddr = addr
			appAddrMu.Unlock()
			if changed {
				log.Printf("uplink: local app addr → %v", addr)
			}

			vlog("up#%d %d B from %v", pktNum, n, addr)
			if *verbose && n <= 64 {
				vlog("up#%d hex: %s", pktNum, hex.EncodeToString(buf[:n]))
			}

			binary.BigEndian.PutUint16(lenBuf[:], uint16(n))

			// net.Buffers → single writev syscall, no copy of payload.
			bufs := net.Buffers{lenBuf[:], buf[:n]}
			if _, err := bufs.WriteTo(tc); err != nil {
				log.Printf("up#%d: TCP write: %v", pktNum, err)
				return
			}
		}
	}()

	// ── downlink: recvConn (spoofed UDP) → localConn → app ────────────────
	go func() {
		defer wg.Done()
		defer localConn.Close()

		bp := recvPool.Get().(*[]byte)
		buf := *bp
		defer recvPool.Put(bp)

		for {
			n, from, err := recvConn.ReadFromUDP(buf)
			if err != nil {
				vlog("downlink: read error: %v", err)
				return
			}

			pktNum := downlinkPkts.Add(1)
			downlinkBytes.Add(uint64(n))

			appAddrMu.RLock()
			dst := appAddr
			appAddrMu.RUnlock()

			if dst == nil {
				dropped := droppedPkts.Add(1)
				vlog("dn#%d %d B from %v — DROPPED (no app addr yet, total=%d)",
					pktNum, n, from, dropped)
				continue
			}

			vlog("dn#%d %d B from %v → app %v", pktNum, n, from, dst)
			if *verbose && n <= 64 {
				vlog("dn#%d hex: %s", pktNum, hex.EncodeToString(buf[:n]))
			}

			if _, err := localConn.WriteToUDP(buf[:n], dst); err != nil {
				log.Printf("dn#%d: deliver to app: %v", pktNum, err)
			}
		}
	}()

	wg.Wait()

	log.Printf("session closed")
	log.Printf("  uplink   : %d pkts / %s", uplinkPkts.Load(), fmtBytes(uplinkBytes.Load()))
	log.Printf("  downlink : %d pkts / %s", downlinkPkts.Load(), fmtBytes(downlinkBytes.Load()))
	if droppedPkts.Load() > 0 {
		log.Printf("  dropped  : %d pkts", droppedPkts.Load())
	}
}

func mustIP4(s string) [4]byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4 %q", s)
	}
	return [4]byte(ip)
}

func fmtBytes(b uint64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.2f KiB", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
