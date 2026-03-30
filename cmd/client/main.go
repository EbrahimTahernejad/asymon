// asymon client — runs INSIDE Iran.
//
// Bridges a local UDP app (KCP/QUIC/etc.) to the asymon server asymmetrically:
//   Uplink:   local UDP → frame → TCP via SOCKS5 proxy → server
//   Downlink: server spoofed UDP → recvConn (0.0.0.0:-myport) → local UDP app
//
// Two separate UDP sockets are used:
//   localConn  binds -local  — talks to the KCP/QUIC app
//   recvConn   binds 0.0.0.0:-myport — receives spoofed downlink from server
//
// The local KCP/QUIC app should connect to -local as if it were the remote server.
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
	myIP       = flag.String("myip", "", "your real external IPv4 (sent to server so it knows where to spoof-reply)")
	myPort     = flag.Int("myport", 0, "UDP port to receive spoofed downlink on (0 = same as -local port)")
	verbose    = flag.Bool("v", false, "verbose logging (every packet, hex dumps, timing)")
)

func vlog(f string, a ...any) {
	if *verbose {
		log.Printf("[V] "+f, a...)
	}
}

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
	log.Printf("  local UDP     : %v  (KCP/QUIC app connects here)", *localAddr)
	log.Printf("  downlink recv : 0.0.0.0:%d  (spoofed UDP arrives here)", udpPort)
	log.Printf("  my real IP    : %v:%d", net.IP(realIP4[:]), udpPort)
	if *verbose {
		log.Printf("  verbose       : ON")
	}

	// ── socket 1: local app ────────────────────────────────────────────────
	vlog("binding localConn %v", laddr)
	localConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatalf("listen local UDP %v: %v", laddr, err)
	}
	localConn.SetReadBuffer(sockBuf)
	localConn.SetWriteBuffer(sockBuf)
	log.Printf("localConn ready on %v", laddr)

	// ── socket 2: downlink receiver ────────────────────────────────────────
	recvAddrStr := fmt.Sprintf("0.0.0.0:%d", udpPort)
	recvAddr, _ := net.ResolveUDPAddr("udp4", recvAddrStr)
	vlog("binding recvConn %v", recvAddrStr)
	recvConn, err := net.ListenUDP("udp4", recvAddr)
	if err != nil {
		log.Fatalf("listen downlink UDP %v: %v", recvAddrStr, err)
	}
	recvConn.SetReadBuffer(sockBuf)
	recvConn.SetWriteBuffer(sockBuf)
	log.Printf("recvConn  ready on %v  (waiting for spoofed downlink)", recvAddrStr)

	// ── dial server via SOCKS5 ─────────────────────────────────────────────
	vlog("creating SOCKS5 dialer via %v", *socksAddr)
	t0 := time.Now()
	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("socks5 dialer: %v", err)
	}
	vlog("dialing %v through SOCKS5 ...", *serverAddr)
	tc, err := dialer.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("dial server via socks5: %v", err)
	}
	log.Printf("TCP connected to %v via socks5 %v (took %v)",
		*serverAddr, *socksAddr, time.Since(t0).Round(time.Millisecond))

	// ── handshake ──────────────────────────────────────────────────────────
	var hs [6]byte
	copy(hs[0:4], realIP4[:])
	binary.BigEndian.PutUint16(hs[4:6], udpPort)
	vlog("sending handshake: %s (ip=%v port=%d)", hex.EncodeToString(hs[:]), net.IP(realIP4[:]), udpPort)
	if _, err := tc.Write(hs[:]); err != nil {
		log.Fatalf("handshake write: %v", err)
	}
	log.Printf("handshake sent — announced real addr %v:%d to server", net.IP(realIP4[:]), udpPort)

	// appAddr: where the local KCP/QUIC app is (learned from first uplink packet)
	var (
		appAddrMu sync.RWMutex
		appAddr   *net.UDPAddr

		uplinkPkts    atomic.Uint64
		uplinkBytes   atomic.Uint64
		downlinkPkts  atomic.Uint64
		downlinkBytes atomic.Uint64
		droppedPkts   atomic.Uint64
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// ── uplink: localConn → TCP frames → server ────────────────────────────
	go func() {
		defer wg.Done()
		defer tc.Close()
		buf := make([]byte, maxPkt)
		for {
			n, addr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				vlog("uplink: localConn read error: %v", err)
				return
			}

			pktNum := uplinkPkts.Add(1)
			uplinkBytes.Add(uint64(n))

			appAddrMu.Lock()
			changed := appAddr == nil || appAddr.String() != addr.String()
			appAddr = addr
			appAddrMu.Unlock()
			if changed {
				log.Printf("uplink: local app addr set to %v", addr)
			}

			vlog("uplink pkt#%d — %d bytes from %v → TCP → server", pktNum, n, addr)
			if *verbose {
				vlog("uplink pkt#%d payload hex: %s", pktNum, hexDump(buf[:n]))
			}

			frame := make([]byte, 2+n)
			binary.BigEndian.PutUint16(frame[:2], uint16(n))
			copy(frame[2:], buf[:n])
			if _, err := tc.Write(frame); err != nil {
				log.Printf("uplink pkt#%d: TCP write failed: %v", pktNum, err)
				return
			}
			vlog("uplink pkt#%d: sent %d-byte frame to server", pktNum, 2+n)
		}
	}()

	// ── downlink: recvConn (spoofed UDP) → localConn → local app ──────────
	go func() {
		defer wg.Done()
		defer localConn.Close()
		buf := make([]byte, maxPkt)
		for {
			n, from, err := recvConn.ReadFromUDP(buf)
			if err != nil {
				vlog("downlink: recvConn read error: %v", err)
				return
			}

			pktNum := downlinkPkts.Add(1)
			downlinkBytes.Add(uint64(n))

			appAddrMu.RLock()
			dst := appAddr
			appAddrMu.RUnlock()

			if dst == nil {
				dropped := droppedPkts.Add(1)
				vlog("downlink pkt#%d — %d bytes from %v DROPPED (no uplink seen yet, total dropped=%d)",
					pktNum, n, from, dropped)
				continue
			}

			vlog("downlink pkt#%d — %d bytes from %v (spoofed) → local app %v", pktNum, n, from, dst)
			if *verbose {
				vlog("downlink pkt#%d payload hex: %s", pktNum, hexDump(buf[:n]))
			}

			if _, err := localConn.WriteToUDP(buf[:n], dst); err != nil {
				log.Printf("downlink pkt#%d: deliver to local app failed: %v", pktNum, err)
			} else {
				vlog("downlink pkt#%d: delivered %d bytes to %v", pktNum, n, dst)
			}
		}
	}()

	wg.Wait()

	log.Printf("session closed")
	log.Printf("  uplink   : %d pkts / %s", uplinkPkts.Load(), fmtBytes(uplinkBytes.Load()))
	log.Printf("  downlink : %d pkts / %s", downlinkPkts.Load(), fmtBytes(downlinkBytes.Load()))
	log.Printf("  dropped  : %d pkts (downlink before first uplink)", droppedPkts.Load())
}

func mustIP4(s string) [4]byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4 %q", s)
	}
	return [4]byte(ip)
}

func hexDump(b []byte) string {
	if len(b) <= 64 {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:64]) + " ..."
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
