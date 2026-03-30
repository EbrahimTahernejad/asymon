// asymon server — runs OUTSIDE Iran.
//
// Uplink:   clients connect via SOCKS5 TCP → server receives data frames
// Downlink: server sends responses to client's real Iran IP via spoofed UDP
//
// Wire format over TCP (client → server):
//   Handshake (6 bytes):  [client real IPv4: 4][client UDP listen port: 2 BE]
//   Data frames:          [length: 2 BE][payload: N] ...
//
// Wire format server → client (UDP, spoofed source):
//   Raw payload, no framing (UDP is already message-oriented)
//
// Requires CAP_NET_RAW / root for spoofed sends.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxPkt    = 65507
	sockBuf   = 8 << 20
	tcpBufSz  = 64 << 10 // bufio read buffer per connection
)

var (
	listenAddr  = flag.String("l", ":4444", "TCP listen addr (clients connect here via SOCKS5)")
	backendAddr = flag.String("b", "127.0.0.1:5555", "backend UDP addr (KCP/QUIC server)")
	spoofSrc    = flag.String("spoof-src", "", "spoof source IP for UDP downlink (required)")
	verbose     = flag.Bool("v", false, "verbose logging (every packet, hex dumps, timing)")
)

func vlog(f string, a ...any) {
	if *verbose {
		log.Printf("[V] "+f, a...)
	}
}

// pktPool holds pre-allocated send buffers (IP+UDP+payload).
var pktPool = sync.Pool{New: func() any {
	b := make([]byte, 28+maxPkt)
	return &b
}}

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if *spoofSrc == "" {
		log.Fatal("-spoof-src is required")
	}

	src4 := mustIP4(*spoofSrc)

	baddr, err := net.ResolveUDPAddr("udp4", *backendAddr)
	if err != nil {
		log.Fatalf("resolve backend %q: %v", *backendAddr, err)
	}

	rawFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatalf("raw socket (needs CAP_NET_RAW): %v", err)
	}
	if err := syscall.SetsockoptInt(rawFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		log.Fatalf("IP_HDRINCL: %v", err)
	}
	vlog("raw socket fd=%d opened with IP_HDRINCL", rawFd)

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen TCP %v: %v", *listenAddr, err)
	}

	log.Printf("asymon server ready")
	log.Printf("  TCP listen    : %v", *listenAddr)
	log.Printf("  backend UDP   : %v", baddr)
	log.Printf("  spoof src     : %v", net.IP(src4[:]))
	if *verbose {
		log.Printf("  verbose       : ON")
	}

	srv := &Server{rawFd: rawFd, spoofSrc: src4, backend: baddr}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		// Disable Nagle — we control framing, small writes must go immediately.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetNoDelay(true)
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(30 * time.Second)
		}
		vlog("accepted TCP from %v", conn.RemoteAddr())
		go srv.handle(conn)
	}
}

// ── server ────────────────────────────────────────────────────────────────────

type Server struct {
	rawFd    int
	spoofSrc [4]byte
	backend  *net.UDPAddr
}

func (s *Server) handle(tc net.Conn) {
	defer tc.Close()
	remote := tc.RemoteAddr()
	connStart := time.Now()

	// Handshake: [client real IPv4: 4][client UDP port: 2]
	var hs [6]byte
	if _, err := io.ReadFull(tc, hs[:]); err != nil {
		log.Printf("%v: handshake: %v", remote, err)
		return
	}
	clientIP4 := [4]byte(hs[0:4])
	clientPort := binary.BigEndian.Uint16(hs[4:6])
	log.Printf("%v: client real addr %v:%d", remote, net.IP(clientIP4[:]), clientPort)
	vlog("%v: handshake bytes: %s", remote, hex.EncodeToString(hs[:]))

	up, err := net.DialUDP("udp4", nil, s.backend)
	if err != nil {
		log.Printf("%v: dial backend: %v", remote, err)
		return
	}
	up.SetReadBuffer(sockBuf)
	up.SetWriteBuffer(sockBuf)
	defer up.Close()

	// Per-session rand — avoids global lock on hot path.
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	var (
		wg            sync.WaitGroup
		uplinkPkts    atomic.Uint64
		uplinkBytes   atomic.Uint64
		downlinkPkts  atomic.Uint64
		downlinkBytes atomic.Uint64
	)
	wg.Add(2)

	// ── uplink: TCP → backend UDP ──────────────────────────────────────────
	go func() {
		defer wg.Done()
		defer up.Close()

		// bufio.Reader amortises the 2-byte length reads into large kernel reads.
		br := bufio.NewReaderSize(tc, tcpBufSz)
		var lenBuf [2]byte
		buf := make([]byte, maxPkt)

		for {
			if _, err := io.ReadFull(br, lenBuf[:]); err != nil {
				vlog("%v: uplink EOF: %v", remote, err)
				return
			}
			n := int(binary.BigEndian.Uint16(lenBuf[:]))
			if n == 0 || n > maxPkt {
				log.Printf("%v: uplink: bad frame len %d", remote, n)
				return
			}
			if _, err := io.ReadFull(br, buf[:n]); err != nil {
				vlog("%v: uplink read payload: %v", remote, err)
				return
			}

			pktNum := uplinkPkts.Add(1)
			uplinkBytes.Add(uint64(n))
			vlog("%v: up#%d %d B → backend", remote, pktNum, n)

			if _, err := up.Write(buf[:n]); err != nil {
				log.Printf("%v: uplink write backend: %v", remote, err)
				return
			}
		}
	}()

	// ── downlink: backend UDP → spoofed UDP → client ───────────────────────
	go func() {
		defer wg.Done()
		defer tc.Close()

		buf := make([]byte, maxPkt)
		for {
			n, err := up.Read(buf)
			if err != nil {
				vlog("%v: downlink backend read: %v", remote, err)
				return
			}

			pktNum := downlinkPkts.Add(1)
			downlinkBytes.Add(uint64(n))
			vlog("%v: dn#%d %d B → %v:%d", remote, pktNum, n, net.IP(clientIP4[:]), clientPort)

			if err := s.sendSpoofed(rng, clientIP4, clientPort, buf[:n]); err != nil {
				log.Printf("%v: dn#%d sendSpoofed: %v", remote, pktNum, err)
			}
		}
	}()

	wg.Wait()
	dur := time.Since(connStart)
	log.Printf("%v: closed — %v  up=%d/%s  dn=%d/%s",
		remote, dur.Round(time.Millisecond),
		uplinkPkts.Load(), fmtBytes(uplinkBytes.Load()),
		downlinkPkts.Load(), fmtBytes(downlinkBytes.Load()),
	)
}

// ── spoofed send ──────────────────────────────────────────────────────────────

func (s *Server) sendSpoofed(rng *rand.Rand, dst4 [4]byte, dstPort uint16, payload []byte) error {
	totalLen := uint16(20 + 8 + len(payload))
	udpLen   := uint16(8 + len(payload))

	// Get a pre-allocated buffer from the pool.
	bp := pktPool.Get().(*[]byte)
	pkt := (*bp)[:totalLen]
	defer pktPool.Put(bp)

	// IPv4 header — flags=0 (no DF), random ID per packet.
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], totalLen)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rng.Intn(65536))) // random ID
	pkt[6], pkt[7] = 0, 0                                          // no DF, no fragment
	pkt[8] = 64
	pkt[9] = 17
	pkt[10], pkt[11] = 0, 0 // checksum, filled below
	copy(pkt[12:16], s.spoofSrc[:])
	copy(pkt[16:20], dst4[:])

	// UDP header — random ephemeral source port per packet.
	binary.BigEndian.PutUint16(pkt[20:22], uint16(1024+rng.Intn(64512)))
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], udpLen)
	pkt[26], pkt[27] = 0, 0 // UDP checksum, filled below

	copy(pkt[28:], payload)

	// IP header checksum.
	var ipSum uint32
	for i := 0; i < 20; i += 2 {
		ipSum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for ipSum>>16 != 0 {
		ipSum = (ipSum & 0xffff) + (ipSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(ipSum))

	// UDP checksum with pseudo-header.
	ck := udpChecksum(pkt[12:16], pkt[16:20], pkt[20:totalLen])
	binary.BigEndian.PutUint16(pkt[26:28], ck)

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst4[:])
	return syscall.Sendto(s.rawFd, pkt, 0, &sa)
}

// udpChecksum computes the UDP checksum using the IPv4 pseudo-header.
func udpChecksum(src4, dst4, udpSeg []byte) uint16 {
	length := uint16(len(udpSeg))
	var sum uint32
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += 17
	sum += uint32(length)
	for i := 0; i+1 < len(udpSeg); i += 2 {
		sum += uint32(udpSeg[i])<<8 | uint32(udpSeg[i+1])
	}
	if len(udpSeg)%2 != 0 {
		sum += uint32(udpSeg[len(udpSeg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	if r := ^uint16(sum); r != 0 {
		return r
	}
	return 0xffff
}

// ── helpers ───────────────────────────────────────────────────────────────────

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
