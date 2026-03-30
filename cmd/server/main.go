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
	maxPkt  = 65507
	sockBuf = 8 << 20
)

var (
	listenAddr  = flag.String("l", ":4444", "TCP listen addr (clients connect here via SOCKS5)")
	backendAddr = flag.String("b", "127.0.0.1:5555", "backend UDP addr (KCP/QUIC server)")
	spoofSrc    = flag.String("spoof-src", "", "spoof source IP for UDP downlink (required)")
	spoofPort   = flag.Int("spoof-port", 0, "spoof source port (0 = same as -l port)")
	verbose     = flag.Bool("v", false, "verbose logging (every packet, hex dumps, timing)")
)

func vlog(f string, a ...any) {
	if *verbose {
		log.Printf("[V] "+f, a...)
	}
}

func main() {
	flag.Parse()
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	if *spoofSrc == "" {
		log.Fatal("-spoof-src is required")
	}

	src4 := mustIP4(*spoofSrc)
	sp := uint16(*spoofPort)
	if sp == 0 {
		_, portStr, _ := net.SplitHostPort(*listenAddr)
		var p int
		for _, b := range []byte(portStr) {
			p = p*10 + int(b-'0')
		}
		sp = uint16(p)
	}

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
	log.Printf("  spoof src     : %v:%d", net.IP(src4[:]), sp)
	if *verbose {
		log.Printf("  verbose       : ON")
	}

	srv := &Server{rawFd: rawFd, spoofSrc: src4, spoofPort: sp, backend: baddr}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		vlog("accepted TCP connection from %v", conn.RemoteAddr())
		go srv.handle(conn)
	}
}

// ── server ────────────────────────────────────────────────────────────────────

type Server struct {
	rawFd     int
	spoofSrc  [4]byte
	spoofPort uint16
	backend   *net.UDPAddr
}

func (s *Server) handle(tc net.Conn) {
	defer tc.Close()
	remote := tc.RemoteAddr()
	connStart := time.Now()

	vlog("%v: reading 6-byte handshake", remote)

	// Handshake: [client real IPv4: 4][client UDP port: 2]
	var hs [6]byte
	if _, err := io.ReadFull(tc, hs[:]); err != nil {
		log.Printf("%v: handshake read failed: %v", remote, err)
		return
	}
	clientIP4 := [4]byte(hs[0:4])
	clientPort := binary.BigEndian.Uint16(hs[4:6])

	log.Printf("%v: handshake OK — client real addr %v:%d", remote, net.IP(clientIP4[:]), clientPort)
	vlog("%v: handshake raw bytes: %s", remote, hex.EncodeToString(hs[:]))

	// Dial backend UDP
	vlog("%v: dialing backend UDP %v", remote, s.backend)
	up, err := net.DialUDP("udp4", nil, s.backend)
	if err != nil {
		log.Printf("%v: dial backend failed: %v", remote, err)
		return
	}
	up.SetReadBuffer(sockBuf)
	up.SetWriteBuffer(sockBuf)
	defer up.Close()
	vlog("%v: backend UDP socket ready (rcvbuf=%d snduf=%d)", remote, sockBuf, sockBuf)

	// Pre-build IP+UDP header template for this client
	var hdr hdrTemplate
	hdr.build(s.spoofSrc, clientIP4, s.spoofPort, clientPort)
	vlog("%v: session ready — spoof src=%v dst=%v:%d",
		remote, net.IP(s.spoofSrc[:]), net.IP(clientIP4[:]), clientPort,
	)

	var (
		wg         sync.WaitGroup
		uplinkPkts atomic.Uint64
		uplinkBytes atomic.Uint64
		downlinkPkts atomic.Uint64
		downlinkBytes atomic.Uint64
	)
	wg.Add(2)

	// TCP → UDP backend (uplink)
	go func() {
		defer wg.Done()
		defer up.Close()
		var lenBuf [2]byte
		buf := make([]byte, maxPkt)
		for {
			if _, err := io.ReadFull(tc, lenBuf[:]); err != nil {
				vlog("%v: uplink: TCP length read: %v", remote, err)
				return
			}
			n := int(binary.BigEndian.Uint16(lenBuf[:]))
			if n == 0 || n > maxPkt {
				log.Printf("%v: uplink: invalid frame length %d, closing", remote, n)
				return
			}
			if _, err := io.ReadFull(tc, buf[:n]); err != nil {
				vlog("%v: uplink: TCP payload read: %v", remote, err)
				return
			}

			pktNum := uplinkPkts.Add(1)
			uplinkBytes.Add(uint64(n))

			vlog("%v: uplink pkt#%d — %d bytes → backend", remote, pktNum, n)
			if *verbose && n <= 64 {
				vlog("%v: uplink pkt#%d payload hex: %s", remote, pktNum, hex.EncodeToString(buf[:n]))
			} else if *verbose {
				vlog("%v: uplink pkt#%d payload hex (first 64): %s ...", remote, pktNum, hex.EncodeToString(buf[:64]))
			}

			sent, err := up.Write(buf[:n])
			if err != nil {
				log.Printf("%v: uplink: backend write failed: %v", remote, err)
				return
			}
			vlog("%v: uplink pkt#%d — wrote %d/%d bytes to backend UDP", remote, pktNum, sent, n)
		}
	}()

	// UDP backend → spoofed UDP → client (downlink)
	go func() {
		defer wg.Done()
		defer tc.Close()
		buf := make([]byte, maxPkt)
		for {
			n, err := up.Read(buf)
			if err != nil {
				vlog("%v: downlink: backend read: %v", remote, err)
				return
			}

			pktNum := downlinkPkts.Add(1)
			downlinkBytes.Add(uint64(n))

			vlog("%v: downlink pkt#%d — %d bytes from backend → spoofed UDP → %v:%d",
				remote, pktNum, n, net.IP(clientIP4[:]), clientPort)
			if *verbose && n <= 64 {
				vlog("%v: downlink pkt#%d payload hex: %s", remote, pktNum, hex.EncodeToString(buf[:n]))
			} else if *verbose {
				vlog("%v: downlink pkt#%d payload hex (first 64): %s ...", remote, pktNum, hex.EncodeToString(buf[:64]))
			}

			if err := s.sendSpoofed(&hdr, clientIP4, buf[:n]); err != nil {
				log.Printf("%v: downlink pkt#%d: sendSpoofed failed: %v", remote, pktNum, err)
			} else {
				vlog("%v: downlink pkt#%d: raw sendto OK (%d IP bytes total)",
					remote, pktNum, 28+n)
			}
		}
	}()

	wg.Wait()

	dur := time.Since(connStart)
	log.Printf("%v: session closed — duration=%v uplink=%d pkts/%s downlink=%d pkts/%s",
		remote, dur.Round(time.Millisecond),
		uplinkPkts.Load(), fmtBytes(uplinkBytes.Load()),
		downlinkPkts.Load(), fmtBytes(downlinkBytes.Load()),
	)
}

func (s *Server) sendSpoofed(h *hdrTemplate, dst4 [4]byte, payload []byte) error {
	totalLen := uint16(20 + 8 + len(payload))
	udpLen   := uint16(8 + len(payload))
	srcPort  := uint16(1024 + rand.Intn(64512)) // random ephemeral src port per packet
	ipID     := uint16(rand.Intn(65536))

	pkt := make([]byte, int(totalLen))

	// IPv4 header — no DF flag (flags_frag = 0), matches Python behaviour
	pkt[0] = 0x45
	pkt[1] = 0
	binary.BigEndian.PutUint16(pkt[2:4], totalLen)
	binary.BigEndian.PutUint16(pkt[4:6], ipID)
	pkt[6], pkt[7] = 0, 0 // flags=0, frag offset=0 — NO DF
	pkt[8] = 64
	pkt[9] = 17
	// [10:12] checksum filled below
	copy(pkt[12:16], h.src4[:]) // src IP
	copy(pkt[16:20], dst4[:])

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)
	binary.BigEndian.PutUint16(pkt[22:24], h.dstPort)
	binary.BigEndian.PutUint16(pkt[24:26], udpLen)
	// [26:28] UDP checksum filled below

	copy(pkt[28:], payload)

	// IP checksum
	var ipSum uint32
	for i := 0; i < 20; i += 2 {
		ipSum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for ipSum>>16 != 0 {
		ipSum = (ipSum & 0xffff) + (ipSum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(ipSum))

	// UDP checksum
	udpCksum := udpChecksum(pkt[12:16], pkt[16:20], pkt[20:])
	binary.BigEndian.PutUint16(pkt[26:28], udpCksum)

	vlog("sendSpoofed: src_port=%d id=%d total=%d IP hdr: %s",
		srcPort, ipID, totalLen, hex.EncodeToString(pkt[:28]))

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst4[:])
	return syscall.Sendto(s.rawFd, pkt, 0, &sa)
}

// udpChecksum computes the UDP checksum using the IPv4 pseudo-header.
// src4, dst4 are the 4-byte IP addresses; udpSegment is the UDP header + payload.
func udpChecksum(src4, dst4, udpSegment []byte) uint16 {
	udpLen := uint16(len(udpSegment))
	var sum uint32

	// Pseudo-header: src IP, dst IP, zero, proto=17, UDP length
	sum += uint32(src4[0])<<8 | uint32(src4[1])
	sum += uint32(src4[2])<<8 | uint32(src4[3])
	sum += uint32(dst4[0])<<8 | uint32(dst4[1])
	sum += uint32(dst4[2])<<8 | uint32(dst4[3])
	sum += 17
	sum += uint32(udpLen)

	// UDP header + payload
	for i := 0; i+1 < len(udpSegment); i += 2 {
		sum += uint32(udpSegment[i])<<8 | uint32(udpSegment[i+1])
	}
	if len(udpSegment)%2 != 0 {
		sum += uint32(udpSegment[len(udpSegment)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	result := ^uint16(sum)
	if result == 0 {
		result = 0xffff // per RFC 768: transmit as all ones if computed result is zero
	}
	return result
}

// ── header template ───────────────────────────────────────────────────────────

// hdrTemplate stores the per-session constants needed to build each spoofed packet.
type hdrTemplate struct {
	src4    [4]byte // spoofed source IP
	dstPort uint16  // client's UDP listen port
}

func (h *hdrTemplate) build(src4, _ [4]byte, _ uint16, dstPort uint16) {
	h.src4 = src4
	h.dstPort = dstPort
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
