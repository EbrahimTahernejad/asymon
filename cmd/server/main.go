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
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
)

const (
	maxPkt  = 65507
	sockBuf = 8 << 20
)

var (
	listenAddr = flag.String("l", ":4444", "TCP listen addr (clients connect here via SOCKS5)")
	backendAddr = flag.String("b", "127.0.0.1:5555", "backend UDP addr (KCP/QUIC server)")
	spoofSrc   = flag.String("spoof-src", "", "spoof source IP for UDP downlink (required)")
	spoofPort  = flag.Int("spoof-port", 0, "spoof source port (0 = same as -l port)")
)

func main() {
	flag.Parse()
	if *spoofSrc == "" {
		log.Fatal("-spoof-src is required")
	}

	src4 := mustIP4(*spoofSrc)
	sp := uint16(*spoofPort)
	if sp == 0 {
		_, portStr, _ := net.SplitHostPort(*listenAddr)
		var p int
		if _, err := net.LookupPort("tcp", portStr); err == nil {
			for _, b := range []byte(portStr) {
				p = p*10 + int(b-'0')
			}
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

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("listen TCP %v: %v", *listenAddr, err)
	}
	log.Printf("listening TCP %v → backend UDP %v | spoof src %v:%d", *listenAddr, baddr, net.IP(src4[:]), sp)

	srv := &Server{rawFd: rawFd, spoofSrc: src4, spoofPort: sp, backend: baddr}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go srv.handle(conn)
	}
}

// ── server ────────────────────────────────────────────────────────────────────

type Server struct {
	rawFd    int
	spoofSrc [4]byte
	spoofPort uint16
	backend  *net.UDPAddr
}

func (s *Server) handle(tc net.Conn) {
	defer tc.Close()
	remote := tc.RemoteAddr()

	// Handshake: [client real IPv4: 4][client UDP port: 2]
	var hs [6]byte
	if _, err := io.ReadFull(tc, hs[:]); err != nil {
		log.Printf("%v: handshake: %v", remote, err)
		return
	}
	clientIP4 := [4]byte(hs[0:4])
	clientPort := binary.BigEndian.Uint16(hs[4:6])
	log.Printf("%v: client real addr %v:%d", remote, net.IP(clientIP4[:]), clientPort)

	// Dial backend UDP
	up, err := net.DialUDP("udp4", nil, s.backend)
	if err != nil {
		log.Printf("%v: dial backend: %v", remote, err)
		return
	}
	up.SetReadBuffer(sockBuf)
	up.SetWriteBuffer(sockBuf)
	defer up.Close()

	// Pre-build IP+UDP header template for this client
	var hdr hdrTemplate
	hdr.build(s.spoofSrc, clientIP4, s.spoofPort, clientPort)

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP → UDP backend (uplink)
	go func() {
		defer wg.Done()
		defer up.Close() // unblocks backend read
		var lenBuf [2]byte
		buf := make([]byte, maxPkt)
		for {
			if _, err := io.ReadFull(tc, lenBuf[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(lenBuf[:]))
			if n == 0 || n > maxPkt {
				return
			}
			if _, err := io.ReadFull(tc, buf[:n]); err != nil {
				return
			}
			up.Write(buf[:n])
		}
	}()

	// UDP backend → spoofed UDP → client (downlink)
	go func() {
		defer wg.Done()
		defer tc.Close() // unblocks TCP read
		buf := make([]byte, maxPkt)
		for {
			n, err := up.Read(buf)
			if err != nil {
				return
			}
			s.sendSpoofed(&hdr, clientIP4, buf[:n])
		}
	}()

	wg.Wait()
	log.Printf("%v: session closed", remote)
}

func (s *Server) sendSpoofed(h *hdrTemplate, dst4 [4]byte, payload []byte) {
	pkt := make([]byte, 28+len(payload))
	copy(pkt[:28], h.tpl[:])
	copy(pkt[28:], payload)

	totalLen := uint16(28 + len(payload))
	udpLen   := uint16(8  + len(payload))
	binary.BigEndian.PutUint16(pkt[2:4], totalLen)
	binary.BigEndian.PutUint16(pkt[24:26], udpLen)

	// Incremental IP checksum (baseSum pre-computed with length=0)
	sum := h.baseSum + uint32(totalLen)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	var sa syscall.SockaddrInet4
	copy(sa.Addr[:], dst4[:])
	syscall.Sendto(s.rawFd, pkt, 0, &sa) //nolint:errcheck
}

// ── header template ───────────────────────────────────────────────────────────

type hdrTemplate struct {
	tpl     [28]byte
	baseSum uint32
}

func (h *hdrTemplate) build(src4, dst4 [4]byte, srcPort, dstPort uint16) {
	t := &h.tpl
	t[0] = 0x45 // IPv4, IHL=5
	// [2:4] total length — per packet
	t[6] = 0x40 // DF
	t[8] = 64   // TTL
	t[9] = 17   // UDP
	// [10:12] checksum — per packet
	copy(t[12:16], src4[:])
	copy(t[16:20], dst4[:])
	binary.BigEndian.PutUint16(t[20:22], srcPort)
	binary.BigEndian.PutUint16(t[22:24], dstPort)
	// [24:26] UDP length — per packet
	// [26:28] UDP checksum — leave 0 (optional in IPv4)

	// Pre-compute IP checksum with length=0 and checksum=0
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(t[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	h.baseSum = sum
}

// ── helpers ───────────────────────────────────────────────────────────────────

func mustIP4(s string) [4]byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4 %q", s)
	}
	return [4]byte(ip)
}
