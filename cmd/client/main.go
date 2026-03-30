// asymon client — runs INSIDE Iran.
//
// Bridges a local UDP app (KCP/QUIC/etc.) to the asymon server asymmetrically:
//   Uplink:   local UDP → frame → TCP via SOCKS5 proxy → server
//   Downlink: server spoofed UDP → local UDP app
//
// Usage:
//   asymon-client -socks 127.0.0.1:1080 \
//                 -server 1.2.3.4:4444  \
//                 -local  :5555         \
//                 -myip   1.2.3.4       \  ← your real Iran-side IP
//                 -myport 5555             ← UDP port server should reply to
//
// The local KCP/QUIC app should connect to -local as if it were the remote server.
package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"sync"

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
	myPort     = flag.Int("myport", 0, "UDP port server should reply to (0 = same as -local port)")
)

func main() {
	flag.Parse()
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

	// Dial server via SOCKS5
	dialer, err := proxy.SOCKS5("tcp", *socksAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("socks5 dialer: %v", err)
	}
	tc, err := dialer.Dial("tcp", *serverAddr)
	if err != nil {
		log.Fatalf("dial server via socks5: %v", err)
	}
	log.Printf("connected to server %v via socks5 %v", *serverAddr, *socksAddr)
	log.Printf("real addr announced: %v:%d", net.IP(realIP4[:]), udpPort)

	// Handshake: [my real IPv4: 4][my UDP port: 2]
	var hs [6]byte
	copy(hs[0:4], realIP4[:])
	binary.BigEndian.PutUint16(hs[4:6], udpPort)
	if _, err := tc.Write(hs[:]); err != nil {
		log.Fatalf("handshake: %v", err)
	}

	// Local UDP socket — talk to the KCP/QUIC app
	localConn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Fatalf("listen local UDP %v: %v", laddr, err)
	}
	localConn.SetReadBuffer(sockBuf)
	localConn.SetWriteBuffer(sockBuf)
	log.Printf("local UDP ready on %v", laddr)

	// We need to remember where the local app is (first packet sets this)
	var (
		appAddrMu sync.RWMutex
		appAddr   *net.UDPAddr
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// Uplink: local UDP → TCP frames → server
	go func() {
		defer wg.Done()
		defer tc.Close()
		buf := make([]byte, maxPkt)
		var lenBuf [2]byte
		for {
			n, addr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Remember the app's address so downlink knows where to deliver
			appAddrMu.Lock()
			appAddr = addr
			appAddrMu.Unlock()

			binary.BigEndian.PutUint16(lenBuf[:], uint16(n))
			// Write frame atomically (length + payload together)
			frame := make([]byte, 2+n)
			copy(frame[:2], lenBuf[:])
			copy(frame[2:], buf[:n])
			if _, err := tc.Write(frame); err != nil {
				return
			}
		}
	}()

	// Downlink: spoofed UDP from server → local UDP app
	// The server sends raw UDP to our real IP:port; we receive it on localConn.
	// But wait — the server spoofs the SOURCE, not the destination.
	// The dest is our real IP:udpPort. So we receive it on localConn (listening on udpPort).
	// We then deliver the payload to the local KCP/QUIC app.
	go func() {
		defer wg.Done()
		defer localConn.Close()
		buf := make([]byte, maxPkt)
		for {
			n, _, err := localConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			appAddrMu.RLock()
			dst := appAddr
			appAddrMu.RUnlock()
			if dst == nil {
				continue // no uplink yet, drop
			}
			localConn.WriteToUDP(buf[:n], dst)
		}
	}()

	wg.Wait()
	log.Println("session closed")
}

func mustIP4(s string) [4]byte {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		log.Fatalf("invalid IPv4 %q", s)
	}
	return [4]byte(ip)
}
