# asymon

Asymmetric UDP tunnel for censored networks.

**Uplink** (client → server) travels over TCP via a SOCKS5 proxy — the only reliable outbound path through heavy filtering.
**Downlink** (server → client) is sent as raw spoofed UDP packets directly to the client's real IP, bypassing inbound filtering by making traffic appear to originate from a trusted address.

The tunnel carries raw bytes. Encryption and reliability (KCP, QUIC, WireGuard, etc.) are handled by whatever runs on top.

```
┌─────────────────────────────────────────────────────────────────┐
│ Iran                          │ Outside                         │
│                               │                                 │
│  [your app]                   │                                 │
│     │ UDP (local)             │                                 │
│  [asymon client]              │  [asymon server]                │
│     │                         │      │                          │
│     ├── TCP via SOCKS5 ───────┼─────▶│ uplink                  │
│     │                         │      │                          │
│     │                         │      ▼                          │
│     │                         │  [backend: KCP/QUIC/etc]        │
│     │                         │      │                          │
│     │                         │      │ response                 │
│     │                         │      ▼                          │
│     ◀── spoofed UDP ──────────┼──────┘ downlink                 │
│         src = trusted IP      │                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

- **Server**: Linux, root or `CAP_NET_RAW` (required for raw socket spoofing)
- **Client**: any OS, a working SOCKS5 proxy for outbound TCP

## Installation

Download a pre-built binary from [Releases](../../releases), or build from source:

```bash
go build -o server ./cmd/server
go build -o client ./cmd/client
```

## Usage

### Server (outside Iran)

```bash
./server \
  -l          :4444          \  # TCP port clients connect to via SOCKS5
  -b          127.0.0.1:5555 \  # your backend (KCP/QUIC server) UDP addr
  -spoof-src  1.2.3.4        \  # source IP stamped on return UDP packets
  -spoof-port 443               # source port (optional, default = -l port)
```

`-spoof-src` should be an IP address that Iran's firewall won't drop — e.g. a CDN IP, a known allowed service, or any address you control that passes inbound filtering.

### Client (inside Iran)

```bash
./client \
  -socks    127.0.0.1:1080  \  # your SOCKS5 proxy
  -server   SERVER_IP:4444  \  # asymon server address
  -local    :5555           \  # local UDP port your app connects to
  -myip     YOUR_IRAN_IP    \  # your real public IPv4 (server sends UDP here)
  -myport   5555               # UDP port to receive on (default = -local port)
```

Point your KCP/QUIC/WireGuard client at `127.0.0.1:5555` (or whatever `-local` is set to) instead of the real server.

### Example: KCP-based tunnel

```bash
# server side
./server -l :4444 -b 127.0.0.1:29900 -spoof-src 104.21.0.1

# client side
./client -socks 127.0.0.1:1080 -server 5.6.7.8:4444 \
         -local :29900 -myip 203.0.113.5
# then point your KCP client at 127.0.0.1:29900
```

## Wire format

```
TCP (client → server):
  Handshake:   [client real IPv4: 4 bytes][client UDP port: 2 bytes BE]
  Data frames: [length: 2 bytes BE][payload: N bytes] ...

UDP (server → client, spoofed source):
  Raw payload, no framing
```

## Notes

- The client must have its real public IP reachable for inbound UDP on `-myport`. If behind NAT, set up port forwarding.
- `CAP_NET_RAW` can be granted without running as root: `setcap cap_net_raw+ep ./server`
- Sessions expire after 5 minutes of inactivity.

## Build status

[![build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)
