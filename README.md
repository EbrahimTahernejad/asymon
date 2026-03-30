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
│   localConn (:8000)           │      │                          │
│   recvConn  (:443)            │      │                          │
│     │                         │      │                          │
│     ├── TCP via SOCKS5 ───────┼─────▶│ uplink                  │
│     │                         │      │                          │
│     │                         │      ▼                          │
│     │                         │  [backend: KCP/QUIC/etc]        │
│     │                         │      │                          │
│     │                         │      │ response                 │
│     │                         │      ▼                          │
│     ◀── spoofed UDP ──────────┼──────┘ downlink (→ recvConn)   │
│         src = trusted IP      │                                 │
└─────────────────────────────────────────────────────────────────┘
```

The client uses **two separate UDP sockets**:
- `localConn` — bound to `-local`, talks to your KCP/QUIC app
- `recvConn` — bound to `0.0.0.0:-myport`, receives spoofed downlink from the server

## Requirements

- **Server**: Linux, root or `CAP_NET_RAW` (required for raw socket spoofing)
- **Client**: Linux/macOS, a working SOCKS5 proxy for outbound TCP, and inbound UDP open on `-myport`

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
  -l          :8443          \  # TCP port clients connect to via SOCKS5
  -b          127.0.0.1:5555 \  # your backend (KCP/QUIC server) UDP addr
  -spoof-src  1.2.3.4        \  # source IP stamped on return UDP packets
  -spoof-port 443               # source port (optional, default = -l port)
```

`-spoof-src` should be an IP address that Iran's firewall won't drop inbound — e.g. a CDN IP, a whitelisted service, or any address whose traffic passes filtering.

### Client (inside Iran)

```bash
./client \
  -socks    127.0.0.1:1080  \  # your SOCKS5 proxy
  -server   SERVER_IP:8443  \  # asymon server address
  -local    127.0.0.1:8000  \  # your KCP/QUIC app connects here
  -myip     YOUR_IRAN_IP    \  # your real public IPv4 (server sends spoofed UDP here)
  -myport   443                # port to receive spoofed downlink on (binds 0.0.0.0:443)
```

Point your KCP/QUIC/WireGuard client at `-local` (e.g. `127.0.0.1:8000`) instead of the real server.

The `-myport` socket listens on `0.0.0.0`, so the spoofed UDP packets destined for your real IP on that port are delivered correctly regardless of which interface they arrive on.

### Example: VLESS+KCP tunnel

```bash
# server side
./server -l :8443 -b 127.0.0.1:5555 -spoof-src 78.46.226.140 -spoof-port 2083

# client side
./client -socks 109.125.168.99:50000 -server 185.113.10.141:8443 \
         -local 127.0.0.1:8000 -myip 193.151.151.83 -myport 443

# then point your VLESS/KCP client at 127.0.0.1:8000
```

## Wire format

```
TCP (client → server):
  Handshake:   [client real IPv4: 4 bytes][client UDP port: 2 bytes BE]
  Data frames: [length: 2 bytes BE][payload: N bytes] ...

UDP (server → client, spoofed source):
  Raw payload, no framing
```

## Flags

### server

| Flag | Default | Description |
|---|---|---|
| `-l` | `:4444` | TCP listen addr (clients connect here via SOCKS5) |
| `-b` | `127.0.0.1:5555` | Backend UDP addr (your KCP/QUIC server) |
| `-spoof-src` | — | Source IP to stamp on downlink UDP packets (required) |
| `-spoof-port` | same as `-l` | Source port to stamp on downlink UDP packets |
| `-v` | false | Verbose: per-packet logging, hex dumps, timing |

### client

| Flag | Default | Description |
|---|---|---|
| `-socks` | `127.0.0.1:1080` | SOCKS5 proxy for uplink TCP |
| `-server` | — | asymon server TCP addr (required) |
| `-local` | `:5555` | Local UDP addr your KCP/QUIC app connects to |
| `-myip` | — | Your real public IPv4 — server sends spoofed UDP here (required) |
| `-myport` | same as `-local` | UDP port to receive spoofed downlink on (binds `0.0.0.0:PORT`) |
| `-v` | false | Verbose: per-packet logging, hex dumps, timing |

## Notes

- **Inbound UDP**: the client machine must accept inbound UDP on `-myport` from the internet. If behind NAT, set up a port forward. Check that no local firewall (`iptables`, `ufw`) drops it either.
- **CAP_NET_RAW**: can be granted without running server as root: `setcap cap_net_raw+ep ./server`
- **Sessions**: expire after 5 minutes of inactivity.
- **Verbose mode**: use `-v` on either side to log every packet with hex dumps, timing, and counters. Filter out packet noise with `grep -v '\[V\]'`.

## Build status

[![build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)
