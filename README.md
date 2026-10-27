# lor

`lor` is a curl-like CLI that shows you what your request does on the wire.
While an HTTP(S) or raw TCP request runs, the terminal shows:

* **Left: the TCP/IP stack**, drawn like the textbook diagram. Application
  (HTTP), Security (TLS), Transport (TCP) and Network (IP) boxes hold the
  decoded, human-readable state of each layer: IP source and destination,
  TCP ports, flags, relative seq/ack and window, the TLS ClientHello (SNI,
  ALPN, offered versions and ciphers), the ServerHello, the certificate, and
  the HTTP request and response. The boxes the current event touched light
  up, and an arrow shows whether data is moving down the stack (sending,
  encapsulation) or up it (receiving, decapsulation).
* **Right: what is happening right now**, one line per event:
  `TCP handshake: SYN`, `SYN-ACK`, `ACK`, `TLS ClientHello`,
  `TLS ServerHello`, `HTTP first byte received (TTFB)`, retransmissions,
  duplicate ACKs, `FIN`, `RST` and so on.
* **Bottom right: a timing waterfall** (DNS, TCP connect, TLS handshake,
  request sent, server processing, content download) that grows live and
  stays on screen when the request is done.

Step through the events with ↑/↓ to see the whole stack as it was at that
moment.

```
 lor  GET https://127.0.0.1:8443/hello  ✓ done 26.547ms · 200 OK
 mode: capturing packets on all interfaces
+1.81ms → TLS ClientHello  [socket]                      │What's happening on the wire (36 events)
╭───────────────────────────────────────────────────────╮│    +742µs → TCP  TCP handshake: SYN
│ L7 Application · HTTP / DNS                           ││    +917µs ← TCP  TCP handshake: SYN-ACK
│ · not used yet                                        ││    +951µs → TCP  TCP handshake: ACK
╰───────────────────────────────────────────────────────╯│   +1.40ms • TCP  TCP connection established
                       ▼ encapsulate                     │   +1.71ms → TCP  TCP data 246B (TLS Handshake)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓│▶  +1.81ms → TLS  TLS ClientHello
┃ L6 Security · TLS                                     ┃│   +4.07ms ← TCP  TCP data 1399B (TLS Handshake)
┃ ▸ ClientHello                                         ┃│   +4.32ms ← TLS  TLS ServerHello
┃ SNI              (none)                               ┃│   ...
┃ Versions offered TLS 1.3, TLS 1.2                     ┃│
┃ ALPN offered     http/1.1                             ┃│Timing waterfall
┃ Cipher suites    13 offered                           ┃│TCP connect       │██                         │ 1.02ms
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛│TLS handshake     │  ██████                   │ 4.16ms
                       ▼ encapsulate                     │Request sent      │        █                  │ 147µs
╭───────────────────────────────────────────────────────╮│Server processing │        ██████████████████ │ 20.68ms
│ L4 Transport · TCP                                    ││Content download  │                          █│ 67µs
│ ...                                                   ││                  0                     26.51ms
```

## Install

```sh
go install github.com/revolyssup/vibecoded-lor/cmd/lor@latest
```

or `go build -o lor ./cmd/lor`. No cgo and no libpcap needed.

## Usage

```sh
lor https://example.com
lor -X POST -H 'Content-Type: application/json' -d '{"a":1}' https://httpbin.org/post
lor -o page.html https://example.com          # save the body
lor tcp -d 'PING\r\n' localhost:6379          # raw TCP, \r \n \t escapes allowed
lor tcp --tls -d 'HEAD / HTTP/1.0\r\n\r\n' example.com:443
lor --plain -v https://example.com            # no TUI, curl -v style log with every field
```

Keys in the TUI: `↑/↓` step through events, `g`/`G` first/last (and follow
live events), `d` toggles detail (raw seq numbers, TCP options, checksums,
full headers, cipher lists), `PgUp/PgDn` scroll the stack, `q` quits. When
you quit, the summary and waterfall are printed to the terminal.

When stdout is not a terminal, `lor` switches to plain mode: events and the
waterfall go to stderr and the response body to stdout, like `curl -v`.

Useful flags: `-k` (skip certificate verification), `--resolve IP` (skip
DNS), `-4`/`-6`, `--timeout`, `--iface`, `--no-capture`, and `--keylog FILE`
(or `SSLKEYLOGFILE`) to decrypt the TLS session in Wireshark later.

## Two levels of visibility

| Mode | When | What you see |
| --- | --- | --- |
| Packet capture | Linux, run as root or with `CAP_NET_RAW` (`sudo setcap cap_net_raw+ep $(which lor)`) | Every real IP/TCP packet of the connection with kernel timestamps: handshake, data segments, ACKs, window, retransmissions, duplicate ACKs, FIN/RST |
| Socket level | Everywhere else | DNS, TLS records and HTTP exactly as sent and received, the kernel's `TCP_INFO` (RTT, MSS, retransmits) on Linux, and the TCP handshake inferred from `connect()` (marked *inferred*) |

TLS records and HTTP messages are always decoded from the bytes on the
socket, so the TLS handshake (ClientHello, ServerHello, certificate,
encrypted handshake records, close_notify) is visible in both modes.

## Design notes

* The request is driven step by step (resolve, connect, TLS handshake, write
  request, read response) instead of through `net/http`'s client, so every
  phase is timed exactly and every byte can be decoded. `HTTP_PROXY` is
  ignored on purpose: the point is to see your own connection to the server.
* HTTP/1.1 only for now (ALPN offers `http/1.1`), so requests and responses
  are readable. Redirects are not followed, like curl without `-L`.
* Packet capture uses a Linux `AF_PACKET` socket in pure Go and decodes
  headers with `gopacket/layers`. It is opened before the clock starts, so
  its setup does not skew timings. macOS and Windows run in socket-level
  mode for now; a libpcap/BPF backend would add capture there.

## Layout

```
cmd/lor           flags and wiring
internal/trace    events, phases and the tracer that timestamps them
internal/probe    DNS/TCP/TLS/HTTP runners, TLS record decoder, TCP_INFO
internal/capture  AF_PACKET capture and TCP/IP header decoding
internal/ui       Bubble Tea TUI (stack, events, waterfall) and plain output
```
