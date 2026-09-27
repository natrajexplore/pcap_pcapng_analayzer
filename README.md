# PacketLens — modern pcap / pcapng analyzer with root-cause correlation

PacketLens reads `.pcap` / `.pcapng` captures and does what an experienced packet analyst
does with Wireshark: it decodes every conversation from source to destination, flags what is
wrong, **correlates symptoms across layers into root causes**, explains *why* it happened from
**every perspective** (client, server, network path, routing control plane, application,
security) and gives concrete **remediation and recommendations**, with the Wireshark display
filter to jump to the evidence.

* **Zero required dependencies.** Pure Python 3.10+ standard library. Two optional extras unlock
  TLS decryption (`cryptography`) and HTTP/2 header decoding (`hpack`): `pip install ".[full]"`.
* **Five ways to use it:** CLI with a terminal report, a self-contained interactive HTML report
  that works offline, a local drag-and-drop web UI, **live capture**, and **two-point comparison**
  (the same traffic captured at two places, to prove *where* packets are lost).
* **Sees inside HTTPS.** Give it an `SSLKEYLOGFILE`, or use a pcapng with embedded secrets, and
  TLS 1.2/1.3 sessions are decrypted; the HTTP/1.1 and HTTP/2 inside get the same analysis as
  cleartext traffic.
* **Built on Chris Greer's (Packet Pioneer) methodology.** The expert rules, packet colouring
  and thresholds are taken from his published Wireshark profiles, and the analyzer is validated
  against his public sample captures (see [Validation](#validation-on-real-captures)).

```
pip install .
packetlens demo                                    # generate + analyze a capture covering every analyzer
packetlens analyze capture.pcapng --html report.html
packetlens analyze https.pcapng --keylog sslkeys.log   # decrypt TLS 1.2 / 1.3
packetlens compare client-side.pcapng server-side.pcapng   # locate loss between two capture points
sudo packetlens live -i eth0 -d 30 --html live.html    # capture + analyze (Linux)
packetlens serve                                   # http://127.0.0.1:8080, drop a capture in the browser
packetlens app pcap_folder/                        # Studio: library, 3D replay, packet simulator, live capture
packetlens batch pcap_folder/ --out reports/       # one 3D report per capture + index.html
```

---

## What it analyzes

| Layer | Protocols | Highlights |
|---|---|---|
| Link | Ethernet, 802.1Q VLAN, Linux SLL/SLL2, raw IP, loopback, ARP, STP | duplicate IP / ARP spoofing of the gateway, unanswered ARP, ARP scans, STP topology changes and multiple roots, broadcast share |
| Network | IPv4, IPv6 (extension headers), ICMP, ICMPv6 | TTL/hop analysis and OS family, multiple TTL signatures for one IP (middlebox or spoofing), link-local multicast TTL ≠ 1, IPv4/IPv6 **fragment reassembly** (incomplete datagrams = lost fragments), checksum errors, unreachable / admin-prohibited / frag-needed (PMTUD) / TTL-exceeded (loops) / redirects, with the embedded original flow |
| Transport | TCP, UDP | Wireshark `tcp.analysis.*` equivalents: retransmission, fast and spurious retransmission, out-of-order, previous segment not captured, ACKed unseen, duplicate ACK, zero window and probes, window full, window update, keep-alive. Also iRTT split into client and server side (capture-point location), bytes in flight, window scaling, SACK, MSS, conversation completeness, RST classification (refused / abort / after FIN), TCP delta gaps with **who-was-waiting attribution**, and application response time |
| Application | DNS, DHCP, HTTP/1.x, HTTP/2 (h2 and h2c, HPACK), TLS (SNI, ALPN, versions, ciphers, alerts, JA3, **decryption**) | DNS latency, timeouts, NXDOMAIN, SERVFAIL, REFUSED, truncation, tunneling/DGA, external resolvers. DHCP DORA reconstruction: no offer, no ack, NAK, DECLINE, rogue servers, APIPA. HTTP 4xx/5xx, `http.time`, cleartext credentials, scanner user agents, file downloads, full URL inventory (including decrypted HTTPS). HTTP/2 GOAWAY / RST_STREAM error codes (e.g. rapid-reset `ENHANCE_YOUR_CALM`). TLS old versions, weak ciphers, handshake failures, alerts (plaintext or decrypted), known-bad JA3 |
| Routing | BGP, OSPFv2/v3, EIGRP, RIPv1/v2, IS-IS, HSRP v1/v2, VRRP v2/v3 | BGP sessions, OPEN/UPDATE/NOTIFICATION decoding with error codes, withdrawals, flaps, TCP/179 failures. OSPF hello/dead, area, mask, auth and MTU mismatch, EXSTART stuck, duplicate RID, one-way adjacency, LSU storms. EIGRP K-value / AS / auth mismatch, SIA, query storms, reliable retransmissions, goodbye, unreachable routes. RIP version mismatch, metric-16 poisoning, missed updates, v1/no-auth. IS-IS circuit-type, area, auth and MTU mismatch (from hello padding), one-way adjacency, duplicate system ID, LSP churn/purges. HSRP/VRRP split brain (two active gateways), active-router flapping, timer / virtual-IP / auth mismatch, default `cisco` key, VRRP TTL ≠ 255 |
| Security | threat hunting | port scans with open-port list, nmap SYN / Null / Xmas signatures, host sweeps, Log4Shell strings, PE executables in transit, cleartext protocols, abused ports |

## How the analysis works

```
 pcap/pcapng ─► reader ─► dissector ─► flow tracker ─► reassembly ─► expert analyzers ─► correlation ─► reports
 or live        (pcap,    (L2→L7)      (TCP state,     (TCP streams,  (tcp, network,      (root-cause   (CLI, HTML,
 capture         pcapng,               conversations,   TLS decrypt,   dns, dhcp, web,     chains across JSON, web UI)
                 DSB keys)             tcp.analysis)    HTTP/1+2, BGP) routing, security)  layers + time)
```

1. **Findings** describe a symptom, for example "3 SYNs to 10.0.3.5:3389, no SYN-ACK". Each one
   is enriched from the knowledge base (`packetlens/knowledge.py`, about 90 entries) with its
   probable causes, what it means from each perspective, remediation, recommendations and the
   Wireshark filter.
2. **Root causes** come from the correlation engine (`packetlens/correlate.py`), which links
   findings across protocols and time into a causal chain and names the **fault domain**. Some
   of the chains it builds:

| Root cause | Evidence it links |
|---|---|
| Firewall/ACL block | SYN retries + ICMP admin-prohibited that embeds the same 5-tuple |
| Middlebox-injected RST | RST whose TTL differs from the genuine endpoint's packets (NGFW/IPS, SNI filtering) |
| PMTUD black hole | full-size segments retransmitted with RTO back-off, then the sender falls back to 536-byte segments; or ICMP frag-needed + retransmissions |
| Routing event disrupted traffic | BGP NOTIFICATION / withdrawals / EIGRP goodbye or SIA / RIP poisoning, followed in the same window by ICMP net-unreachable, TTL-exceeded or TCP failures |
| BGP hold-timer expiry caused by loss | TCP retransmissions on the TCP/179 session before a Hold Timer Expired NOTIFICATION |
| OSPF / EIGRP adjacency failure | timer, area, mask, auth, MTU, K-value or AS mismatches, DBD retransmissions |
| Receiver bottleneck ("it's not the network") | zero window + probes + window full on one side: that host's application is slow |
| Server think time vs loss | slow request→response with clean TCP (server at fault) vs with retransmissions (network at fault) |
| DNS failure / DNS latency | failed or slow lookups that precede, or prevent, connections |
| DHCP failure → APIPA; rogue DHCP; ARP spoofing | DORA outcome + link-local sources; two servers offering different gateways; gateway IP claimed by two MACs |
| Attack chain | scan → scanner user agents / Log4Shell / credential exposure from the same source |
| Capture drops | receivers ACK data the capture never saw, so fix the measurement first |
| IS-IS adjacency failure | circuit type, area, auth or MTU (hello padding) mismatch, one-way hellos |
| FHRP split brain | both HSRP/VRRP routers active at once, together with the auth/timer/VIP mismatch that explains why |
| Loss between capture points (two-point) | segments present at the upstream capture and missing downstream; flags an MTU black hole when only full-size packets vanish |

## The HTML report

A single file with no external assets, a dark/light theme, and something that works on a phone:

* **Overview**: health score per domain (transport, network, routing, application, security),
  capture-point location, severity counts, top root causes, traffic timeline with problem
  packets, protocol hierarchy.
* **Root causes**: verdict, narrative, time-ordered chain with clickable packet numbers,
  every-perspective panel, remediation and recommendations.
* **Findings**: filterable by severity, category, protocol and free text. Each one lists
  probable causes, perspectives, fixes, a copyable Wireshark filter and its evidence packets.
* **TCP streams**: per-stream metrics plus a **ladder (sequence) diagram** that highlights
  analysis flags, idle gaps with who-was-waiting attribution, and request→response times.
* **DNS · DHCP**, **Web · URLs · TLS**, **Routing** (BGP sessions and message timeline, OSPF
  routers, EIGRP neighbors, RIP routes), **Conversations · Endpoints** (hop estimates, OS
  family, DNS names, ARP table).
* **Packets**: a Wireshark-style list using Chris Greer's colouring rules (Bad TCP in red on
  black, ICMP errors, RST, SYN, FIN, TLS handshake, DNS critical…) with quick filters such as
  `bad`, `proto:dns`, `stream:3`, `delta>1`.

## TCP reassembly

Every TCP direction is rebuilt in sequence order: retransmissions and overlaps are removed and
out-of-order segments are buffered. The stream is then cut into application messages (TLS
records, HTTP/1.x headers plus Content-Length or chunked bodies, HTTP/2 frames, BGP messages,
DNS over TCP), and each message is attached to the packet where it completes, like Wireshark's
"reassembled PDU". A BGP UPDATE or HTTP header split across segments is therefore decoded
correctly. Payload bytes are dropped as soon as they are consumed, which cuts peak memory by
roughly a third (`--keep-payload` keeps them).

## TLS decryption

* **Key sources:** `--keylog FILE` (NSS key log written by browsers, curl, Python and OpenSSL when
  `SSLKEYLOGFILE` is set), and/or **Decryption Secrets Blocks** embedded in the pcapng
  (`editcap --inject-secrets tls,keys.log in.pcapng out.pcapng`) are picked up automatically.
  The web UI accepts a key-log file next to the capture.
* **Cipher suites:** TLS 1.3 AES-128/256-GCM and ChaCha20-Poly1305. TLS 1.2 ECDHE/DHE/RSA with
  AES-GCM (SHA-256/384 PRF) and ChaCha20-Poly1305.
* **What you get:** decrypted HTTP/1.1 and HTTP/2 (`https://` URLs, status codes, `http.time`,
  4xx/5xx and slow-response findings), encrypted TLS 1.3 alerts, and a per-session decryption
  status in the TLS table. Credentials seen inside decrypted TLS are **not** reported as
  cleartext.
* **Verification:** key derivation is checked against the RFC 8448 TLS 1.3 vector and the
  standard TLS 1.2 PRF vector, and decryption is tested end-to-end on genuine OpenSSL TLS 1.2 and
  1.3 traffic captured live on loopback.

## Two-point comparison (locate the loss)

```
packetlens compare client-side.pcapng server-side.pcapng --html compare.html
```

It matches every TCP segment between the two captures, by 5-tuple, sequence number and length,
or by sequence/ack/length if NAT sits between the points. For each direction it reports:
* segments that left the upstream point and never reached the downstream point (**loss between
  the points**);
* retransmissions whose originals *did* reach the downstream point (**loss outside the points**,
  or lost ACKs);
* the **one-way delay** between the points and the **clock offset** between the two capture hosts,
  so the captures don't need synchronized clocks.

On Chris Greer's `slowfile-clientside` / `slowfile-serverside` pair it finds the 3 full-size
server segments that vanished in transit, flags an MTU black hole, and measures a 43.3 ms one-way
delay and a 410.29 s clock offset between the captures. The result is the same whichever
capture is given first.

## Live capture (Linux)

```
sudo packetlens live -i eth0 -d 60 --port 443 --keylog $SSLKEYLOGFILE --html live.html
```

It uses an `AF_PACKET` raw socket (root or `CAP_NET_RAW`, no libpcap needed), filters by
`--host` / `--port`, handles loopback duplicates, saves a Wireshark-compatible pcapng (`-w`), and
analyzes the result.

## PacketLens Studio (`packetlens app`)

A local web app (127.0.0.1 only, no extra dependencies) with a neon 3D view of every capture:

* **Library** — every capture under the folder with its health score, worst problem and protocols.
* **Analyze** — Wireshark-style workbench for any .pcap/.pcapng you open, drop or pick: packet list with
  coloring rules (virtual scrolling, keyboard navigation, marking), packet details tree with exact byte
  highlighting in the hex pane (headers; application layers map to their payload), display filters in
  Wireshark syntax (`ip.addr == 10.0.0.0/8 && tcp.port in {80 443}`, `dns.qry.name contains "x"`,
  `tcp.analysis.retransmission`, `frame contains "jndi"`, `!arp`) with live validation, "Apply/Prepare as
  filter" from any field, Follow TCP/UDP stream, protocol hierarchy, conversations, endpoints, I/O graph,
  expert info, time display formats, go-to-packet and export of the displayed or marked packets as pcapng.
* **Capture** — the inferred source→destination path in 3D; replay every packet in capture-time order
  (timeline scrubber, speed control, drops burst where the flow broke), per-flow hop chains, findings,
  and a 3D sequence "ribbon" per TCP stream. Folders with several captures show the stitched path.
* **Simulator** — build a path (client, optional switch, 1–6 routers, server), pick traffic (HTTP, TLS,
  ping, traceroute, DNS, DHCP), inject a fault (loss, latency, firewall drop/reject, missing route, MTU black
  hole, routing loop, closed port, slow server, zero window, DNS/DHCP failures, rogue DHCP, TLS alert) and
  choose the capture link. Every packet is walked hop by hop; the capture the chosen link would record is
  analyzed and the result shows *injected vs. detected* — including when a fault is invisible from that
  capture point. The simulated pcapng can be downloaded for Wireshark.
* **Live** — capture and watch hosts and packets appear in 3D, then analyze. Linux: AF_PACKET (root).
  Windows: raw IPv4 socket (`SIO_RCVALL`, Administrator prompt, IPv4 only).

## CLI

```
packetlens analyze CAPTURE [--keylog FILE] [--html FILE] [--json FILE|-] [-v] [-q] [--max-packets N]
                           [--keep-payload] [--packet-list N] [--fail-on critical|high|medium|low] [--no-color]
packetlens compare A B     [--keylog FILE] [--html FILE] [--json FILE|-] [...]
packetlens live    [-i IFACE] [-d SECONDS] [-c COUNT] [--host IP] [--port N] [-s SNAPLEN] [-w FILE]
                   [--keylog FILE] [--html FILE] [...]
packetlens demo    [--out demo.pcapng] [--html demo.html] [--format pcapng|pcap]
packetlens serve   [--host 127.0.0.1] [--port 8080] [--max-mb 200]
packetlens app     [FOLDER] [--port 8090] [--no-browser]
packetlens batch   FOLDER [--out packetlens-reports] [--max-packets N]
```

* `-v` prints the causes, perspectives, fixes and Wireshark filter for every finding.
* `--fail-on high` exits with status 2 when a finding at or above that severity exists, which is
  useful in CI or for synthetic-monitoring captures.
* `--json -` writes the full analysis to stdout for SIEM/automation pipelines.

## Built on Chris Greer's (Packet Pioneer) work

The technical elements follow the public resources of
[Chris Greer / packetpioneer](https://github.com/packetpioneer):

* **[`profiles`](https://github.com/packetpioneer/profiles)** (TCP Plain and ThreatHunt Wireshark profiles).
  Their filter buttons and colouring rules became expert rules and thresholds: *Bad TCP*
  (`tcp.analysis.flags && !tcp.analysis.window_update`), *Low RWin* (≤ 2920), *Slow iRTT*,
  *TCP Delta > 1 s*, *Slow HTTP* (`http.time > 2`), *Slow DNS* (`dns.time > 0.05`), *Weird TTLs*
  (30–50), *TTL low or unexpected*, *ICMP errors*, *Name Resolution Critical/Warning*,
  *High DNS Count*, *Non-Local DNS*, *Old TLS*, *No User-Agent*, *Old Mozilla*, *Gobuster*,
  *NMAP* (window 1024 / no options / Null / Xmas), *ScanActivity* (`tcp.completeness`),
  *R-Shell*, *log4j*, *Executable Header*, *Password*, and the Trickbot JA3.
* **Methodology** from his TCP/IP and Wireshark courses: split iRTT to locate the capture point,
  attribute each delta gap to whoever's turn it was to talk, and "measure the measurement"
  (ACKed-unseen means the capture dropped the packet, not the network).
* **Sample captures** ([`youtube`](https://github.com/packetpioneer/youtube),
  [`Wireshark101`](https://github.com/packetpioneer/Wireshark101),
  [`Pearson-TCP`](https://github.com/packetpioneer/Pearson-TCP)) are used for validation. They
  are *not* redistributed here; clone them yourself to reproduce the results.

## Validation on real captures

Results on Chris Greer's public captures (`git clone https://github.com/packetpioneer/youtube`):

| Capture | PacketLens verdict |
|---|---|
| `PMTUD.pcapng` | **PMTUD** root cause: ICMP frag-needed from 192.168.1.1 with next-hop MTU 1350, plus 19 retransmissions of full-size segments |
| `slowfile-serverside.pcapng` | **PMTUD black hole** (90%): 1460-byte segments retransmitted at 3 s → 9 s → 21 s, then the sender falls back to 536-byte segments and data flows; ≈18 s stall. Capture point: near the server |
| `slowfile-clientside.pcapng` | the same transfer from the client side: retransmissions and a lost segment; capture point: near the client |
| `Lab1-GreerBombal_ItsNotTheNetwork.pcapng` | **Receiver bottleneck on client 10.0.2.15**: zero window and window full, network exonerated |
| `Lab2-GreerBombal_zerowindowprobe.pcapng` / `tcp-zerowindow-greer.pcapng` | receiver bottleneck on the client, zero-window probes |
| `tlsbroken.pcapng` | TLS `protocol_version` fatal alerts, TLS 1.0 servers (badssl.com), ClientHellos without SNI |
| `DisplayFilters.pcapng` | **attack chain**: nmap scan of 316 ports with the open ports listed, Nmap NSE user agent, Null scan, cleartext FTP/Telnet/POP3 |
| `sample.pcapng` | **server think time**: worst 4.7 s request→response with clean TCP |
| `dns_*`, `dns-lesson1` | DNS timings, NXDOMAIN, truncation → TCP fallback, queries to root servers |
| `slowfile-clientside` + `slowfile-serverside` (**compare**) | 3 full-size segments lost *between* the capture points → MTU black hole; one-way delay 43.3 ms; clock offset 410.29 s |
| `DoH-Sample-ChrisGreer.pcapng` | ordinary loss (no black hole: full-size segments were delivered) |

Sliced captures (snaplen 66–200 bytes, common in these samples) are handled: TCP segment
lengths come from the IP header, so sequence analysis stays correct and the report warns that
application-layer decoding may be incomplete.

## Project layout

```
packetlens/
  reader.py        pcap/pcapng reader (µs/ns, multi-section, EPB/SPB/PB, Decryption Secrets Block) + writers
  decode.py        L2→L7 dissector            packet.py   packet model
  protocols/       dns, dhcp, http, http2, tls (JA3), bgp, ospf, eigrp, rip, isis, fhrp (HSRP/VRRP), l2 (arp, icmp, stp)
  flows.py         conversations + TCP stream analysis (tcp.analysis.* equivalents)
  reassembly.py    TCP stream reassembly + message framing (TLS, HTTP/1, HTTP/2, BGP, DNS)
  tlsdecrypt.py    key log, TLS 1.2 PRF / TLS 1.3 HKDF key schedules, AEAD record decryption
  compare.py       two-point capture comparison (loss location, one-way delay, clock offset)
  live.py          AF_PACKET live capture
  experts/         tcp, network, dns, dhcp, web, routing, security
  knowledge.py     causes / perspectives / remediation / recommendations / filters
  correlate.py     cross-layer root-cause engine
  analyzer.py      pipeline, stats, health score, colouring rules
  report/          self-contained HTML report
  cli.py, web.py   command line and local web UI
  synth.py         synthetic multi-scenario capture generator (demo + tests)
tests/             unittest suite (python -m unittest discover -s tests)
```

## Limitations

* **QUIC / HTTP/3** is identified but not decrypted, and TLS 1.2 **CBC** suites are not decrypted
  (AEAD suites cover practically all current traffic). TLS 1.3 `KeyUpdate` is not followed.
* **HTTP/2 headers** need the optional `hpack` package; without it, frames and error codes are
  still analyzed. HPACK state can't be recovered for connections that started before the
  capture.
* **Memory:** decoded packet metadata is about 1.7 KB/packet (300k packets ≈ 520 MB peak; about
  21k packets/s). For multi-million-packet files, slice with `editcap` or use `--max-packets`.
* **Live capture** is Linux-only (`AF_PACKET`) with simple host/port filters rather than BPF.

## License

MIT for the code. Chris Greer's sample captures and profiles belong to their author; see his
repositories for their licenses.
