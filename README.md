# PacketLens — modern pcap / pcapng analyzer with root-cause correlation

PacketLens reads `.pcap` / `.pcapng` captures and does what an experienced packet analyst
does with Wireshark: it decodes every conversation from source to destination, flags what is
wrong, **correlates symptoms across layers into root causes**, explains *why* it happened from
**every perspective** (client, server, network path, routing control plane, application,
security) and gives concrete **remediation and recommendations**, with the Wireshark display
filter to jump to the evidence.

* **Zero required dependencies.** Pure Python 3.10+ standard library. Two optional extras unlock
  TLS and QUIC decryption (`cryptography`) and HTTP/2 / gRPC header decoding (`hpack`):
  `pip install ".[full]"`.
* **Six ways to use it:** CLI with a terminal report, a self-contained interactive HTML report
  that works offline, **PacketLens Studio** (local web app with a Wireshark-style workbench, 3D
  replay, Insights dashboards and a packet simulator), a drag-and-drop web UI, **live capture**,
  and **two-point comparison** (the same traffic captured at two places, to prove *where* packets
  are lost).
* **Post-quantum ready.** Every key exchange (TLS, QUIC, SSH, IKE/IPsec, WireGuard, MACsec/MKA,
  EAP-TLS) is graded post-quantum / hybrid / draft / classical / weak and rolled into a **PQC
  readiness score**. It recognises ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205),
  and explains why a migration fails, for example a middlebox dropping the larger post-quantum ClientHello.
* **Understands AI-era traffic.** It identifies AI / LLM services and MCP agents, measures time to first
  token and stalls even on encrypted streams, and diagnoses RoCEv2 / PFC problems in GPU fabrics.
* **Sees inside HTTPS.** Give it an `SSLKEYLOGFILE`, or use a pcapng with embedded secrets, and
  TLS 1.2/1.3 sessions are decrypted; the HTTP/1.1 and HTTP/2 inside get the same analysis as
  cleartext traffic. QUIC Initial packets are decrypted without any secrets.
* **Built on Chris Greer's (Packet Pioneer) methodology.** The expert rules, packet colouring
  and thresholds are taken from his published Wireshark profiles, and the analyzer is validated
  against his public sample captures (see [Validation](#validation-on-real-captures)).

**Contents:** [Quick start](#quick-start) · [What it analyzes](#what-it-analyzes) ·
[How the analysis works](#how-the-analysis-works) · [Post-quantum & crypto posture](#post-quantum--crypto-posture) ·
[AI traffic](#ai-traffic) · [AI fabric (RoCEv2 / PFC)](#ai-fabric-rocev2--pfc) · [HTML report](#the-html-report) ·
[TLS decryption](#tls-decryption) · [Two-point comparison](#two-point-comparison-locate-the-loss) ·
[Studio](#packetlens-studio-packetlens-app) · [Display filters](#display-filters) · [CLI](#cli) ·
[Validation](#validation-on-real-captures) · [Testing](#testing) · [Project layout](#project-layout) ·
[Limitations](#limitations)

## Quick start

```
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install ".[full]"                               # or: pip install .   (zero dependencies)
packetlens demo --html demo.html                    # synthetic capture that exercises every analyzer
packetlens app pcap_folder/                         # open the Studio on a folder of captures
```

The demo capture contains healthy and broken TCP, DNS, DHCP, HTTP/1/2, TLS, routing protocols,
attacks, post-quantum TLS / SSH / IKE, MACsec, EAP-TLS, AI services, MCP, QUIC, WireGuard, RoCEv2
and PFC, so every view and dashboard has something to show.

```
packetlens demo                                    # generate + analyze a capture covering every analyzer
packetlens analyze capture.pcapng --html report.html
packetlens analyze https.pcapng --keylog sslkeys.log   # decrypt TLS 1.2 / 1.3
packetlens compare client-side.pcapng server-side.pcapng   # locate loss between two capture points
sudo packetlens live -i eth0 -d 30 --html live.html    # capture + analyze (Linux)
packetlens serve                                   # http://127.0.0.1:8080, drop a capture in the browser
packetlens app pcap_folder/                        # Studio: library, 3D replay, Insights (PQC / AI / fabric), simulator, live
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
| Crypto & post-quantum | TLS 1.2/1.3 (ML-KEM / X25519MLKEM768, ML-DSA, HelloRetryRequest, ECH), X.509, SSH, IKEv1/IKEv2 (RFC 9370 ML-KEM, IKE_INTERMEDIATE, RFC 7383 fragmentation, NAT-T), ESP, MACsec (802.1AE), MKA, EAP-TLS / PEAP / TTLS | **PQC readiness score** and a key-exchange inventory classified as post-quantum / hybrid / draft / classical / weak; PQC offered but not selected, draft Kyber, large PQC ClientHello dropped by a middlebox, IKE NO_PROPOSAL_CHOSEN / INVALID_KE / AUTH_FAILED, ML-KEM IKE without fragmentation, weak IKE and SSH algorithms, Terrapin exposure, ESP and MACsec sequence gaps and replays, MACsec integrity-only and PN exhaustion, MKA CKN mismatch, expired / self-signed / weak / ML-DSA certificates (including certificates reassembled from EAP-TLS fragments) |
| AI traffic | AI / LLM services (OpenAI, Anthropic, Gemini / Vertex, Azure OpenAI, Copilot, Bedrock, Mistral, Hugging Face and more) via TLS / QUIC SNI, DNS, HTTP and certificates; OpenAI-compatible, Anthropic, Gemini and Ollama APIs; MCP (JSON-RPC); gRPC inference (Triton / KServe, TF Serving) | AI service and client inventory, consumer assistants (shadow AI), large uploads, API keys over cleartext HTTP, unauthenticated self-hosted model servers, **time to first token and mid-stream stalls measured from packet timing even when encrypted**, 429/529 rate limits, MCP tool calls, gRPC status errors |
| AI fabric · new transports | RoCEv2 (BTH / AETH, CNP), ECN, 802.1Qbb PFC / PAUSE, QUIC v1/v2 (Initial decryption: SNI, ALPN, ML-KEM key shares), WireGuard | RoCE PSN gaps, go-back-N retransmissions, NAK / RNR NAK, DCQCN congestion (CNP, ECN-CE), non-ECN-capable RoCE, PFC pause storms; QUIC blocked with TCP fallback, version negotiation; WireGuard handshakes never answered |
| Security | threat hunting | port scans with open-port list, nmap SYN / Null / Xmas signatures, host sweeps, Log4Shell strings, PE executables in transit, cleartext protocols, abused ports |

## How the analysis works

```
 pcap/pcapng ─► reader ─► dissector ─► flow tracker ─► reassembly ─► expert analyzers ─► correlation ─► reports
 or live        (pcap,    (L2→L7)      (TCP state,     (TCP streams,  (tcp, network,      (root-cause   (CLI, HTML,
 capture         pcapng,               conversations,   TLS decrypt,   dns, dhcp, web,     chains across JSON, web UI)
                 DSB keys)             tcp.analysis)    HTTP/1+2, BGP,  routing, security,  layers + time)
                                                        SSH, QUIC)     quic, crypto, ai,
                                                                       fabric)
```

1. **Findings** describe a symptom, for example "3 SYNs to 10.0.3.5:3389, no SYN-ACK". Each one
   is enriched from the knowledge base (`packetlens/knowledge.py`, about 200 entries) with its
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
| PQC ClientHello blocked | ClientHello with an ML-KEM key share spans two segments, the second is never acknowledged, then a RST with a foreign TTL |
| IKE PQC mismatch / fragment loss | ML-KEM ADDKE proposal answered with NO_PROPOSAL_CHOSEN; or IKE_INTERMEDIATE retransmitted without IKEv2 fragmentation |
| RDMA congestion spreading / lossy RoCE | PFC pause storm together with RoCE loss or CNPs; or RoCE loss with neither PFC nor ECN feedback |
| QUIC fallback | QUIC Initials never answered, then the same client reaches the server over TCP/TLS |
| MACsec CKN mismatch | MKA participants that never become live peers while another participant uses a different CAK name |
| Capture drops | receivers ACK data the capture never saw, so fix the measurement first |
| IS-IS adjacency failure | circuit type, area, auth or MTU (hello padding) mismatch, one-way hellos |
| FHRP split brain | both HSRP/VRRP routers active at once, together with the auth/timer/VIP mismatch that explains why |
| Loss between capture points (two-point) | segments present at the upstream capture and missing downstream; flags an MTU black hole when only full-size packets vanish |

## Post-quantum & crypto posture

`experts/crypto.py` builds one inventory of every key exchange in the capture and classifies it
with the algorithm registry in `protocols/pqc.py`:

| Status | Meaning | Examples |
|---|---|---|
| **Post-quantum** | pure NIST PQC algorithm | MLKEM768, ML-KEM-1024 (IKEv2), ML-DSA-65 / SLH-DSA certificates |
| **Hybrid** | classical + PQC combined, safe against "harvest now, decrypt later" | X25519MLKEM768, SecP256r1MLKEM768, `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, IKEv2 ECP-256 + ML-KEM-768 (RFC 9370) |
| **Draft** | pre-standard PQC that must be migrated | X25519Kyber768Draft00 (0x6399) |
| **Classical** | secure today, breakable by a quantum computer | ECDHE / X25519, finite-field DH, Curve25519 (WireGuard), MKA |
| **Weak** | already broken or deprecated | RSA key transport, DH group 1/2/5, `diffie-hellman-group14-sha1`, SHA-1 / MD5 signatures |

**PQC readiness score** = share of key exchanges that are hybrid or post-quantum (draft counts half),
shown in the CLI, the HTML report and the Studio Insights gauge (graded A–F).

| Protocol | What is decoded | Problems detected |
|---|---|---|
| TLS 1.2 / 1.3 | supported_groups, key_share sizes, signature_algorithms, selected group, HelloRetryRequest, ECH, Certificate | PQC offered but classical selected, HelloRetryRequest round trip, draft Kyber, **large PQC ClientHello dropped / reset by a middlebox**, ECH in use |
| X.509 | subject / issuer, validity, SAN, key algorithm and size, signature algorithm (incl. ML-DSA / SLH-DSA OIDs); from TLS 1.2, decrypted TLS 1.3 and **EAP-TLS fragments** | expired / not yet valid (and future capture clocks), expiring within 30 days, self-signed leaf, RSA < 2048 / DSA, SHA-1 / MD5 signatures, PQC certificates |
| SSH | banner, KEXINIT lists, negotiated kex / host key / cipher / MAC, DISCONNECT | weak algorithms offered or negotiated, **Terrapin (CVE-2023-48795)** exposure, SSH-1, no common key exchange |
| IKEv1 / IKEv2 | SA proposals and transforms, KE groups, RFC 9370 ADDKE, IKE_INTERMEDIATE, RFC 7383 fragments, notifies, NAT-T | NO_PROPOSAL_CHOSEN / INVALID_KE / AUTH_FAILED / TS_UNACCEPTABLE, unanswered requests, weak crypto, IKEv1 / Aggressive Mode, **ML-KEM without IKEv2 fragmentation** |
| ESP | SPI and sequence number per SA | gaps (loss hidden by encryption), duplicates (replay), reordering |
| MACsec / MKA | SecTAG (AN, PN, SCI, E/C bits), MKPDU parameter sets, live / potential peers, distributed SAK cipher suite | integrity-only links, PN gaps / replays, **PN exhaustion** on non-XPN ciphers, participants with no live peer, CKN mismatch |
| QUIC, WireGuard | TLS inside decrypted QUIC Initials; Noise_IKpsk2 handshakes | added to the inventory; unanswered WireGuard handshakes |

## AI traffic

`experts/ai.py` recognises generative-AI services from **every name the capture offers**: TLS
and QUIC SNI, DNS answers, HTTP Host and certificate CN/SAN. It covers OpenAI / ChatGPT,
Anthropic / Claude, Gemini, Vertex AI, Azure OpenAI, Microsoft and GitHub Copilot, AWS Bedrock,
Mistral, Cohere, Hugging Face, Perplexity, DeepSeek, xAI, Groq, Together, Fireworks, Replicate,
OpenRouter, Cursor, Codeium and more. It also recognises API request shapes (OpenAI-compatible
`/v1/chat/completions`, Anthropic `/v1/messages`, Gemini `:generateContent`, Bedrock
`/invoke` / `/converse`, Ollama `/api/chat`, KServe), **MCP** JSON-RPC (`initialize`,
`tools/list`, `tools/call` and the tool name) and **gRPC inference** services (Triton / KServe v2,
TensorFlow Serving).

For every AI flow it measures upload and download volume and a **streaming profile from packet
timing**, so it works on encrypted traffic: the time from the request to the first response burst
(time to first token) and the longest pause mid-stream.

| Finding | When |
|---|---|
| AI services in use | inventory per provider and client (info) |
| Consumer AI assistants | chat assistants used directly (possible shadow AI) |
| Large upload to an AI service | ≥ 1 MB from one client in one flow (≥ 10 MB = high) |
| AI API key over plain HTTP | Authorization / x-api-key sent to an AI API over cleartext HTTP |
| Unauthenticated self-hosted model server | Ollama / OpenAI-compatible server answering clients without authentication |
| Slow first response / stream stall | time to first token ≥ 5 s, or ≥ 5 s gap mid-stream |
| Rate limited | HTTP 429 / 503 / 529 from an AI API |
| MCP traffic | MCP methods and tools called; medium when carried over cleartext HTTP |
| gRPC errors | non-zero `grpc-status` from HTTP/2 trailers (UNAVAILABLE, DEADLINE_EXCEEDED, …) |

## AI fabric (RoCEv2 / PFC)

GPU training clusters run RDMA over lossless Ethernet: one lossy link slows every rank of a
collective operation. `experts/fabric.py` tracks every RoCEv2 queue pair (UDP 4791, InfiniBand
BTH / AETH) together with ECN marks and 802.1Qbb PFC frames:

* **packet loss**: PSN gaps, go-back-N retransmissions, NAK (PSN sequence error) and RNR NAK;
* **congestion**: Congestion Notification Packets (DCQCN) and ECN-CE marked packets;
* **misconfiguration**: RoCE traffic that is not ECN-capable, so DCQCN cannot react;
* **PFC pause storms**: a port pausing a priority continuously, with sustained frame rate and max quanta.

Root causes link them: *congestion spreading* (pause storm + RoCE loss or CNPs) and *lossy RoCE
fabric* (loss with neither PFC nor ECN feedback).

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
* **Crypto · PQC**: readiness score, key-exchange mix, every session with its quantum status,
  certificates with issues, ESP SAs, MACsec channels and MKA participants.
* **AI traffic** and **AI fabric**: services and flows with time to first response and stalls,
  MCP calls; RoCEv2 queue pairs and PFC senders. These tabs appear only when the capture has such traffic.
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
* **Insights** — three dashboards per capture:
  * **Crypto & PQC**: readiness gauge, key-exchange mix overall and per protocol, a searchable
    session table filtered by quantum status, certificate cards with a validity bar, and ESP / MACsec / MKA tables.
  * **AI traffic**: services with upload / download bars, flows with time-to-first-response and stall bars, MCP calls.
  * **AI fabric**: RoCEv2 queue pairs and PFC senders.

  Selecting any row or evidence chip opens that packet in Analyze.

Across the Studio:

* **Findings panel** (capture view and Insights): search, severity chips with counts, grouping by
  category or protocol, expandable root-cause chains with clickable steps, evidence-packet chips,
  and **Apply in Analyze** for each finding's display filter (or **Copy for Wireshark** when the
  filter uses Wireshark-only fields).
* **Command palette** (`Ctrl K` / `⌘ K`): jump to any view or capture, open a capture file, switch
  theme, open the current capture's dashboards, or apply a common display filter.
* **Drop a capture anywhere** to analyze it; loading skeletons and clear empty / error states
  with retry.
* **Light and dark themes** (follow the OS until you choose), keyboard focus rings, skip link,
  reduced-motion support and a narrow-screen layout.

| Shortcut | Action |
|---|---|
| `Ctrl K` / `⌘ K` | command palette |
| `?` | list shortcuts |
| `/` | focus the search or display-filter box |
| `t` | switch light / dark theme |
| `g` then `l` / `a` / `i` / `s` / `v` | Library / Analyze / Insights / Simulator / Live |
| `↑ ↓ PgUp PgDn Home End`, `Ctrl M` | move in and mark the packet list (Analyze) |

## Display filters

The built-in engine (`dfilter.py`) understands Wireshark syntax: `== != > < >= <=`, `contains`,
`matches`, `in {…}`, `and / or / not`, CIDR, `frame contains`, and the `tcp.analysis.*` flags.
Fields for the newer protocols:

| Area | Fields and protocols |
|---|---|
| Post-quantum TLS | `tls.pqc`, `tls.ech`, `tls.handshake.extensions_supported_group`, `tls.handshake.extensions_key_share_group`, `tls.handshake.sig_hash_alg`, `x509af`, `x509sat.CommonName`, `x509af.algorithm` |
| SSH | `ssh`, `ssh.pqc`, `ssh.protocol`, `ssh.message_code`, `ssh.kex_algorithms` |
| IPsec | `isakmp`, `isakmp.version`, `isakmp.exch_type`, `isakmp.ispi`, `isakmp.notify.msgtype`, `isakmp.notify.error`, `isakmp.pqc`, `esp`, `esp.spi`, `esp.sequence` |
| MACsec / 802.1X | `macsec`, `macsec.an`, `macsec.pn`, `macsec.sci`, `macsec.encrypted`, `mka`, `eapol.type`, `eap.type` |
| QUIC / WireGuard | `quic`, `quic.version`, `quic.long.packet_type`, `quic.dcid`, `quic.scid`, `wg`, `wg.type`, `wg.sender`, `wg.receiver`, `wg.counter` |
| AI fabric | `infiniband`, `infiniband.bth.opcode`, `infiniband.bth.psn`, `infiniband.bth.destqp`, `infiniband.aeth.syndrome`, `pfc`, `pfc.priority`, `ip.dsfield.ecn` |
| AI / HTTP | `http.authorization`, `grpc`, plus `tls.handshake.extensions_server_name`, which also matches QUIC SNI |

Examples: `tls.pqc && tcp.analysis.retransmission`, `isakmp.notify.error`,
`infiniband.bth.opcode == 129` (CNP), `ip.dsfield.ecn == 3`, `macsec.encrypted == 0`.

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

* The terminal report header includes a **PQC readiness** line, the AI services seen and an AI
  fabric summary when present.
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

Crypto analysis on real 802.1X / ISE and SSL samples:

| Capture | PacketLens verdict |
|---|---|
| `EAP-TLS.pcap`, `EAP-TLS-Wireless.pcap` | server and client certificates reassembled from EAP-TLS fragments; SHA-1 signatures flagged |
| `wiredradiusfiltered.pcap` | ISE certificate from RADIUS EAP-Message attributes; expiry reported together with a capture clock set in the future |
| `rsasnakeoil2.cap` | RSA key transport (weak, no forward secrecy); RSA-1024 / MD5 certificate |
| `tls12-dsb.pcapng` | ECDHE (classical); certificate expiring within 30 days |

## Testing

```
python -m unittest discover -s tests
```

About 120 tests cover the readers, every decoder, the experts and root causes, display filters,
the HTML report, the Studio API and assets, and live capture. Known-answer vectors include
RFC 8448 (TLS 1.3 HKDF), the TLS 1.2 PRF and RFC 9001 Appendix A (QUIC Initial keys).
Post-quantum, AI, QUIC, WireGuard and RoCE scenarios use synthetic traffic from `synth_crypto.py` and
`synth_ai.py`, because public captures of them are rare. Tests that need `cryptography` or
`hpack` are skipped without them, so run the suite with `.[full]` installed for full coverage.

## Project layout

```
packetlens/
  reader.py        pcap/pcapng reader (µs/ns, multi-section, EPB/SPB/PB, Decryption Secrets Block) + writers
  decode.py        L2→L7 dissector            packet.py   packet model
  protocols/       dns, dhcp, http, http2, tls (JA3, groups, key shares, ECH), x509, ssh, ike (IKEv1/v2, ESP),
                   macsec (SecTAG, MKA), auth (EAPOL, EAP-TLS, RADIUS), quic, wireguard, roce (BTH/AETH, PFC),
                   ai (service catalog, API shapes, MCP), pqc (algorithm registry), bgp, ospf, eigrp, rip, isis,
                   fhrp (HSRP/VRRP), l2 (arp, icmp, stp), l2ctl, mcast, tunnel, wlan
  flows.py         conversations + TCP stream analysis (tcp.analysis.* equivalents)
  reassembly.py    TCP stream reassembly + message framing (TLS, HTTP/1, HTTP/2, BGP, DNS, SSH)
  tlsdecrypt.py    key log, TLS 1.2 PRF / TLS 1.3 HKDF key schedules, AEAD record decryption
  compare.py       two-point capture comparison (loss location, one-way delay, clock offset)
  live.py          AF_PACKET live capture
  experts/         tcp, network, dns, dhcp, web (HTTP, TLS, HTTP/2, gRPC), routing, switching, multicast,
                   tunnels, access (802.1X), ipv6, quic, crypto (PQC inventory), ai, fabric, security
  knowledge.py     causes / perspectives / remediation / recommendations / filters (~200 entries)
  correlate.py     cross-layer root-cause engine
  analyzer.py      pipeline, stats, health score, colouring rules
  dfilter.py       Wireshark-syntax display-filter engine      fields.py   packet details tree
  report/          self-contained HTML report
  app/             PacketLens Studio (server, library, workbench; static/ app.js, analyze.js, insights.js, scene.js)
  cli.py, web.py   command line and local web UI
  synth.py, synth_crypto.py, synth_ai.py   synthetic capture generators (demo + tests)
tests/             unittest suite (python -m unittest discover -s tests)
```

## Limitations

* **QUIC / HTTP/3**: Initial packets are decrypted (SNI, ALPN, key shares, with `cryptography`),
  but 1-RTT application data is not. TLS 1.2 **CBC** suites are not decrypted (AEAD suites cover
  practically all current traffic). TLS 1.3 `KeyUpdate` is not followed.
* **Encrypted handshakes:** TLS 1.3 certificates are only visible with a key log. SSH, IKE and
  QUIC 1-RTT contents after the key exchange stay opaque, and the AI streaming profile is a timing
  estimate rather than a token count.
* **Display filters:** some knowledge-base filters use Wireshark-only fields (for example
  `dns.time`, `ospf.msg.hello`). The Studio offers to copy them for Wireshark instead of applying them.
* **HTTP/2 headers** need the optional `hpack` package; without it, frames and error codes are
  still analyzed. HPACK state can't be recovered for connections that started before the
  capture.
* **Memory:** decoded packet metadata is about 1.7 KB/packet (300k packets ≈ 520 MB peak; about
  21k packets/s). For multi-million-packet files, slice with `editcap` or use `--max-packets`.
* **Live capture** is Linux-only (`AF_PACKET`) with simple host/port filters rather than BPF.

## License

MIT for the code. Chris Greer's sample captures and profiles belong to their author; see his
repositories for their licenses.
