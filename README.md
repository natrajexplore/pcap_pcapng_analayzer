# PacketLens — modern pcap / pcapng analyzer with root-cause correlation

PacketLens reads `.pcap` / `.pcapng` captures and does what an experienced packet analyst
does with Wireshark: it decodes every conversation from source to destination, flags what is
wrong, **correlates symptoms across layers into root causes**, explains *why* it happened from
**every perspective** (client, server, network path, routing control plane, application,
security) and gives concrete **remediation and recommendations**, with the Wireshark display
filter to jump to the evidence.

* **Zero dependencies.** Pure Python 3.10+ standard library, so it runs anywhere Python runs.
* **Three ways to use it:** CLI with a terminal report, a self-contained interactive HTML report
  that works offline, and a local drag-and-drop web UI.
* **Built on Chris Greer's (Packet Pioneer) methodology.** The expert rules, packet colouring
  and thresholds are taken from his published Wireshark profiles, and the analyzer is validated
  against his public sample captures (see [Validation](#validation-on-real-captures)).

```
pip install .
packetlens demo                                    # generate + analyze a capture covering every analyzer
packetlens analyze capture.pcapng --html report.html
packetlens serve                                   # http://127.0.0.1:8080, drop a capture in the browser
```

---

## What it analyzes

| Layer | Protocols | Highlights |
|---|---|---|
| Link | Ethernet, 802.1Q VLAN, Linux SLL/SLL2, raw IP, loopback, ARP, STP | duplicate IP / ARP spoofing of the gateway, unanswered ARP, ARP scans, STP topology changes and multiple roots, broadcast share |
| Network | IPv4, IPv6 (extension headers), ICMP, ICMPv6 | TTL/hop analysis and OS family, multiple TTL signatures for one IP (middlebox or spoofing), link-local multicast TTL ≠ 1, fragmentation, checksum errors, unreachable / admin-prohibited / frag-needed (PMTUD) / TTL-exceeded (loops) / redirects, with the embedded original flow |
| Transport | TCP, UDP | Wireshark `tcp.analysis.*` equivalents: retransmission, fast and spurious retransmission, out-of-order, previous segment not captured, ACKed unseen, duplicate ACK, zero window and probes, window full, window update, keep-alive. Also iRTT split into client and server side (capture-point location), bytes in flight, window scaling, SACK, MSS, conversation completeness, RST classification (refused / abort / after FIN), TCP delta gaps with **who-was-waiting attribution**, and application response time |
| Application | DNS, DHCP, HTTP/1.x (URLs), TLS (SNI, ALPN, versions, ciphers, alerts, JA3) | DNS latency, timeouts, NXDOMAIN, SERVFAIL, REFUSED, truncation, tunneling/DGA, external resolvers. DHCP DORA reconstruction: no offer, no ack, NAK, DECLINE, rogue servers, APIPA. HTTP 4xx/5xx, `http.time`, cleartext credentials, scanner user agents, file downloads, full URL inventory. TLS old versions, weak ciphers, handshake failures, known-bad JA3 |
| Routing | BGP, OSPFv2/v3, EIGRP, RIPv1/v2 | BGP sessions, OPEN/UPDATE/NOTIFICATION decoding with error codes, withdrawals, flaps, TCP/179 failures. OSPF hello/dead, area, mask, auth and MTU mismatch, EXSTART stuck, duplicate RID, one-way adjacency, LSU storms. EIGRP K-value / AS / auth mismatch, SIA, query storms, reliable retransmissions, goodbye, unreachable routes. RIP version mismatch, metric-16 poisoning, missed updates, v1/no-auth |
| Security | threat hunting | port scans with open-port list, nmap SYN / Null / Xmas signatures, host sweeps, Log4Shell strings, PE executables in transit, cleartext protocols, abused ports |

## How the analysis works

```
 pcap/pcapng ─► reader ─► dissector ─► flow tracker ─► expert analyzers ─► correlation engine ─► reports
                (pcap,    (L2→L7)      (TCP state,     (tcp, network,      (root-cause chains     (CLI, HTML,
                 pcapng,               conversations,   dns, dhcp, web,     across layers          JSON, web UI)
                 ns/µs)                tcp.analysis)    routing, security)  and time)
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

## CLI

```
packetlens analyze CAPTURE [--html FILE] [--json FILE|-] [-v] [-q] [--max-packets N]
                           [--packet-list N] [--fail-on critical|high|medium|low] [--no-color]
packetlens demo    [--out demo.pcapng] [--html demo.html] [--format pcapng|pcap]
packetlens serve   [--host 127.0.0.1] [--port 8080] [--max-mb 200]
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

Sliced captures (snaplen 66–200 bytes, common in these samples) are handled: TCP segment
lengths come from the IP header, so sequence analysis stays correct and the report warns that
application-layer decoding may be incomplete.

## Project layout

```
packetlens/
  reader.py        pcap/pcapng reader (µs/ns, multi-section, EPB/SPB/PB) + writers
  decode.py        L2→L7 dissector            packet.py   packet model
  protocols/       dns, dhcp, http, tls (JA3), bgp, ospf, eigrp, rip, l2 (arp, icmp, stp)
  flows.py         conversations + TCP stream analysis (tcp.analysis.* equivalents)
  experts/         tcp, network, dns, dhcp, web, routing, security
  knowledge.py     causes / perspectives / remediation / recommendations / filters
  correlate.py     cross-layer root-cause engine
  analyzer.py      pipeline, stats, health score, colouring rules
  report/          self-contained HTML report
  cli.py, web.py   command line and local web UI
  synth.py         synthetic multi-scenario capture generator (demo + tests)
tests/             unittest suite (python -m unittest discover -s tests)
```

## Limitations and roadmap

* HTTP/2, HTTP/3/QUIC payloads, and TLS 1.3 encrypted records are identified but not decrypted
  (no key-log support yet).
* TCP reassembly is per segment: application messages split across segments are decoded from
  the first segment only.
* The whole capture is held in memory. That's fine for typical troubleshooting captures (hundreds
  of thousands of packets); for multi-GB files, slice first with `editcap`, or use
  `--max-packets`.
* Planned: SSLKEYLOGFILE decryption, IS-IS/HSRP/VRRP analyzers, multi-point capture merge
  (client-side and server-side captures analyzed together to locate loss), and a live capture
  mode.

## License

MIT for the code. Chris Greer's sample captures and profiles belong to their author; see his
repositories for their licenses.
