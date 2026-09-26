"""Cross-protocol correlation engine.

Individual expert findings describe *symptoms*. This module links symptoms across
layers and time into *root-cause chains* - e.g. "OSPF MTU mismatch → adjacency
stuck → routes missing → ICMP net-unreachable → TCP SYNs unanswered" - and
explains why it happened from every perspective together with remediation.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .findings import SEVERITY_ORDER


@dataclass
class RootCause:
    id: str
    title: str
    severity: str
    confidence: float
    verdict: str                       # the single-sentence "what really happened"
    narrative: str                     # why it happened
    chain: list = field(default_factory=list)       # ordered steps {t, no, layer, text}
    evidence: list = field(default_factory=list)    # finding uids
    affected: list = field(default_factory=list)
    perspectives: dict = field(default_factory=dict)
    remediation: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    fault_domain: str = ""             # client | server | network | routing | application | security | capture

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("id", "title", "severity", "confidence", "verdict", "narrative", "chain",
                                              "evidence", "affected", "perspectives", "remediation",
                                              "recommendations", "fault_domain")}


def step(ctx, no, layer, text, t=None):
    p = ctx.pkt(no) if no else None
    when = p.rel_ts if p else t
    return {"t": None if when is None else round(when, 6), "no": no, "layer": layer, "text": text}


def _dedupe(items):
    seen, out = set(), []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _by(ctx, fid):
    return [f for f in ctx.findings if f.id == fid]


def correlate(ctx) -> list[RootCause]:
    out: list[RootCause] = []
    for rule in (_firewall_block, _middlebox_reset, _pmtud, _routing_impact, _bgp_transport, _ospf_adjacency,
                 _eigrp_adjacency, _isis_adjacency, _fhrp, _dns_impact, _dhcp_chain, _rogue_dhcp, _arp_mitm, _receiver_bottleneck,
                 _loss_vs_server, _stp_l2, _attack_chain, _capture_quality):
        try:
            out.extend(rule(ctx) or [])
        except Exception as exc:  # a broken rule must never break the report
            ctx.warnings.append(f"correlation rule {rule.__name__} failed: {exc!r}")
    for r in out:
        r.chain.sort(key=lambda st: (st["t"] is None, st["t"] or 0))
        r.remediation = _dedupe(r.remediation)
        r.recommendations = _dedupe(r.recommendations)
        r.evidence = _dedupe(r.evidence)
    out.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 9), -r.confidence))
    return out


# ------------------------------------------------------------------ rules ---
def _firewall_block(ctx):
    res = []
    admin = _by(ctx, "icmp_admin_prohibited")
    blocked = {}
    for p in ctx.packets:
        d = p.layers.get("icmp")
        if d and (d["type"] == 3 and d["code"] in (9, 10, 13)) and d.get("original"):
            o = d["original"]
            blocked.setdefault((o["src"], o["dst"], o.get("dport")), []).append((p, p.src))
    syn_fail = _by(ctx, "tcp_syn_no_response") + _by(ctx, "tcp_conn_refused")
    for f in syn_fail:
        det = f.details
        srv, cli = det.get("server"), det.get("client")
        ports = det.get("ports") or [det.get("port")]
        for port in ports:
            hit = blocked.get((cli, srv, port))
            if not hit:
                continue
            icmp_pkt, fw = hit[0]
            res.append(RootCause(
                "firewall_block", f"Firewall/ACL on {fw} blocks {cli} → {srv}:{port}", "high", 0.95,
                f"The connection failure is caused by an explicit policy on {fw}, not by the server or a network outage.",
                f"{cli} attempted TCP {srv}:{port}. Device {fw} answered with ICMP 'administratively prohibited' "
                f"embedding the original packet — the ACL/firewall rule is rejecting this 5-tuple. The server never saw the request.",
                [step(ctx, f.packets[0] if f.packets else None, "Transport", f"{cli} sends SYN to {srv}:{port}"),
                 step(ctx, icmp_pkt.no, "Network", f"{fw} replies ICMP type 3 code {icmp_pkt.layers['icmp']['code']} (admin prohibited)"),
                 step(ctx, f.packets[-1] if f.packets else None, "Application", "Client connection fails / retries")],
                [f.uid] + [a.uid for a in admin], [cli, srv, fw],
                {"client": "Client is healthy; its traffic is policy-blocked.",
                 "server": "Server is not at fault — the request never reached it.",
                 "network": f"Filtering device {fw} is the choke point.",
                 "security": "Validate whether the block is intended (policy) or a rule-change regression.",
                 "application": "Feature depending on this flow is broken."},
                [f"Review rules on {fw} matching src {cli} dst {srv} port {port}", "Check recent firewall change tickets",
                 "If legitimate, add a permit rule scoped to the application"],
                ["Maintain an application-flow inventory and test firewall changes against it"], "security"))
    return res


def _middlebox_reset(ctx):
    res = []
    ttl_by = defaultdict(lambda: defaultdict(set))
    rsts = {}
    for p in ctx.packets:
        if p.tcp and p.ttl is not None:
            if p.tcp.rst:
                rsts.setdefault(p.tcp.stream, p)
            else:
                ttl_by[p.tcp.stream][p.src].add(p.ttl)
    for st in ctx.flows.streams:
        p = rsts.get(st.id)
        if not p or not ttl_by[st.id].get(p.src) or st.client in ctx.scanners or p.src in ctx.scanners:
            continue   # scanners craft raw packets with arbitrary TTLs
        normal = ttl_by[st.id][p.src]
        if all(abs(p.ttl - t) >= 3 for t in normal):
            if len(res) >= 5:
                break
            res.append(RootCause(
                "middlebox_reset", f"RST for stream {st.id} injected by a middlebox (TTL mismatch)", "high", 0.8,
                f"The TCP reset claiming to be from {p.src} was generated by a device in the path, not by {p.src} itself.",
                f"Packets genuinely from {p.src} arrive with TTL {sorted(normal)}, but the RST arrived with TTL {p.ttl}. A different "
                f"hop count means a different device crafted it — typically a firewall, IPS, proxy or load balancer enforcing policy or an idle timeout.",
                [step(ctx, st.first_no, "Transport", f"Stream {st.id} {st.client}:{st.cport} ↔ {st.server}:{st.sport} established"),
                 step(ctx, p.no, "Transport", f"RST 'from' {p.src} with TTL {p.ttl} (expected {sorted(normal)})")],
                [], [st.client, st.server],
                {"network": "Find the device whose hop distance matches the RST TTL (traceroute).",
                 "security": "IPS/NGFW policy (URL/SNI filtering, signature match) is the likely source.",
                 "server": f"{p.src} did not reset the connection.", "application": "Transaction aborted by the network."},
                ["Check IPS/firewall logs for this session", "Compare idle timeouts vs application keep-alives"],
                ["Log and alert on policy-driven resets so users get clear errors"], "network"))
    return res


def _pmtud(ctx):
    res = []
    frag = _by(ctx, "icmp_frag_needed")
    mtu_f = _by(ctx, "ospf_mtu_mismatch")
    big_retrans = []
    blackholed = []   # streams where EVERY full-size segment in a direction needed retransmission
    for st in ctx.flows.streams:
        mss = min(x for x in (st.c.mss, st.s.mss, 1460) if x)
        full = [e for e in st.ladder if e["len"] >= mss - 40]
        rtx = [e for e in full if "retransmission" in e["analysis"]]
        if rtx:
            big_retrans.append((st, rtx[0]))
            for d in ("c2s", "s2c"):
                again = [e for e in rtx if e["dir"] == d]
                rtx_seqs = {e["seq"] for e in st.ladder if e["dir"] == d and "retransmission" in e["analysis"]}
                orig = [e for e in full if e["dir"] == d and "retransmission" not in e["analysis"]]
                # black hole only if NO full-size segment ever got through: every full-size original was retransmitted
                if again and orig and all(e["seq"] in rtx_seqs for e in orig):
                    blackholed.append((st, again[0]))
    small_ok = [st for st, _ in blackholed if st.completeness & 4]
    if frag:
        f = frag[0]
        mt = f.details.get("mtus")
        # hosts named inside the ICMP messages; their streams' retransmissions are the loss PMTUD caused
        hosts = {v for p in ctx.packets if "icmp" in p.layers and (p.layers["icmp"].get("original") or {})
                 for v in (p.layers["icmp"]["original"]["src"], p.layers["icmp"]["original"]["dst"])}
        if not big_retrans:
            for st in ctx.flows.streams:
                e = next((e for e in st.ladder if "retransmission" in e["analysis"] and e["len"]), None)
                if e and st.client in hosts and st.server in hosts:
                    big_retrans.append((st, e))
        chain = [step(ctx, f.packets[0], "Network", f"Router {', '.join(f.details['reporters'])} reports next-hop MTU {mt}")]
        for st, e in big_retrans[:3]:
            chain.append(step(ctx, e["no"], "Transport", f"Full-size segment ({e['len']} B) retransmitted on stream {st.id}"))
        res.append(RootCause(
            "pmtud", "Path MTU reduction causing large-packet loss", "high", 0.85 if big_retrans else 0.6,
            "A lower-MTU link in the path drops full-size packets; small packets (handshakes) succeed while bulk data stalls.",
            f"The path contains a link with MTU {mt}. Senders using DF-bit packets larger than this receive ICMP 'fragmentation needed'. "
            "If those ICMPs are filtered anywhere, or the sender ignores them, full-size segments are silently dropped → retransmissions → stalls (PMTUD black hole).",
            chain, [x.uid for x in frag], f.details.get("reporters", []),
            {"client": "Page/transfer hangs after connecting.", "server": "Must lower its segment size for this path.",
             "network": "Tunnel/PPPoE/VPN link reduces MTU; MSS clamping missing.",
             "security": "Blanket ICMP blocking breaks PMTUD.", "application": "Large responses fail; small ones work."},
            ["Clamp TCP MSS on the tunnel interface to MTU-40", "Permit ICMP type 3 code 4 / ICMPv6 type 2 end-to-end"],
            ["Standardize MTU; consider PLPMTUD"], "network"))
    elif blackholed and not frag:
        # strongest evidence: after full-size segments time out, the sender falls back to small
        # segments (RFC 4821 / OS black-hole detection, typically 536 B) and data suddenly flows
        fallback = []
        for st, first in blackholed:
            d = first["dir"]
            last_rtx = max(e["no"] for e in st.ladder if e["dir"] == d and "retransmission" in e["analysis"] and e["len"] >= first["len"] - 40)
            after = [e for e in st.ladder if e["dir"] == d and e["no"] > last_rtx and e["len"]]
            ok = [e for e in after if not e["analysis"]]
            if len(ok) >= 3 and max(e["len"] for e in ok) <= first["len"] - 200:
                fallback.append((st, first, ok[0], max(e["len"] for e in ok)))
        if fallback or len(small_ok) >= 2:
            chain = [step(ctx, e["no"], "Transport", f"stream {st.id}: {e['len']} B full-size segment retransmitted (no ICMP 'frag needed' seen)")
                     for st, e in ([(f[0], f[1]) for f in fallback] or blackholed)[:2]]
            for st, first, ok0, small in fallback[:2]:
                rtx = [e for e in st.ladder if e["dir"] == first["dir"] and "retransmission" in e["analysis"]]
                chain += [step(ctx, e["no"], "Transport", f"retransmission after {e['t'] - first['t']:.1f} s (RTO back-off)") for e in rtx[1:4]]
                chain.append(step(ctx, ok0["no"], "Transport", f"sender falls back to ≤{small} B segments — data now flows"))
            res.append(RootCause(
                "pmtud_blackhole", "PMTUD black hole: full-size packets silently dropped on the path",
                "high" if fallback else "medium", 0.9 if fallback else 0.5,
                ("Full-size segments were silently dropped somewhere on the path and no ICMP 'fragmentation needed' came back; "
                 "the sender only recovered after its black-hole detection shrank the segment size." if fallback else
                 "Only maximum-size segments are being retransmitted while handshakes and small packets succeed."),
                "A link on the path has a smaller MTU than the endpoints assume (tunnel, VPN, PPPoE, mis-set interface MTU) and the ICMP "
                "that should tell the sender to shrink its packets is filtered or never generated. Small packets (handshake, requests) pass; "
                "every full-size data segment is dropped until the sender's retransmission timeouts expire. "
                + (f"Stalled for ≈{fallback[0][2]['t'] - fallback[0][1]['t']:.0f} s before falling back to {fallback[0][3]}-byte segments." if fallback else ""),
                chain, [f.uid for f in _by(ctx, "tcp_retransmissions")], sorted({st.server for st, *_ in (fallback or blackholed)}),
                {"client": "Session connects fine, then the transfer hangs for tens of seconds.",
                 "server": "Server retransmits full-size segments with exponential back-off, then shrinks its MSS.",
                 "network": "Find the low-MTU hop (ping -M do -s <size>, tracepath) and whether a device drops ICMP type 3 code 4.",
                 "security": "Over-aggressive ICMP filtering on a firewall is the classic cause.",
                 "application": "Looks like a slow or hanging application although the app is not at fault."},
                ["Locate the smallest-MTU hop with tracepath / ping -M do -s 1472 and step down",
                 "Clamp TCP MSS on the tunnel/WAN interface (e.g. ip tcp adjust-mss 1360)",
                 "Permit ICMP type 3 code 4 (and ICMPv6 type 2) through firewalls"],
                ["Standardize MTU end-to-end; enable PLPMTUD (net.ipv4.tcp_mtu_probing=1) on servers"], "network"))
    if mtu_f:
        f = mtu_f[0]
        res.append(RootCause(
            "ospf_mtu", "Interface MTU mismatch between OSPF neighbors", "critical", 0.95,
            "OSPF neighbors disagree on interface MTU so the adjacency can't finish database exchange — and the data plane has an MTU mismatch too.",
            f.summary, [step(ctx, n, "Routing", "DBD with conflicting MTU") for n in f.packets[:4]], [f.uid], f.entities,
            {"routing": "Neighbors stuck in EXSTART/EXCHANGE; no routes exchanged over this link.",
             "network": "Large frames from the higher-MTU side are dropped by the lower-MTU side."},
            ["Set identical MTU on both interfaces (preferred) or 'ip ospf mtu-ignore' as a workaround"],
            ["Standardize MTU per link type in configuration templates"], "routing"))
    return res


ROUTING_EVENT_IDS = ("bgp_notification", "bgp_withdrawals", "eigrp_goodbye", "eigrp_sia", "eigrp_unreachable_routes",
                     "rip_unreachable_routes", "ospf_lsu_storm", "stp_topology_change", "bgp_session_flap",
                     "fhrp_flap", "fhrp_split_brain", "isis_lsp_churn")
IMPACT_IDS = ("icmp_unreachable", "icmp_ttl_exceeded", "tcp_syn_no_response", "tcp_retransmissions", "tcp_reset_abort")


def _routing_impact(ctx):
    res = []
    events = [f for f in ctx.findings if f.id in ROUTING_EVENT_IDS and f.ts is not None]
    if not events:
        return res
    t0 = min(f.ts for f in events)
    impacts = [f for f in ctx.findings if f.id in IMPACT_IDS and f.ts is not None and t0 - 2 <= f.ts <= t0 + 120]
    # also look at raw ICMP events directly for time precision
    icmp_after = [p for p in ctx.packets if "icmp" in p.layers and p.layers["icmp"]["type"] in (3, 11) and t0 <= p.ts <= t0 + 120]
    if not impacts and not icmp_after:
        return res
    chain = [step(ctx, f.packets[0] if f.packets else None, "Routing", f"{f.title}: {f.summary[:140]}", t=f.ts - ctx.t0)
             for f in sorted(events, key=lambda f: f.ts)[:4]]
    chain += [step(ctx, p.no, "Network", f"{p.src}: {p.info}") for p in icmp_after[:3]]
    chain += [step(ctx, f.packets[0] if f.packets else None, "Transport/App", f"{f.title}", t=f.ts - ctx.t0)
              for f in sorted(impacts, key=lambda f: f.ts)[:3]]
    loop = any(f.id == "icmp_ttl_exceeded" and f.severity == "high" for f in impacts)
    res.append(RootCause(
        "routing_impact", "Routing control-plane event disrupted data-plane traffic", "critical" if loop or len(impacts) > 1 else "high",
        0.75,
        "A routing change (session loss / route withdrawal / reconvergence) removed or altered paths, and user traffic failed in the same time window.",
        "Control-plane events precede data-plane failures within seconds: routes were withdrawn or recalculated, routers temporarily lacked a "
        "valid path (ICMP unreachable) " + ("or forwarded in a loop (TTL exceeded) " if loop else "") +
        "while convergence took place, so TCP sessions retransmitted or failed to connect.",
        chain, [f.uid for f in events + impacts], sorted({e for f in events for e in f.entities})[:10],
        {"routing": "Identify the first control-plane event — it is the trigger; later events are consequences.",
         "network": "ICMP reporters are routers lacking the route during convergence.",
         "client": "Users experience timeouts during convergence.", "server": "Server unreachable while routes are missing.",
         "application": "Outage duration ≈ convergence time; tune timers/BFD to reduce it."},
        ["Stabilize the trigger (link errors, config mismatch, peer reset)", "Verify routes are restored (show ip route / show bgp)",
         "Check for loops: consistent next hops between routers"],
        ["Enable BFD and fast convergence features", "Use graceful restart / NSF", "Monitor routing adjacency changes with alerts"],
        "routing"))
    return res


def _bgp_transport(ctx):
    res = []
    for f in _by(ctx, "bgp_notification"):
        if f.details.get("code") == 4 and f.details.get("tcp_retrans"):
            res.append(RootCause(
                "bgp_hold_loss", f"BGP hold timer expiry caused by packet loss on the peering ({' ↔ '.join(f.details['peers'])})",
                "critical", 0.85,
                "Transport-level packet loss delayed BGP KEEPALIVEs beyond the hold time, so the peer declared the session dead.",
                f"The BGP TCP session shows {f.details['tcp_retrans']} retransmissions before the NOTIFICATION (Hold Timer Expired). "
                "Keepalives were stuck behind lost/retransmitted segments; once the hold time elapsed the session was torn down and all prefixes withdrawn.",
                [step(ctx, None, "Transport", f"{f.details['tcp_retrans']} TCP retransmissions on TCP/179", t=(f.ts or ctx.t0) - ctx.t0 - 1),
                 step(ctx, f.packets[0], "Routing", "NOTIFICATION: Hold Timer Expired"),
                 step(ctx, None, "Routing", "All routes from the peer withdrawn; traffic re-routed/black-holed", t=(f.ts or ctx.t0) - ctx.t0)],
                [f.uid], f.details["peers"],
                {"network": "Lossy/congested link between the peers or control-plane policing dropping BGP.",
                 "routing": "Session reset → full table re-exchange → churn.", "application": "Loss of reachability for affected prefixes."},
                ["Fix loss on the peering link (errors/congestion)", "Prioritize BGP (CS6) in QoS and CoPP", "Enable BFD"],
                ["Monitor TCP retransmissions on routing sessions", "Consider longer hold time only as a temporary mitigation"], "network"))
    return res


def _ospf_adjacency(ctx):
    ids = ("ospf_hello_mismatch", "ospf_area_mismatch", "ospf_mask_mismatch", "ospf_auth_mismatch", "ospf_one_way",
           "ospf_exstart_stuck", "ospf_duplicate_rid")
    fs = [f for f in ctx.findings if f.id in ids]
    if not fs:
        return []
    return [RootCause(
        "ospf_adjacency", "OSPF adjacency failure", "critical", 0.9,
        "OSPF neighbors cannot become FULL because their Hello/DBD parameters disagree — routes over this link are missing.",
        "OSPF requires matching hello/dead timers, area, mask (broadcast), authentication and MTU; any mismatch silently drops the neighbor's packets. Detected: "
        + "; ".join(f.summary for f in fs[:4]),
        [step(ctx, f.packets[0] if f.packets else None, "Routing", f.title) for f in fs[:5]],
        [f.uid for f in fs], sorted({e for f in fs for e in f.entities})[:10],
        {"routing": "Adjacency stuck in INIT/EXSTART or never formed; LSDB not synchronized; SPF computes paths without this link.",
         "network": "Traffic takes alternate (possibly suboptimal) paths or is black-holed.",
         "application": "Reachability issues to networks behind the affected router."},
        _dedupe(f.remediation[0] for f in fs[:6]),
        ["Use templates for OSPF interface parameters", "Alert on adjacency state changes (syslog/SNMP traps)"], "routing")]


def _eigrp_adjacency(ctx):
    ids = ("eigrp_k_mismatch", "eigrp_as_mismatch", "eigrp_auth_mismatch", "eigrp_goodbye", "eigrp_sia", "eigrp_retrans")
    fs = [f for f in ctx.findings if f.id in ids]
    if not fs:
        return []
    sia = any(f.id in ("eigrp_sia", "eigrp_retrans") for f in fs)
    return [RootCause(
        "eigrp_adjacency", "EIGRP neighbor instability" if sia else "EIGRP adjacency failure", "critical", 0.85,
        ("EIGRP queries are not answered in time (SIA) / reliable packets are retransmitted — neighbors will be reset, causing route loss."
         if sia else "EIGRP neighbors cannot peer due to configuration mismatch or a neighbor left the topology."),
        "; ".join(f.summary for f in fs[:4]),
        [step(ctx, f.packets[0] if f.packets else None, "Routing", f.title) for f in fs[:5]],
        [f.uid for f in fs], sorted({e for f in fs for e in f.entities})[:10],
        {"routing": "DUAL cannot converge normally; affected prefixes flap.",
         "network": "Retransmissions/SIA often trace back to a lossy link or overloaded router.",
         "application": "Intermittent reachability."},
        [f.remediation[0] for f in fs[:4]], ["Summarize and use stub routing to limit query scope"], "routing")]


def _dns_impact(ctx):
    res = []
    failed = [t for t in ctx.dns_transactions if t["response_no"] is None or t["rcode"] in ("SERVFAIL", "REFUSED", "NXDOMAIN")]
    by_client = defaultdict(list)
    for t in failed:
        by_client[t["client"]].append(t)
    for cli, ts in by_client.items():
        names = sorted({t["qname"] for t in ts})
        hard = [t for t in ts if t["rcode"] != "NXDOMAIN"]
        if not hard:
            continue
        servers = sorted({t["server"] for t in hard})
        res.append(RootCause(
            "dns_failure", f"Name resolution failure on {cli} prevents connections", "high", 0.8,
            f"{cli} could not resolve {', '.join(names[:3])}; no connection to those services was even attempted. The root cause is DNS, not the application servers.",
            f"Resolver(s) {', '.join(servers)} returned "
            f"{', '.join(sorted({t['rcode'] or 'no response' for t in hard}))}. Every application connection starts with name resolution, "
            "so the user sees an application failure that is actually a DNS problem.",
            [step(ctx, t["query_no"], "Application", f"Query {t['qtype']} {t['qname']} → {t['rcode'] or 'no response'} "
                                                    f"({t['retries']} retries)") for t in hard[:5]],
            [f.uid for f in ctx.findings if f.id.startswith("dns_") and f.severity in ("high", "critical")],
            [cli] + servers,
            {"client": "Client resolver configuration (DHCP option 6) points at the failing server(s).",
             "server": "Application servers are fine; they were never contacted.",
             "network": "Verify UDP/TCP 53 reachability to the resolver.",
             "application": "Name resolution precedes every connection.",
             "security": "If DNS is being blocked deliberately, confirm policy."},
            ["Test the resolver directly with dig/nslookup", "Fail over to a secondary resolver", "Check resolver forwarders/upstream"],
            ["Redundant resolvers, resolver health monitoring"], "application"))
    # slow DNS adding to connection time
    slow = [t for t in ctx.dns_transactions if t["time_ms"] and t["time_ms"] > 200]
    if slow:
        worst = max(slow, key=lambda t: t["time_ms"])
        res.append(RootCause(
            "dns_latency", "Slow DNS inflates application response time", "medium", 0.7,
            f"DNS lookups add up to {worst['time_ms']:.0f} ms before any connection starts.",
            "Users perceive slowness before the application server is involved: each new hostname waits on the resolver.",
            [step(ctx, t["query_no"], "Application", f"{t['qname']} resolved in {t['time_ms']:.0f} ms") for t in slow[:5]],
            [f.uid for f in _by(ctx, "dns_slow")], sorted({t["server"] for t in slow}),
            {"client": "Perceived slowness at page/app start.", "server": "Resolver slow (cache miss/overload/upstream).",
             "network": "Compare with RTT to resolver."},
            ["Investigate resolver performance and caching"], ["Local caching resolvers close to clients"], "application"))
    return res


def _dhcp_chain(ctx):
    res = []
    for f in _by(ctx, "dhcp_no_offer"):
        apipa = _by(ctx, "dhcp_apipa")
        chain = [step(ctx, n, "Application", "DHCP DISCOVER (no OFFER)") for n in f.packets[:3]]
        if apipa:
            chain.append(step(ctx, None, "Network", f"Host falls back to link-local: {', '.join(apipa[0].entities[:3])}",
                              t=(apipa[0].ts or ctx.t0) - ctx.t0))
        res.append(RootCause(
            "dhcp_failure", "DHCP failure leaves hosts without an IP address", "high", 0.85 if apipa else 0.7,
            "Clients cannot obtain an address; everything else (DNS, apps) fails as a consequence.",
            "DISCOVER broadcasts went unanswered, so no server/relay responded on this VLAN. Without a lease the client self-assigns 169.254.x.x "
            "and cannot reach its gateway, DNS or any application.",
            chain, [f.uid] + [a.uid for a in apipa], f.entities,
            {"client": "Host is healthy but unconfigured.", "network": "Relay (ip helper-address) or VLAN issue, DHCP snooping, scope exhaustion.",
             "server": "DHCP server may not receive the DISCOVER or may lack free leases.", "application": "Total loss of connectivity for the host."},
            f.remediation, f.recommendations, "network"))
    return res


def _rogue_dhcp(ctx):
    res = []
    for f in _by(ctx, "dhcp_multiple_servers"):
        offers = f.details.get("offers") or []
        routers = {o["server"]: o.get("router") for o in offers}
        res.append(RootCause(
            "rogue_dhcp", "Rogue DHCP server handing out conflicting configuration", "critical", 0.8,
            "More than one DHCP server answers clients; some clients get a different gateway/DNS — traffic may be intercepted or black-holed.",
            f"{f.summary} Default gateways offered: {routers or 'n/a'}.",
            [step(ctx, o["no"], "Application", f"OFFER from {o['server']}: IP {o['ip']} gw {o.get('router')} dns {o.get('dns')}") for o in offers[:4]],
            [f.uid], list(f.details.get("servers", {}).keys()),
            {"security": "Classic MITM setup: attacker becomes gateway/DNS.", "client": "Clients receive inconsistent leases.",
             "network": "Enable DHCP snooping.", "application": "Intermittent failures depending on which OFFER wins."},
            f.remediation, f.recommendations, "security"))
    return res


def _arp_mitm(ctx):
    res = []
    for f in _by(ctx, "arp_duplicate_ip"):
        ip = f.details.get("ip")
        resets = [x for x in ctx.findings if x.id in ("tcp_reset_abort", "tcp_retransmissions")]
        gw = f.details.get("gateway")
        res.append(RootCause(
            "arp_conflict", f"{'ARP spoofing of gateway' if gw else 'IP address conflict'} for {ip}", "critical", 0.85 if gw else 0.7,
            f"Two MAC addresses ({', '.join(f.details['macs'])}) claim {ip}; hosts' ARP caches flip between them, misdirecting traffic.",
            ("The gateway IP is being claimed by a second MAC — typical of ARP poisoning (MITM). " if gw else
             "Two devices are configured with the same IP (often a static IP inside a DHCP scope). ") +
            ("TCP resets/retransmissions in the capture are consistent with traffic being delivered to the wrong host." if resets else ""),
            [step(ctx, n, "Network", f"ARP: {ip} is-at {m}") for n, m in zip(f.packets[:2], f.details["macs"])] +
            [step(ctx, r.packets[0] if r.packets else None, "Transport", r.title) for r in resets[:2]],
            [f.uid] + [r.uid for r in resets[:2]], [ip] + f.details["macs"],
            {"network": "Locate both MACs in the switch CAM table.", "security": "Enable DAI; investigate the unexpected MAC.",
             "client": "Intermittent connectivity to that IP.", "server": "If the IP is a server, some clients reach the wrong box."},
            f.remediation, f.recommendations, "security" if gw else "network"))
    return res


def _receiver_bottleneck(ctx):
    res = []
    for st in ctx.flows.streams:
        zw = st.count("zero_window")
        if not zw:
            continue
        sides = {d for _, f, d in st.events if f == "zero_window"}
        who = "client" if "c2s" in sides else "server"
        host = st.client if who == "client" else st.server
        stall = sum(g["seconds"] for g in st.gaps if "zero window" in g["cause"])
        res.append(RootCause(
            "receiver_bottleneck", f"Receiver-side bottleneck on {who} {host} (stream {st.id})", "high", 0.9,
            f"The {who} ({host}) cannot consume data fast enough — the slowness is in that host/application, NOT the network or the sender.",
            f"{host} advertised a zero receive window {zw} time(s)"
            + (f", stalling the transfer for ≈{stall:.1f} s" if stall else "") +
            ". TCP flow control paused the sender until the application read from its socket buffer.",
            [step(ctx, n, "Transport", f"{f.replace('_', ' ')} ({'client' if d == 'c2s' else 'server'})")
             for n, f, d in st.events if f in ("window_full", "zero_window", "zero_window_probe", "window_update")][:6],
            [f.uid for f in _by(ctx, "tcp_zero_window")], [host],
            {who: f"{host}'s application/OS is the bottleneck (CPU, disk I/O, blocked reader thread, small buffers).",
             "network": "Exonerated — no loss is required for this pattern.",
             "application": "Profile the receiving application's read loop and its dependencies (disk, DB)."},
            ["Inspect CPU/memory/disk on the receiving host at this time", "Increase socket receive buffers / autotuning"],
            ["Load-test the receiver; monitor socket receive queues"], who))
        if len(res) >= 5:
            break
    return res


def _loss_vs_server(ctx):
    res = []
    slow = _by(ctx, "tcp_slow_response")
    loss = _by(ctx, "tcp_retransmissions")
    if slow:
        streams = {s.id: s for s in ctx.flows.streams}
        worst = slow[0]
        lossy = [s for s in streams.values() if 179 not in (s.sport, s.cport) and s.response_times
                 and (s.count("retransmission") or s.count("fast_retransmission"))
                 and any(t > 1 for _, _, t in s.response_times)]
        if lossy:
            s = lossy[0]
            res.append(RootCause(
                "slow_due_to_loss", f"Slow responses caused by packet loss (stream {s.id})", "high", 0.75,
                "Response delays coincide with retransmissions: the network lost data and TCP waited for timeouts.",
                "Retransmission timeouts (≥200 ms, doubling) add directly to response time. The server may have responded quickly, but the data had to be resent.",
                [step(ctx, n, "Transport", f.replace("_", " ")) for n, f, _ in s.events if "retrans" in f][:5],
                [worst.uid] + [x.uid for x in loss], [s.server],
                {"network": "Loss on the path is the dominant factor.", "server": "Probably not the bottleneck.", "client": "Perceives slowness."},
                loss[0].remediation if loss else [], loss[0].recommendations if loss else [], "network"))
        else:
            res.append(RootCause(
                "server_think_time", "Slow application: server think time (network exonerated)", "high", 0.8,
                "Requests reach the server quickly and are ACKed, but the application takes seconds to respond — the delay is inside the server or its back-ends.",
                worst.summary + " No retransmissions or zero-window events coincide with the delays.",
                [step(ctx, n, "Application", "request" if i % 2 == 0 else "first byte of response") for i, n in enumerate(worst.packets[:6])],
                [worst.uid], worst.entities,
                {"server": "Profile the application for this request (APM, slow query log, GC pauses).",
                 "network": "Exonerated: low RTT, no loss.", "client": "Waits for the server.",
                 "application": "Check back-end dependencies (DB, auth, storage)."},
                worst.remediation, worst.recommendations, "server"))
    return res


def _stp_l2(ctx):
    stp = _by(ctx, "stp_topology_change")
    loss = _by(ctx, "tcp_retransmissions")
    if stp and loss and stp[0].ts is not None:
        t_stp = stp[0].ts
        near = [n for st in ctx.flows.streams for n, f, _ in st.events
                if "retransmission" in f and ctx.pkt(n) and t_stp - 5 <= ctx.pkt(n).ts <= t_stp + 60]
        if not near:
            return []
        return [RootCause(
            "stp_instability", "Spanning-tree topology changes coincide with packet loss", "high", 0.6,
            "Layer-2 reconvergence flushes MAC tables and may block ports briefly, causing floods and drops.",
            stp[0].summary, [step(ctx, stp[0].packets[0], "Network", "BPDU with TC flag"),
                             step(ctx, near[0], "Transport", f"{len(near)} TCP retransmission(s) within 60 s")],
            [stp[0].uid, loss[0].uid], [],
            {"network": "Find the port generating TCs; enable PortFast/BPDU guard on edge ports."},
            stp[0].remediation, stp[0].recommendations, "network")]
    return []


def _attack_chain(ctx):
    scans = _by(ctx, "sec_port_scan") + _by(ctx, "sec_nmap_signature") + _by(ctx, "sec_host_sweep") + _by(ctx, "arp_scan")
    follow = [f for f in ctx.findings if f.id in ("http_suspicious_user_agent", "sec_log4j", "http_cleartext_credentials",
                                                    "sec_executable", "tls_known_bad_ja3", "sec_suspicious_port",
                                                    "http_client_errors", "http_file_download")]
    if not scans:
        return []
    srcs = {e for f in scans for e in f.entities[:1]}
    related = [f for f in follow if any(s in " ".join(f.entities) + f.summary for s in srcs)]
    phases = ["Reconnaissance (scanning)"] + (["Exploitation / weaponization attempts"] if related else [])
    return [RootCause(
        "attack_chain", "Reconnaissance activity" + (" followed by exploitation attempts" if related else ""),
        "critical" if related else "high", 0.8 if related else 0.65,
        f"Host(s) {', '.join(sorted(srcs))} performed scanning" + (" and then attacked discovered services." if related else "."),
        "Kill-chain view: " + " → ".join(phases) + ". " + " ".join(f.summary for f in (scans + related)[:4]),
        [step(ctx, f.packets[0] if f.packets else None, "Security", f.title, t=(f.ts or ctx.t0) - ctx.t0) for f in (scans + related)[:6]],
        [f.uid for f in scans + related], sorted(srcs),
        {"security": "Confirm whether the source is an authorized scanner; if not, contain it and check targets for compromise.",
         "server": "Review exposed services that answered the scan.", "network": "Segment and restrict lateral movement."},
        ["Identify the owner of the scanning host", "Block/contain if unauthorized", "Check targeted servers' logs for successful exploitation"],
        ["Deploy IDS/NDR with scan detection", "Reduce exposed services"], "security")]


def _capture_quality(ctx):
    f = _by(ctx, "tcp_lost_segment")
    if f and "CAPTURE" in f[0].summary:
        return [RootCause(
            "capture_drops", "Capture is missing packets (analysis accuracy reduced)", "medium", 0.7,
            "Receivers acknowledged data the capture never recorded — the capture tool/SPAN dropped packets.",
            "Before blaming the network, fix the measurement: several gaps were ACKed by the receiver, proving the data arrived.",
            [step(ctx, n, "Capture", "ACKed unseen / previous segment not captured") for n in f[0].packets[:4]],
            [f[0].uid], [], {"network": "Not a network fault.", "application": "N/A"},
            f[0].remediation, f[0].recommendations, "capture")]
    return []


def _isis_adjacency(ctx):
    ids = ("isis_circuit_mismatch", "isis_area_mismatch", "isis_auth_mismatch", "isis_mtu_mismatch", "isis_one_way",
           "isis_duplicate_sysid")
    fs = [f for f in ctx.findings if f.id in ids]
    if not fs:
        return []
    return [RootCause(
        "isis_adjacency", "IS-IS adjacency failure", "critical", 0.9,
        "IS-IS neighbors cannot come up because their hello parameters disagree — routes over this link are missing.",
        "IS-IS requires a common level, (for L1) a common area, matching authentication and — because hellos are padded to "
        "the MTU — matching MTUs. Detected: " + "; ".join(f.summary for f in fs[:4]),
        [step(ctx, f.packets[0] if f.packets else None, "Routing", f.title) for f in fs[:5]],
        [f.uid for f in fs], sorted({e for f in fs for e in f.entities})[:10],
        {"routing": "No adjacency → LSDB lacks this link; SPF routes around it or not at all.",
         "network": "An MTU mismatch also drops large data-plane frames.", "application": "Reachability issues."},
        _dedupe(f.remediation[0] for f in fs[:6]), ["Standardize IS-IS interface templates; alert on adjacency changes"], "routing")]


def _fhrp(ctx):
    res = []
    for f in _by(ctx, "fhrp_split_brain"):
        related = [x for x in ctx.findings if x.id in ("fhrp_auth_mismatch", "fhrp_timer_mismatch", "fhrp_vip_mismatch", "arp_duplicate_ip")
                   and set(x.entities) & set(f.entities)]
        res.append(RootCause(
            "fhrp_split_brain", "Two routers act as the default gateway at once (FHRP split brain)", "critical", 0.85,
            "The redundant gateways stopped hearing each other, so both became active; hosts' traffic is split or black-holed.",
            f.summary + " Each router only becomes active when it no longer receives the other's hellos — the layer-2 path "
            "between them, or a parameter mismatch (" + (", ".join(x.title for x in related) or "none detected") + "), is the cause.",
            [step(ctx, n, "Routing", "active/master claim") for n in f.packets[:3]] +
            [step(ctx, x.packets[0] if x.packets else None, "Routing", x.title) for x in related[:3]],
            [f.uid] + [x.uid for x in related], f.entities,
            {"routing": "Both routers advertise the connected subnet as active.", "network": "Check the VLAN between the routers.",
             "client": "Gateway MAC flaps in ARP caches.", "security": "Rule out a rogue router with higher priority."},
            f.remediation + [x.remediation[0] for x in related], f.recommendations, "routing"))
    return res
