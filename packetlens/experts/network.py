"""Layer 2/3 expert: IP (TTL, checksum, fragmentation), ICMP, ARP, STP, broadcast."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from ..knowledge import make

# Link-local control protocols that must be sent with TTL 1 (EIGRP legitimately uses 2, VRRP uses 255).
LINK_LOCAL_MCAST_TTL1 = {"224.0.0.5", "224.0.0.6", "224.0.0.9", "224.0.0.2", "224.0.0.102"}


def initial_ttl(ttl: int) -> int:
    for base in (32, 64, 128, 255):
        if ttl <= base:
            return base
    return 255


def run(ctx) -> None:
    F = ctx.findings
    pk = ctx.packets
    # ------------------------------------------------------------ IP --------
    weird, mcast_bad, low = [], [], []
    bad_cks, frags = [], []
    src_ttls: dict[str, set] = defaultdict(set)
    for p in pk:
        if p.ip_version != 4 or p.ttl is None:
            continue
        if p.ttl > 2:  # ignore link-local control traffic (TTL 1/2) when comparing TTL families
            src_ttls[p.src].add(p.ttl)
        if 30 < p.ttl < 50:
            weird.append(p)
        if p.dst in LINK_LOCAL_MCAST_TTL1 and p.ttl != 1:
            mcast_bad.append(p)
        elif p.ttl < 5 and not p.dst.startswith("224.") and "icmp" not in p.layers \
                and p.protocol not in ("BGP", "OSPF", "EIGRP", "RIP") and 179 not in (p.sport, p.dport):
            low.append(p)
        if p.ip_checksum_ok is False:
            bad_cks.append(p)
        if "ip_fragment" in p.tags:
            frags.append(p)
    if weird or mcast_bad or low:
        parts = []
        if weird:
            parts.append(f"{len(weird)} packets with TTL 31–49 from {', '.join(sorted({p.src for p in weird})[:5])}")
        if mcast_bad:
            parts.append(f"{len(mcast_bad)} link-local routing/FHRP multicasts with TTL ≠ 1 "
                         f"(from {', '.join(sorted({p.src for p in mcast_bad})[:5])}) — should always be 1")
        if low:
            parts.append(f"{len(low)} unicast packets with TTL < 5")
        F.append(make("ip_ttl_anomaly", "; ".join(parts) + ".", severity="medium" if mcast_bad else "low",
                      packets=[p.no for p in (mcast_bad + low + weird)[:20]],
                      ts=(mcast_bad + low + weird)[0].ts))
    ttl_multi = {s: t for s, t in src_ttls.items() if len({initial_ttl(x) for x in t}) > 1}
    if ttl_multi:
        F.append(make("ip_ttl_anomaly",
                      "Same source IP seen with different initial-TTL families (multiple devices answering for one IP, "
                      "e.g. firewall-generated RSTs or spoofing): " +
                      "; ".join(f"{s} TTLs {sorted(t)}" for s, t in list(ttl_multi.items())[:5]),
                      severity="low", entities=list(ttl_multi)[:10],
                      title="Multiple TTL signatures for one IP (middlebox or spoofing)"))
    if bad_cks:
        F.append(make("ip_checksum_errors", f"{len(bad_cks)} IPv4 header checksum errors "
                                            f"(sources: {', '.join(sorted({p.src for p in bad_cks})[:5])}).",
                      packets=[p.no for p in bad_cks[:20]], count=len(bad_cks), ts=bad_cks[0].ts))
    if frags:
        F.append(make("ip_fragmentation", f"{len(frags)} IP fragments observed "
                                          f"({', '.join(sorted({f'{p.src}→{p.dst}' for p in frags})[:5])}).",
                      packets=[p.no for p in frags[:20]], count=len(frags), ts=frags[0].ts))

    # ------------------------------------------------------------ ICMP ------
    icmp = [p for p in pk if "icmp" in p.layers]
    unreach = defaultdict(list)
    admin, fragneed, ttlx, redirect, large, recon = [], [], [], [], [], []
    echo_targets = defaultdict(set)
    for p in icmp:
        d = p.layers["icmp"]
        t, c, v6 = d["type"], d["code"], d["v6"]
        if (not v6 and t == 3 and c in (9, 10, 13)) or (v6 and t == 1 and c == 1):
            admin.append(p)
        elif (not v6 and t == 3 and c == 4) or (v6 and t == 2):
            fragneed.append(p)
        elif (not v6 and t == 3) or (v6 and t == 1):
            unreach[d.get("code_name", f"code {c}")].append(p)
        elif (not v6 and t == 11) or (v6 and t == 3):
            ttlx.append(p)
        elif not v6 and t == 5:
            redirect.append(p)
        elif not v6 and t in (13, 15, 17):
            recon.append(p)
        if t in (8, 128):
            echo_targets[p.src].add(p.dst)
            if d.get("data_len", 0) > 100:
                large.append(p)
    ctx.icmp_events = [_icmp_event(p) for p in icmp if p.layers["icmp"]["type"] not in (0, 8, 128, 129, 133, 134, 135, 136)]
    for name, lst in unreach.items():
        orig = [p.layers["icmp"].get("original") or {} for p in lst]
        flows = sorted({f"{o.get('src')}→{o.get('dst')}:{o.get('dport')}" for o in orig if o})
        F.append(make("icmp_unreachable", f"{len(lst)} × ICMP '{name}' reported by {', '.join(sorted({p.src for p in lst})[:5])} "
                                          f"for flow(s) {', '.join(flows[:5])}.",
                      title=f"ICMP destination unreachable — {name}", packets=[p.no for p in lst[:20]], count=len(lst),
                      entities=sorted({p.src for p in lst}), ts=lst[0].ts,
                      severity="medium" if "Port" in name else "high",
                      details={"reporters": sorted({p.src for p in lst}), "flows": flows[:20]}))
    if admin:
        orig = [p.layers["icmp"].get("original") or {} for p in admin]
        flows = sorted({f"{o.get('src')}→{o.get('dst')}:{o.get('dport')}" for o in orig if o})
        F.append(make("icmp_admin_prohibited",
                      f"{len(admin)} 'administratively prohibited' messages from filtering device(s) "
                      f"{', '.join(sorted({p.src for p in admin}))} blocking {', '.join(flows[:5])}.",
                      packets=[p.no for p in admin[:20]], entities=sorted({p.src for p in admin}), ts=admin[0].ts,
                      count=len(admin), details={"reporters": sorted({p.src for p in admin}), "flows": flows}))
    if fragneed:
        mtus = sorted({p.layers["icmp"].get("next_hop_mtu") or p.layers["icmp"].get("mtu") for p in fragneed} - {None})
        F.append(make("icmp_frag_needed", f"{len(fragneed)} PMTUD messages from {', '.join(sorted({p.src for p in fragneed}))}; "
                                          f"next-hop MTU(s): {', '.join(map(str, mtus)) or 'unspecified'}.",
                      packets=[p.no for p in fragneed[:20]], ts=fragneed[0].ts, count=len(fragneed),
                      details={"mtus": mtus, "reporters": sorted({p.src for p in fragneed})}))
    if ttlx:
        dsts = Counter((p.layers["icmp"].get("original") or {}).get("dst") for p in ttlx)
        reporters = sorted({p.src for p in ttlx})
        loop = [d for d, n in dsts.items() if n >= 3 and d]
        sev = "high" if loop else "low"
        F.append(make("icmp_ttl_exceeded",
                      f"{len(ttlx)} TTL-exceeded messages from {len(reporters)} router(s) ({', '.join(reporters[:6])}). "
                      + (f"Repeated for destination(s) {', '.join(loop[:5])} — possible routing loop." if loop else
                         "Pattern consistent with traceroute."),
                      severity=sev, packets=[p.no for p in ttlx[:20]], ts=ttlx[0].ts, count=len(ttlx),
                      details={"destinations": dict(dsts), "reporters": reporters}))
    if redirect:
        F.append(make("icmp_redirect", f"{len(redirect)} ICMP redirects (gateways: "
                                       f"{', '.join(sorted({p.layers['icmp'].get('gateway', '?') for p in redirect}))}).",
                      packets=[p.no for p in redirect[:20]], ts=redirect[0].ts))
    if large:
        F.append(make("icmp_large_ping", f"{len(large)} ICMP echo packets with payload > 100 bytes "
                                         f"({', '.join(sorted({f'{p.src}→{p.dst}' for p in large})[:5])}).",
                      packets=[p.no for p in large[:20]], ts=large[0].ts))
    if recon:
        F.append(make("icmp_recon", f"{len(recon)} ICMP timestamp/info/mask requests from {', '.join(sorted({p.src for p in recon}))}.",
                      packets=[p.no for p in recon[:20]], ts=recon[0].ts))
    for src, targets in echo_targets.items():
        if len(targets) >= 10:
            F.append(make("sec_host_sweep", f"{src} sent ICMP echo requests to {len(targets)} different hosts.",
                          entities=[src], ts=next(p.ts for p in icmp if p.src == src)))

    # ------------------------------------------------------------ ARP -------
    arps = [p for p in pk if "arp" in p.layers]
    ip_macs: dict[str, set] = defaultdict(set)
    ip_first: dict[str, list] = defaultdict(list)
    requests = defaultdict(list)
    replied = set()
    req_by_sender = defaultdict(set)
    for p in arps:
        d = p.layers["arp"]
        if d["sender_ip"] != "0.0.0.0":
            ip_macs[d["sender_ip"]].add(d["sender_mac"])
            ip_first[d["sender_ip"]].append(p.no)
        if d["op"] == "request" and not d["gratuitous"]:
            requests[(d["sender_ip"], d["target_ip"])].append(p)
            req_by_sender[d["sender_ip"]].add(d["target_ip"])
        elif d["op"] == "reply":
            replied.add((d["target_ip"], d["sender_ip"]))
    ctx.arp_table = {ip: sorted(m) for ip, m in ip_macs.items()}
    for ip, macs in ip_macs.items():
        if len(macs) > 1:
            gw = ip in ctx.gateways
            F.append(make("arp_duplicate_ip",
                          f"IP {ip} claimed by {len(macs)} MAC addresses: {', '.join(sorted(macs))}"
                          + (" — this IP is used as a default gateway: strong ARP-spoofing indicator." if gw else "."),
                          packets=ip_first[ip][:20], entities=[ip] + sorted(macs), severity="critical",
                          ts=next(p.ts for p in arps if p.no == ip_first[ip][0]),
                          details={"ip": ip, "macs": sorted(macs), "gateway": gw}))
    unans = [(k, v) for k, v in requests.items() if k not in replied]
    for sender, targets in req_by_sender.items():
        if len(targets) >= 20:
            F.append(make("arp_scan", f"{sender} ARPed for {len(targets)} different addresses.", entities=[sender]))
    unans = [(k, v) for k, v in unans if len(req_by_sender[k[0]]) < 20]
    if unans:
        F.append(make("arp_unanswered", f"{len(unans)} ARP target(s) never answered: "
                                        + ", ".join(f"{t} (asked by {s}, {len(v)}×)" for (s, t), v in unans[:8]) + ".",
                      packets=[v[0].no for _, v in unans[:20]], ts=unans[0][1][0].ts,
                      severity="medium" if any(len(v) >= 3 for _, v in unans) else "low",
                      details={"targets": [t for (_, t), _ in unans]}))

    # ------------------------------------------------------------ STP -------
    tcs = [p for p in pk if p.layers.get("stp", {}).get("tc")]
    if tcs:
        roots = sorted({p.layers["stp"].get("root") for p in pk if "stp" in p.layers} - {None})
        F.append(make("stp_topology_change",
                      f"{len(tcs)} BPDUs with Topology Change flag/TCN from {', '.join(sorted({p.eth_src for p in tcs})[:5])}."
                      + (f" Multiple root bridges advertised: {', '.join(roots)}." if len(roots) > 1 else ""),
                      packets=[p.no for p in tcs[:20]], ts=tcs[0].ts, count=len(tcs),
                      severity="high" if len(roots) > 1 or len(tcs) > 10 else "medium"))

    # ------------------------------------------------------ broadcast -------
    eth = [p for p in pk if p.eth_dst]
    if len(eth) >= 50:
        bc = [p for p in eth if p.eth_dst == "ff:ff:ff:ff:ff:ff"]
        share = len(bc) / len(eth) * 100
        if share > 20:
            top = Counter(p.eth_src for p in bc).most_common(5)
            F.append(make("broadcast_high", f"{share:.1f}% of frames are broadcast. Top talkers: "
                                            + ", ".join(f"{m} ({n})" for m, n in top) + ".",
                          severity="medium" if share > 40 else "low", ts=bc[0].ts))

    # ---------------------------------------------------------- APIPA -------
    apipa = sorted({p.src for p in pk if p.src and p.ip_version == 4 and ipaddress.IPv4Address(p.src).is_link_local})
    if apipa:
        F.append(make("dhcp_apipa", f"Hosts using link-local addresses: {', '.join(apipa[:10])}.",
                      entities=apipa, ts=next(p.ts for p in pk if p.src in apipa)))


def _icmp_event(p) -> dict:
    d = p.layers["icmp"]
    o = d.get("original") or {}
    return {"no": p.no, "t": round(p.rel_ts, 6), "reporter": p.src, "to": p.dst,
            "type": d["type_name"], "code": d.get("code_name", d["code"]),
            "orig": f"{o.get('src')}:{o.get('sport')} → {o.get('dst')}:{o.get('dport')} proto {o.get('proto')}" if o else ""}
