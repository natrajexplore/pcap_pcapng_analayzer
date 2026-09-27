"""Tunnel expert: GRE and VXLAN endpoints, carried traffic, MTU overhead and MSS sizing."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from ..knowledge import make

ETH_MTU = 1500


def run(ctx) -> None:
    F = ctx.findings
    for kind in ("gre", "vxlan"):
        pk = [p for p in ctx.packets if kind in p.layers]
        if not pk:
            continue
        ends = defaultdict(lambda: {"pkts": 0, "inner": Counter(), "vni": set(), "max_outer": 0, "first_no": None, "ts": None})
        for p in pk:
            d = p.layers[kind]
            e = ends[tuple(sorted((d["outer_src"], d["outer_dst"])))]
            e["pkts"] += 1
            e["inner"][p.protocol if p.protocol not in ("GRE", "VXLAN") else "other"] += 1
            if "vni" in d:
                e["vni"].add(d["vni"])
            e["max_outer"] = max(e["max_outer"], d.get("outer_len") or 0)
            if e["first_no"] is None:
                e["first_no"], e["ts"] = p.no, p.ts
        overhead = pk[0].layers[kind]["overhead"]
        name = "GRE" if kind == "gre" else "VXLAN"
        mcast_bum = sorted({p.layers[kind]["outer_dst"] for p in pk
                            if ipaddress.ip_address(p.layers[kind]["outer_dst"]).is_multicast})
        F.append(make(f"{kind}_tunnel", f"{name} tunnel(s): " + "; ".join(
            f"{a} ↔ {b}" + (f" VNI {', '.join(map(str, sorted(e['vni'])))}" if e["vni"] else "")
            + f" carrying {', '.join(f'{k} {v}' for k, v in e['inner'].most_common(4))}"
            for (a, b), e in list(ends.items())[:6])
            + f". Each packet grows by {overhead} bytes of encapsulation, so the inner MTU is {ETH_MTU - overhead}."
            + (f" Broadcast/unknown/multicast frames are flooded to underlay group(s) {', '.join(mcast_bum)} "
               "(flood-and-learn)." if mcast_bum else ""),
            entities=sorted({x for k in ends for x in k}), ts=pk[0].ts, packets=[e["first_no"] for e in ends.values()][:10],
            details={"endpoints": [list(k) for k in ends], "overhead": overhead, "bum_groups": mcast_bum}))
        big = [p for p in pk if (p.layers[kind].get("outer_len") or 0) > ETH_MTU]
        if big:
            F.append(make("tunnel_oversize", f"{len(big)} {name} packet(s) exceed {ETH_MTU} bytes after encapsulation "
                                             f"(largest {max(p.layers[kind]['outer_len'] for p in big)} B): they must be "
                                             "fragmented, or are dropped where DF is set.",
                          packets=[p.no for p in big[:10]], ts=big[0].ts, count=len(big)))
        limit = ETH_MTU - overhead - 40
        syns = [p for p in pk if p.tcp is not None and p.tcp.syn and p.tcp.options.get("mss", 0) > limit]
        if syns:
            F.append(make("tunnel_mss_too_large",
                          f"{len(syns)} TCP SYN(s) inside the {name} tunnel advertise MSS "
                          f"{', '.join(map(str, sorted({p.tcp.options['mss'] for p in syns})))} but the tunnel only fits "
                          f"{limit} bytes of TCP payload ({ETH_MTU} − {overhead} tunnel − 40 IP/TCP).",
                          packets=[p.no for p in syns[:10]], ts=syns[0].ts,
                          entities=sorted({f"{p.src}→{p.dst}:{p.dport}" for p in syns})[:10],
                          details={"recommended_mss": limit}))
    # MSS clamping visible in the same capture: one flow's SYN seen with two MSS values
    mss = defaultdict(set)
    for p in ctx.packets:
        if p.tcp is not None and p.tcp.syn and "mss" in p.tcp.options:
            mss[(p.src, p.sport, p.dst, p.dport, p.tcp.seq)].add(p.tcp.options["mss"])
    clamped = {k: sorted(v) for k, v in mss.items() if len(v) > 1}
    if clamped:
        F.append(make("tcp_mss_clamped", "MSS rewritten in flight (MSS clamping): " + "; ".join(
            f"{a}:{b} → {c}:{d} MSS {' → '.join(map(str, sorted(v, reverse=True)))}" for (a, b, c, d, _), v in list(clamped.items())[:5]) + ".",
            details={"flows": len(clamped)}))
