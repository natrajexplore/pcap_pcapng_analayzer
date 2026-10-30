"""IPv6 expert: router advertisements (SLAAC / DHCPv6 mode), rogue RAs, neighbor resolution and DAD."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make


def run(ctx) -> None:
    F = ctx.findings
    nd = [p for p in ctx.packets if p.layers.get("icmp", {}).get("v6") and p.layers["icmp"]["type"] in (133, 134, 135, 136)]
    if not nd:
        return
    ras = defaultdict(list)
    rs, ns, na = [], [], []
    for p in nd:
        t = p.layers["icmp"]["type"]
        if t == 134:
            ras[p.src].append(p)
        else:
            {133: rs, 135: ns, 136: na}[t].append(p)
    if ras:
        parts, prefixes_by_router = [], {}
        for src, lst in ras.items():
            d = lst[-1].layers["icmp"]
            pfx = sorted({x["prefix"] for p in lst for x in p.layers["icmp"].get("prefixes", [])})
            prefixes_by_router[src] = pfx
            mode = ("stateful DHCPv6 (M=1)" if d.get("managed") else
                    "SLAAC + stateless DHCPv6 for DNS (O=1)" if d.get("other") else "SLAAC only (M=0, O=0)")
            parts.append(f"{src} advertises {', '.join(pfx) or 'no prefix'} — hosts use {mode}; router lifetime "
                         f"{d.get('router_lifetime')} s" + (" (NOT a default router)" if d.get("router_lifetime") == 0 else ""))
        F.append(make("ipv6_ra_summary", "; ".join(parts) + ".", entities=list(ras), ts=min(l[0].ts for l in ras.values()),
                      packets=[l[0].no for l in ras.values()][:10], details={"routers": prefixes_by_router}))
        if len(ras) > 1 and len({tuple(v) for v in prefixes_by_router.values()}) > 1:
            F.append(make("ipv6_multiple_ra_sources",
                          f"{len(ras)} routers advertise DIFFERENT prefixes on the same link: " +
                          "; ".join(f"{r}: {', '.join(v) or 'none'}" for r, v in prefixes_by_router.items()) + ".",
                          entities=list(ras), packets=[l[0].no for l in ras.values()]))
    if rs and not ras:
        F.append(make("ipv6_rs_no_ra", f"{len(rs)} Router Solicitation(s) from {', '.join(sorted({p.src for p in rs})[:5])} "
                                       "were never answered by a Router Advertisement.", packets=[p.no for p in rs[:10]],
                      ts=rs[0].ts))
    answered = {p.layers["icmp"]["target"] for p in na if "target" in p.layers["icmp"]}
    dad = [p for p in ns if p.src == "::"]
    # a conflict is another node (different MAC) defending the address within the DAD wait (RetransTimer ≈1 s);
    # the host's own later NAs for the address it just claimed are normal
    conflict = [p for p in dad if any(a.layers["icmp"].get("target") == p.layers["icmp"].get("target")
                                      and a.eth_src != p.eth_src and 0 <= a.ts - p.ts <= 1.5 for a in na)]
    if conflict:
        F.append(make("ipv6_dad_conflict", "Duplicate Address Detection failed — another node already owns "
                                           f"{', '.join(sorted({p.layers['icmp']['target'] for p in conflict}))}.",
                      packets=[p.no for p in conflict[:10]], ts=conflict[0].ts))
    unans = [p for p in ns if p.src != "::" and p.layers["icmp"].get("target") not in answered]
    targets = sorted({p.layers["icmp"].get("target") for p in unans} - {None})
    if targets:
        F.append(make("ipv6_ns_unanswered", f"Neighbor Solicitations for {', '.join(targets[:6])} got no Neighbor "
                                            "Advertisement (IPv6 equivalent of an unanswered ARP).",
                      packets=[p.no for p in unans[:10]], ts=unans[0].ts, entities=targets,
                      severity="medium" if len(unans) >= 3 else "low"))
    if ns and na:
        F.append(make("ipv6_nd_summary", f"Neighbor discovery: {len(ns)} solicitation(s) ({len(dad)} duplicate-address "
                                         f"checks), {len(na)} advertisement(s) resolving "
                                         f"{', '.join(sorted(answered)[:5])}.", ts=ns[0].ts))
