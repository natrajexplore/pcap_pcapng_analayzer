"""Multicast expert: PIM neighbors / DR election, RP discovery, Register handling, IGMP membership and querier."""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from ..knowledge import make


def _ipkey(ip: str):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def run(ctx) -> None:
    _pim(ctx)
    _igmp(ctx)


def _pim(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "pim" in p.layers]
    if not pk:
        return
    hellos = defaultdict(dict)                # segment -> router -> hello params
    regs, stops = defaultdict(list), defaultdict(list)
    rps, bsrs, joins = set(), set(), []
    for p in pk:
        d = p.layers["pim"]
        t = d["type_num"]
        if t == 0:
            seg = p.vlan if p.vlan is not None else _subnet(p.src)
            hellos[seg][p.src] = {"dr_priority": d.get("dr_priority", 1), "holdtime": d.get("holdtime"),
                                  "no": p.no, "ts": p.ts}
        elif t == 1 and not d.get("null_register") and "group" in d:
            regs[(d.get("source"), d["group"])].append(p)
        elif t == 2 and "group" in d:
            stops[(d.get("source"), d["group"])].append(p)
        elif t == 3:
            joins.append(p)
        elif t == 4:
            bsrs.add(d.get("bsr"))
            rps.update((r["rp"], r["group"]) for r in d.get("rps", []))
        elif t == 8:
            rps.update((d.get("rp"), g) for g in d.get("groups", []))
    for seg, routers in hellos.items():
        dr = max(routers, key=lambda r: (routers[r]["dr_priority"], _ipkey(r)))
        F.append(make("pim_neighbors",
                      f"PIM neighbors on {seg if isinstance(seg, str) else f'VLAN {seg}'}: {', '.join(sorted(routers))}; "
                      f"elected DR {dr} (priority {routers[dr]['dr_priority']}, highest priority then highest IP). "
                      "The DR registers local sources with the RP and sends joins for local receivers.",
                      entities=sorted(routers), packets=[r["no"] for r in routers.values()][:10],
                      ts=min(r["ts"] for r in routers.values()), details={"dr": dr, "routers": routers}))
        holds = {r: v["holdtime"] for r, v in routers.items() if v["holdtime"] is not None}
        if len(set(holds.values())) > 1:
            F.append(make("pim_timer_mismatch", f"PIM hello holdtimes differ on {seg}: " +
                          ", ".join(f"{r}={h}s" for r, h in holds.items()) + ".", entities=list(holds)))
    if rps or bsrs:
        F.append(make("pim_rp_info", (f"Bootstrap router(s): {', '.join(sorted(b for b in bsrs if b))}. " if bsrs else "")
                      + ("RP mapping: " + "; ".join(f"{g} → RP {rp}" for rp, g in sorted(rps)[:8]) if rps else
                         "No RP set advertised yet (bootstrap messages without candidate RPs)."),
                      entities=sorted({rp for rp, _ in rps} | {b for b in bsrs if b}),
                      details={"bsr": sorted(b for b in bsrs if b), "rps": sorted(rps)}))
    for sg, lst in regs.items():
        if sg in stops:
            first_stop = stops[sg][0]
            F.append(make("pim_register_flow",
                          f"Source {sg[0]} → group {sg[1]}: the DR encapsulated {len(lst)} data packet(s) in PIM Register "
                          f"to the RP; the RP answered Register-Stop after "
                          f"{(first_stop.ts - lst[0].ts) * 1000:.0f} ms (native (S,G) traffic now flows).",
                          packets=[lst[0].no, first_stop.no], ts=lst[0].ts, entities=[sg[0], sg[1]]))
        elif len(lst) >= 3:
            F.append(make("pim_register_no_stop",
                          f"{len(lst)} PIM Registers for ({sg[0]}, {sg[1]}) from {lst[0].src} to {lst[0].dst} with no "
                          "Register-Stop: the RP keeps receiving encapsulated data.",
                          packets=[p.no for p in lst[:10]], ts=lst[0].ts, entities=[lst[0].src, lst[0].dst, sg[1]]))
    prunes = [(p, g) for p in joins for g in p.layers["pim"].get("groups", []) if g["prunes"]]
    if joins:
        F.append(make("pim_join_prune", f"{len(joins)} Join/Prune message(s); "
                                        f"{sum(len(g['joins']) for p in joins for g in p.layers['pim'].get('groups', []))} "
                                        f"join(s), {sum(len(g['prunes']) for _, g in prunes)} prune(s) "
                                        f"(groups {', '.join(sorted({g['group'] for p in joins for g in p.layers['pim'].get('groups', [])})[:5])}).",
                      packets=[p.no for p in joins[:10]], ts=joins[0].ts))


def _subnet(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


def _igmp(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "igmp" in p.layers]
    if not pk:
        return
    queriers = defaultdict(list)
    members = defaultdict(set)
    versions = set()
    for p in pk:
        d = p.layers["igmp"]
        if d.get("version"):
            versions.add(d["version"])
        if d["type_num"] == 0x11:
            queriers[p.src].append(p)
        elif d["type_num"] in (0x12, 0x16):
            members[d["group"]].add(p.src)
        elif d["type_num"] == 0x22:
            for r in d.get("records", []):
                if r["type"] == "TO_INCLUDE" and not r["sources"]:   # v3 equivalent of a Leave
                    members[r["group"]].discard(p.src)
                else:
                    members[r["group"]].add(p.src)
        elif d["type_num"] == 0x17:
            members[d["group"]].discard(p.src)
    q = sorted(queriers, key=_ipkey)
    members = {g: h for g, h in members.items() if h}       # groups every host has left are gone
    F.append(make("igmp_summary", f"IGMP v{'/'.join(map(str, sorted(versions)))}: querier "
                                  f"{q[0] if q else 'NONE'}" + (f" (candidates {', '.join(q)}; lowest IP wins)" if len(q) > 1 else "")
                  + ("; " + f"{len(members)} group(s) joined: " + "; ".join(f"{g} by {', '.join(sorted(h)[:3])}"
                                                                      for g, h in sorted(members.items())[:6])
                     if members else "; no group memberships reported") + ".",
                  ts=pk[0].ts, details={"queriers": q, "groups": {g: sorted(h) for g, h in members.items()}}))
    if not queriers and members:
        F.append(make("igmp_no_querier", f"Hosts report membership in {', '.join(sorted(members)[:5])} but no IGMP "
                                         "querier was seen on the segment.", ts=pk[0].ts, entities=sorted(members)))
    elif len(q) > 1:
        late = [s for s in q[1:] if queriers[s][-1].ts > queriers[q[0]][0].ts + 1]
        if late:
            F.append(make("igmp_multiple_queriers", f"{', '.join(late)} keep sending queries although {q[0]} has the "
                                                    "lower address and should be the only querier.",
                          entities=q, packets=[queriers[s][-1].no for s in late]))
    if len(versions) > 1:
        F.append(make("igmp_version_mix", f"IGMP versions {', '.join(map(str, sorted(versions)))} on the same segment.",
                      ts=pk[0].ts))
