"""Routing control-plane expert: BGP, OSPF, EIGRP and RIP."""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from ..knowledge import make


def run(ctx) -> None:
    _bgp(ctx)
    _ospf(ctx)
    _eigrp(ctx)
    _rip(ctx)
    _fhrp(ctx)
    _isis(ctx)


# ---------------------------------------------------------------- BGP -------
def _bgp(ctx) -> None:
    F = ctx.findings
    sessions: dict[tuple, dict] = {}
    for p in ctx.packets:
        if not p.tcp or 179 not in (p.sport, p.dport):
            continue
        key = tuple(sorted((p.src, p.dst)))
        s = sessions.setdefault(key, {"peers": list(key), "opens": [], "notifications": [], "keepalives": 0,
                                      "updates": 0, "announced": 0, "withdrawn": [], "first": p.ts, "last": p.ts,
                                      "state": "Connect", "hold": {}, "as": {}, "streams": set(), "events": []})
        s["last"] = p.ts
        s["streams"].add(p.tcp.stream)
        for m in p.layers.get("bgp", {}).get("messages", []):
            ev = {"no": p.no, "t": round(p.rel_ts, 6), "from": p.src, "type": m["type"]}
            if m["type"] == "OPEN":
                s["opens"].append({"no": p.no, "from": p.src, "as": m.get("my_as"), "hold": m.get("hold_time"),
                                   "id": m.get("bgp_id"), "ts": p.ts})
                s["hold"][p.src] = m.get("hold_time")
                s["as"][p.src] = m.get("my_as")
                s["state"] = "OpenSent"
                ev["detail"] = f"AS{m.get('my_as')} hold {m.get('hold_time')}s id {m.get('bgp_id')}"
            elif m["type"] == "KEEPALIVE":
                s["keepalives"] += 1
                if s["state"] in ("OpenSent", "OpenConfirm"):
                    s["state"] = "Established"
            elif m["type"] == "UPDATE":
                s["updates"] += 1
                s["announced"] += len(m.get("nlri", []))
                s["withdrawn"] += [(p.no, x) for x in m.get("withdrawn", [])]
                ev["detail"] = f"+{len(m.get('nlri', []))} -{len(m.get('withdrawn', []))} path {' '.join(map(str, m.get('as_path', [])))}"
            elif m["type"] == "NOTIFICATION":
                s["notifications"].append({"no": p.no, "from": p.src, "ts": p.ts, "error": m.get("error"),
                                           "sub": m.get("suberror"), "code": m.get("error_code")})
                s["state"] = "Idle"
                ev["detail"] = f"{m.get('error')} {m.get('suberror') or ''}".strip()
            if len(s["events"]) < 300:
                s["events"].append(ev)
    streams = {st.id: st for st in ctx.flows.streams}
    out = []
    for key, s in sessions.items():
        sts = [streams[i] for i in s["streams"] if i in streams]
        retrans = sum(st.count("retransmission") for st in sts)
        zero = sum(st.count("zero_window") for st in sts)
        out.append({**{k: v for k, v in s.items() if k != "streams"}, "streams": sorted(s["streams"]),
                    "tcp_retrans": retrans, "tcp_zero_window": zero, "withdrawn_count": len(s["withdrawn"])})
        for n in s["notifications"]:
            code = n["code"]
            extra = []
            persp = {}
            sev = "critical"
            if code == 4:
                extra.append(f"TCP evidence: {retrans} retransmissions and {zero} zero-window events on this BGP session "
                             "before the hold timer expired" if retrans or zero else
                             "No TCP retransmissions seen on the session — keepalives were likely not generated (peer CPU/control-plane) or dropped by CoPP")
                persp["routing"] = (f"Hold time negotiated = min({', '.join(f'{k}:{v}s' for k, v in s['hold'].items())}); "
                                    "no KEEPALIVE/UPDATE arrived within it.")
            elif code == 2:
                if n["sub"] == "Bad Peer AS":
                    extra.append(f"Configured 'remote-as' does not match the AS in the peer's OPEN ({s['as']})")
                elif n["sub"] == "Unacceptable Hold Time":
                    extra.append(f"Hold times offered: {s['hold']}")
            elif code == 6 and n["sub"] in ("Administrative Shutdown", "Administrative Reset", "Peer De-configured"):
                sev = "high"
                extra.append("An operator action on the sending router tore down the session")
            elif code == 6 and n["sub"] == "Maximum Number of Prefixes Reached":
                extra.append(f"Peer announced {s['announced']} prefixes in this capture — exceeds the configured maximum-prefix")
            F.append(make("bgp_notification",
                          f"BGP session {key[0]} ↔ {key[1]}: NOTIFICATION from {n['from']} — {n['error']}"
                          + (f" / {n['sub']}" if n['sub'] else "") + (". " + ". ".join(extra) if extra else "."),
                          title=f"BGP NOTIFICATION: {n['error']}" + (f" / {n['sub']}" if n['sub'] else ""),
                          severity=sev, packets=[n["no"]], entities=list(key), ts=n["ts"],
                          details={"peers": list(key), "code": code, "subcode": n["sub"], "tcp_retrans": retrans,
                                   "hold": s["hold"], "as": s["as"]},
                          extra_causes=extra, extra_perspectives=persp))
        if len(s["opens"]) > 2:
            F.append(make("bgp_session_flap", f"BGP peers {key[0]} ↔ {key[1]} exchanged {len(s['opens'])} OPEN messages "
                                              f"(session re-established {len(s['opens']) // 2} time(s)).",
                          packets=[o["no"] for o in s["opens"]], entities=list(key), ts=s["opens"][0]["ts"]))
        if len(s["withdrawn"]) >= 1:
            F.append(make("bgp_withdrawals", f"{len(s['withdrawn'])} prefixes withdrawn on {key[0]} ↔ {key[1]}: "
                                             + ", ".join(x for _, x in s["withdrawn"][:8]),
                          severity="high" if len(s["withdrawn"]) > 50 else "medium",
                          packets=sorted({n for n, _ in s["withdrawn"]})[:20], entities=list(key),
                          ts=next(p.ts for p in ctx.packets if p.no == s["withdrawn"][0][0])))
        if not s["opens"] and sts and not (set(key) & ctx.scanners):
            refused = [st for st in sts if st.rst and st.rst["kind"] == "refused"]
            unans = [st for st in sts if st.syn_count and not st.synack_count]
            if refused or unans:
                F.append(make("bgp_connect_fail",
                              f"TCP/179 between {key[0]} and {key[1]} never established: "
                              f"{len(refused)} refused (RST), {len(unans)} unanswered SYN sequence(s).",
                              packets=[st.first_no for st in sts][:20], entities=list(key), ts=sts[0].first_ts))
    ctx.routing["bgp"] = out


# --------------------------------------------------------------- OSPF -------
def _ospf(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "ospf" in p.layers]
    if not pk:
        return
    routers: dict[str, dict] = {}
    rid_src = defaultdict(set)
    links = defaultdict(dict)       # link key -> router id -> hello params
    dbd = defaultdict(list)         # (src, dst) -> dbd packets
    lsu = Counter()
    events = []
    for p in pk:
        d = p.layers["ospf"]
        rid = d["router_id"]
        rid_src[rid].add(p.src)
        r = routers.setdefault(rid, {"router_id": rid, "interfaces": set(), "area": set(), "hello": None,
                                     "dead": None, "mtu": set(), "auth": set(), "neighbors_seen": set(), "packets": 0})
        r["interfaces"].add(p.src)
        r["area"].add(d["area"])
        r["auth"].add(d.get("auth_type", "None"))
        r["packets"] += 1
        link = _link_key(p, d)
        if d["type_num"] == 1 and "hello_interval" in d:
            r["hello"], r["dead"] = d["hello_interval"], d["dead_interval"]
            r["neighbors_seen"].update(d.get("neighbors", []))
            links[link][rid] = {"hello": d["hello_interval"], "dead": d["dead_interval"], "area": d["area"],
                                "mask": d.get("mask"), "auth": d.get("auth_type"), "no": p.no, "ts": p.ts,
                                "neighbors": set(d.get("neighbors", [])), "src": p.src, "ttl": p.ttl}
        elif d["type_num"] == 2 and "mtu" in d:
            r["mtu"].add(d["mtu"])
            dbd[(rid, link)].append(p)
        elif d["type_num"] == 4:
            lsu[rid] += 1
        if len(events) < 400:
            events.append({"no": p.no, "t": round(p.rel_ts, 6), "src": p.src, "rid": rid, "type": d["type"],
                           "area": d["area"], "detail": p.info})
    for link, rs in links.items():
        if len(rs) < 2:
            continue
        items = list(rs.items())
        base_rid, base = items[0]
        for rid, h in items[1:]:
            pair = f"{base_rid} ({base['src']}) vs {rid} ({h['src']})"
            nos = [base["no"], h["no"]]
            ents = [base_rid, rid]
            if (h["hello"], h["dead"]) != (base["hello"], base["dead"]):
                F.append(make("ospf_hello_mismatch",
                              f"{pair}: hello/dead {base['hello']}/{base['dead']}s vs {h['hello']}/{h['dead']}s — adjacency cannot form.",
                              packets=nos, entities=ents, ts=h["ts"],
                              details={"a": {"rid": base_rid, "hello": base["hello"], "dead": base["dead"]},
                                       "b": {"rid": rid, "hello": h["hello"], "dead": h["dead"]}}))
            if h["area"] != base["area"]:
                F.append(make("ospf_area_mismatch", f"{pair}: area {base['area']} vs {h['area']}.", packets=nos, entities=ents, ts=h["ts"]))
            if h["mask"] and base["mask"] and h["mask"] != base["mask"]:
                F.append(make("ospf_mask_mismatch", f"{pair}: mask {base['mask']} vs {h['mask']}.", packets=nos, entities=ents, ts=h["ts"]))
            if h["auth"] != base["auth"]:
                F.append(make("ospf_auth_mismatch", f"{pair}: authentication '{base['auth']}' vs '{h['auth']}'.",
                              packets=nos, entities=ents, ts=h["ts"]))
        # one-way: router R never lists a neighbour it can hear
        for rid, h in rs.items():
            others = set(rs) - {rid}
            missing = others - h["neighbors"]
            if missing and all((rs[o]["hello"], rs[o]["dead"], rs[o]["area"]) == (h["hello"], h["dead"], h["area"]) for o in missing):
                F.append(make("ospf_one_way", f"Router {rid} ({h['src']}) hears {', '.join(sorted(missing))} but never lists them "
                                              f"as neighbors in its Hello — adjacency stuck in INIT (one-way).",
                              packets=[h["no"]], entities=[rid] + sorted(missing), ts=h["ts"]))
    # MTU mismatch & EXSTART
    rids_mtu = {rid: r["mtu"] for rid, r in routers.items() if r["mtu"]}
    mtus = {m for s in rids_mtu.values() for m in s}
    if len(mtus) > 1:
        F.append(make("ospf_mtu_mismatch", "Routers advertise different interface MTUs in DB Description packets: " +
                      ", ".join(f"{rid}={sorted(m)}" for rid, m in rids_mtu.items()) +
                      ". The router with the smaller MTU rejects the larger DBDs; neighbors stay in EXSTART/EXCHANGE.",
                      packets=[p.no for lst in dbd.values() for p in lst[:3]][:20], entities=list(rids_mtu),
                      ts=min(p.ts for lst in dbd.values() for p in lst), details={"mtus": {k: sorted(v) for k, v in rids_mtu.items()}}))
    for (rid, link), lst in dbd.items():
        seqs = Counter(p.layers["ospf"].get("dd_seq") for p in lst)
        rep = max(seqs.values()) if seqs else 0
        if rep >= 4:
            F.append(make("ospf_exstart_stuck", f"Router {rid} retransmitted the same DBD sequence {rep} times "
                                                f"— neighbor stuck in EXSTART/EXCHANGE.",
                          packets=[p.no for p in lst[:10]], entities=[rid], ts=lst[0].ts))
    for rid, srcs in rid_src.items():
        if len(srcs) > 1 and len({_subnet_guess(s) for s in srcs}) < len(srcs):
            F.append(make("ospf_duplicate_rid", f"Router ID {rid} used by multiple interfaces on the same segment: {', '.join(sorted(srcs))}.",
                          entities=[rid] + sorted(srcs)))
    dur = max(pk[-1].ts - pk[0].ts, 1)
    for rid, n in lsu.items():
        if n >= 20 and n / dur > 0.2:
            F.append(make("ospf_lsu_storm", f"Router {rid} sent {n} LS Updates in {dur:.0f} s ({n / dur:.2f}/s).",
                          entities=[rid]))
    ctx.routing["ospf"] = {"routers": [{**r, "interfaces": sorted(r["interfaces"]), "area": sorted(r["area"]),
                                        "mtu": sorted(r["mtu"]), "auth": sorted(r["auth"]),
                                        "neighbors_seen": sorted(r["neighbors_seen"])} for r in routers.values()],
                           "events": events}


def _link_key(p, d) -> str:
    if d["version"] == 2 and d.get("mask") and p.ip_version == 4:
        try:
            return str(ipaddress.IPv4Network(f"{p.src}/{d['mask']}", strict=False))
        except ValueError:
            pass
    return _subnet_guess(p.src) if p.ip_version == 4 else "fe80::/64"


def _subnet_guess(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{ip}/24", strict=False))
    except ValueError:
        return ip


# -------------------------------------------------------------- EIGRP -------
def _eigrp(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "eigrp" in p.layers]
    if not pk:
        return
    nbrs: dict[str, dict] = {}
    seq_seen = Counter()
    seq_pkts = defaultdict(list)
    queries, sia, goodbyes, unreach = [], [], [], []
    events = []
    for p in pk:
        d = p.layers["eigrp"]
        n = nbrs.setdefault(p.src, {"address": p.src, "as": set(), "k": None, "hold": None, "auth": False,
                                    "hellos": 0, "updates": 0, "queries": 0, "replies": 0, "sw": None,
                                    "first_no": p.no, "first_ts": p.ts})
        n["as"].add(d["as"])
        n["auth"] = n["auth"] or d["auth"]
        if d.get("k_values") and not d.get("goodbye"):
            n["k"], n["hold"] = d["k_values"], d["hold_time"]
        if d.get("sw_version"):
            n["sw"] = d["sw_version"]
        op = d["opcode_num"]
        if op == 5:
            n["hellos"] += 1
        elif op == 1:
            n["updates"] += 1
        elif op == 3:
            n["queries"] += 1
            queries.append(p)
        elif op == 4:
            n["replies"] += 1
        elif op in (10, 11):
            sia.append(p)
        if d.get("goodbye"):
            goodbyes.append(p)
        if op in (1, 3, 4, 10, 11) and d["seq"]:
            seq_seen[(p.src, p.dst, d["seq"])] += 1
            seq_pkts[(p.src, p.dst, d["seq"])].append(p)
        for r in d["routes"]:
            if r["unreachable"]:
                unreach.append((p, r["prefix"]))
        if len(events) < 400:
            events.append({"no": p.no, "t": round(p.rel_ts, 6), "src": p.src, "dst": p.dst, "type": d["opcode"],
                           "as": d["as"], "detail": p.info})
    items = list(nbrs.values())
    for i, a in enumerate(items):
        for b in items[i + 1:]:
            if _subnet_guess(a["address"]) != _subnet_guess(b["address"]):
                continue
            pair = f"{a['address']} vs {b['address']}"
            ev = {"packets": [a["first_no"], b["first_no"]], "ts": max(a["first_ts"], b["first_ts"])}
            if a["k"] and b["k"] and a["k"] != b["k"]:
                F.append(make("eigrp_k_mismatch", f"{pair}: K-values {a['k']} vs {b['k']}.", entities=[a["address"], b["address"]],
                              details={"a": a["k"], "b": b["k"]}, **ev))
            if a["as"] and b["as"] and not (a["as"] & b["as"]):
                F.append(make("eigrp_as_mismatch", f"{pair}: AS {sorted(a['as'])} vs {sorted(b['as'])}.", entities=[a["address"], b["address"]], **ev))
            if a["auth"] != b["auth"]:
                F.append(make("eigrp_auth_mismatch", f"{pair}: authentication {'on' if a['auth'] else 'off'} vs "
                                                     f"{'on' if b['auth'] else 'off'}.", entities=[a["address"], b["address"]], **ev))
    if goodbyes:
        F.append(make("eigrp_goodbye", f"Goodbye message(s) from {', '.join(sorted({p.src for p in goodbyes}))}.",
                      packets=[p.no for p in goodbyes], ts=goodbyes[0].ts, entities=sorted({p.src for p in goodbyes})))
    if sia:
        F.append(make("eigrp_sia", f"{len(sia)} SIA-Query/SIA-Reply packets between "
                                   f"{', '.join(sorted({f'{p.src}→{p.dst}' for p in sia})[:5])}: routes stuck in active.",
                      packets=[p.no for p in sia[:20]], ts=sia[0].ts))
    if len(queries) >= 3:
        F.append(make("eigrp_query_storm", f"{len(queries)} EIGRP Query packets (routes went active; no feasible successor).",
                      packets=[p.no for p in queries[:20]], ts=queries[0].ts, severity="high" if len(queries) > 30 else "medium"))
    retx = {k: v for k, v in seq_seen.items() if v > 1}
    if retx:
        F.append(make("eigrp_retrans", f"{sum(v - 1 for v in retx.values())} retransmitted reliable EIGRP packets: " +
                      ", ".join(f"{s}→{d} seq {q} ×{n}" for (s, d, q), n in list(retx.items())[:5]),
                      entities=sorted({k[0] for k in retx}), severity="high" if max(retx.values()) >= 5 else "medium",
                      packets=[p.no for k in retx for p in seq_pkts[k]][:20], ts=min(seq_pkts[k][1].ts for k in retx)))
    if unreach:
        F.append(make("eigrp_unreachable_routes", f"{len(unreach)} route(s) advertised with infinite delay: " +
                      ", ".join(sorted({x for _, x in unreach})[:10]), packets=[p.no for p, _ in unreach[:20]], ts=unreach[0][0].ts))
    ctx.routing["eigrp"] = {"neighbors": [{k: v for k, v in n.items() if k not in ("first_no", "first_ts")} | {"as": sorted(n["as"])}
                                          for n in nbrs.values()], "events": events}


# ---------------------------------------------------------------- RIP -------
def _rip(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "rip" in p.layers]
    if not pk:
        return
    routers: dict[str, dict] = {}
    poisoned = []
    for p in pk:
        d = p.layers["rip"]
        r = routers.setdefault(p.src, {"address": p.src, "versions": set(), "responses": [], "routes": {}, "auth": False})
        r["versions"].add(d["version"])
        if d["auth_type"]:
            r["auth"] = True
        if d["command"] == "Response":
            r["responses"].append(p.ts)
            for e in d["entries"]:
                r["routes"][f"{e['ip']}/{e['mask']}"] = e["metric"]
                if e["metric"] >= 16:
                    poisoned.append((p, e["ip"]))
    versions = {v for r in routers.values() for v in r["versions"]}
    if len(versions) > 1:
        F.append(make("rip_version_mismatch", "RIP versions on this segment: " +
                      ", ".join(f"{a}=v{'/'.join(map(str, sorted(r['versions'])))}" for a, r in routers.items()) + ".",
                      entities=list(routers), ts=pk[0].ts, packets=[p.no for p in pk[:4]]))
    v1 = [a for a, r in routers.items() if 1 in r["versions"]]
    if v1:
        F.append(make("rip_v1_in_use", f"RIPv1 speakers: {', '.join(v1)}.", entities=v1, ts=pk[0].ts))
    noauth = [a for a, r in routers.items() if 2 in r["versions"] and not r["auth"]]
    if noauth:
        F.append(make("rip_no_auth", f"RIPv2 without authentication from {', '.join(noauth)}.", entities=noauth))
    if poisoned:
        F.append(make("rip_unreachable_routes", f"{len(poisoned)} route(s) advertised with metric 16: " +
                      ", ".join(sorted({f'{x} (by {p.src})' for p, x in poisoned})[:8]),
                      packets=[p.no for p, _ in poisoned[:20]], ts=poisoned[0][0].ts))
    for a, r in routers.items():
        ts = r["responses"]
        gaps = [b - a_ for a_, b in zip(ts, ts[1:])]
        big = [g for g in gaps if g > 45]
        if big:
            F.append(make("rip_update_gap", f"Router {a}: {len(big)} interval(s) > 45 s between updates (max {max(big):.0f} s; expected ~30 s).",
                          entities=[a]))
    ctx.routing["rip"] = {"routers": [{**r, "versions": sorted(r["versions"]), "responses": len(r["responses"])} for r in routers.values()]}


# ------------------------------------------------------------ HSRP / VRRP ---
def _fhrp(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "fhrp" in p.layers]
    if not pk:
        return
    groups: dict = {}
    for p in pk:
        d = p.layers["fhrp"]
        g = groups.setdefault((d["proto"], d["group"], p.vlan), {"speakers": {}, "active": [], "coups": []})
        sp = g["speakers"].setdefault(p.src, {"address": p.src, "states": set(), "priority": set(), "timers": set(),
                                              "vips": set(), "auth": set(), "auth_default": False, "ttl": set(),
                                              "first_no": p.no, "packets": 0})
        sp["states"].add(d["state"])
        sp["priority"].add(d["priority"])
        sp["timers"].add((d["hello"], d["hold"]))
        if d["vip"] and d["vip"] != "0.0.0.0":
            sp["vips"].add(d["vip"])
        sp["auth"].add(d["auth"])
        sp["auth_default"] |= d["auth_default"]
        sp["ttl"].add(p.ttl)
        sp["packets"] += 1
        if d["state"] in ("Active", "Master") and d["priority"]:
            g["active"].append((p.ts, p.src, p.no, d["hold"]))
        if d["op"] in ("Coup", "Resign") or d["priority"] == 0 and d["proto"] == "VRRP":
            g["coups"].append((p.ts, p.src, p.no, d["op"] if d["proto"] == "HSRP" else "priority 0 (resign)"))
    out = []
    for (proto, gid, vlan), g in groups.items():
        name = f"{proto} group {gid}" + (f" (VLAN {vlan})" if vlan is not None else "")
        sps = list(g["speakers"].values())
        ents = [s["address"] for s in sps]
        # split brain: two different speakers both active within one hold time
        act = sorted(g["active"])
        split = [(a, b) for a, b in zip(act, act[1:]) if a[1] != b[1] and b[0] - a[0] < max(a[3], 1)
                 and any(c[1] == a[1] and c[0] > b[0] for c in act)]
        if split:
            a, b = split[0]
            F.append(make("fhrp_split_brain", f"{name}: {a[1]} and {b[1]} both claim to be active/master at the same time "
                                              f"({len(split)} overlapping claims).",
                          packets=[a[2], b[2]], entities=ents, ts=b[0]))
        transitions = [(a, b) for a, b in zip(act, act[1:]) if a[1] != b[1]]
        if len(transitions) >= 2 and not split or g["coups"]:
            F.append(make("fhrp_flap", f"{name}: active router changed {len(transitions)} time(s)"
                                       + (f"; {len(g['coups'])} coup/resign messages" if g["coups"] else "") + ": "
                                       + " → ".join(dict.fromkeys(x[1] for x in act))[:200] + ".",
                          packets=[b[2] for _, b in transitions[:10]] + [c[2] for c in g["coups"][:10]], entities=ents,
                          ts=(g["coups"] or [b for _, b in transitions] or [act[0]])[0][0],
                          severity="high" if len(transitions) >= 3 else "medium"))
        timers = {t for s_ in sps for t in s_["timers"]}
        if len(timers) > 1:
            F.append(make("fhrp_timer_mismatch", f"{name}: hello/hold timers differ: " +
                          "; ".join(f"{s_['address']} {sorted(s_['timers'])}" for s_ in sps), entities=ents,
                          packets=[s_["first_no"] for s_ in sps]))
        vips = {v for s_ in sps for v in s_["vips"]}
        if len(vips) > 1:
            F.append(make("fhrp_vip_mismatch", f"{name}: routers advertise different virtual IPs: " +
                          "; ".join(f"{s_['address']}={sorted(s_['vips'])}" for s_ in sps), entities=ents,
                          packets=[s_["first_no"] for s_ in sps]))
        auths = {a for s_ in sps for a in s_["auth"]}
        if len(auths) > 1:
            F.append(make("fhrp_auth_mismatch", f"{name}: authentication differs between routers ({len(auths)} variants) — "
                                                "they ignore each other's hellos.", entities=ents,
                          packets=[s_["first_no"] for s_ in sps]))
        if any(s_["auth_default"] for s_ in sps):
            F.append(make("fhrp_weak_auth", f"{name}: HSRP uses the default cleartext key 'cisco'.", entities=ents))
        if proto == "VRRP" and any(t != 255 for s_ in sps for t in s_["ttl"]):
            F.append(make("fhrp_bad_ttl", f"{name}: VRRP advertisements with TTL ≠ 255 from "
                                          f"{', '.join(s_['address'] for s_ in sps if any(t != 255 for t in s_['ttl']))} "
                                          "(RFC 5798 requires 255; receivers must drop them).", entities=ents))
        out.append({"protocol": proto, "group": gid, "vlan": vlan,
                    "speakers": [{**s_, "states": sorted(s_["states"]), "priority": sorted(s_["priority"]),
                                  "timers": sorted(s_["timers"]), "vips": sorted(s_["vips"]),
                                  "auth": sorted(str(a) for a in s_["auth"]), "ttl": sorted(t for t in s_["ttl"] if t is not None)}
                                 for s_ in sps],
                    "active_changes": len(transitions)})
    ctx.routing["fhrp"] = out


# ------------------------------------------------------------------ IS-IS ---
def _isis(ctx) -> None:
    F = ctx.findings
    pk = [p for p in ctx.packets if "isis" in p.layers]
    if not pk:
        return
    routers: dict = {}
    sid_macs = defaultdict(set)
    lsps = defaultdict(list)
    purges = []
    for p in pk:
        d = p.layers["isis"]
        if d["type"] in (15, 16, 17):
            r = routers.setdefault((d["system_id"], p.vlan), {"system_id": d["system_id"], "vlan": p.vlan, "mac": p.eth_src, "circuit": set(),
                                                    "areas": set(), "hold": set(), "auth": set(), "hello_len": set(),
                                                    "neighbors": set(), "ips": set(), "first_no": p.no, "ts": p.ts,
                                                    "hellos": 0, "p2p": d["type"] == 17})
            sid_macs[d["system_id"]].add(p.eth_src)
            r["circuit"].add(d["circuit"])
            r["areas"].update(d["areas"])
            r["hold"].add(d["hold"])
            r["auth"].add(d["auth"])
            if d.get("padded"):
                r["hello_len"].add(d["pdu_length"])
            r["neighbors"].update(d["neighbors"])
            r["ips"].update(d["ip_addresses"])
            r["hellos"] += 1
        elif d["type"] in (18, 20):
            lsps[d["lsp_id"]].append((p, d["seq"]))
            if d.get("purge"):
                purges.append(p)
    rs = list(routers.values())
    for i, a in enumerate(rs):
        for b in rs[i + 1:]:
            if a["vlan"] != b["vlan"] or a["system_id"] == b["system_id"]:
                continue                          # only neighbours on the same segment can form an adjacency
            pair = f"{a['system_id']} vs {b['system_id']}"
            ev = {"packets": [a["first_no"], b["first_no"]], "ts": max(a["ts"], b["ts"]), "entities": [a["system_id"], b["system_id"]]}
            ca, cb = set().union(*[{"L1", "L2"} if c == "L1L2" else {c} for c in a["circuit"]]), \
                set().union(*[{"L1", "L2"} if c == "L1L2" else {c} for c in b["circuit"]])
            common = ca & cb
            if not common:
                F.append(make("isis_circuit_mismatch", f"{pair}: circuit types {sorted(a['circuit'])} vs {sorted(b['circuit'])} — "
                                                       "no common level, no adjacency.", **ev))
            elif common == {"L1"} and not (a["areas"] & b["areas"]):
                F.append(make("isis_area_mismatch", f"{pair}: L1-only adjacency but no common area "
                                                    f"({sorted(a['areas'])} vs {sorted(b['areas'])}).", **ev))
            if a["auth"] != b["auth"]:
                F.append(make("isis_auth_mismatch", f"{pair}: authentication {sorted(map(str, a['auth']))} vs "
                                                    f"{sorted(map(str, b['auth']))}.", **ev))
            if a["hello_len"] and b["hello_len"] and a["hello_len"] != b["hello_len"]:
                F.append(make("isis_mtu_mismatch", f"{pair}: padded hello sizes {sorted(a['hello_len'])} vs "
                                                   f"{sorted(b['hello_len'])} bytes — interface MTUs differ, so the larger "
                                                   "hellos are dropped by the smaller-MTU side.", **ev))
            if not a["p2p"] and not b["p2p"] and common:
                for x, y in ((a, b), (b, a)):
                    if y["mac"] and y["mac"] not in x["neighbors"] and x["mac"] in y["neighbors"]:
                        F.append(make("isis_one_way", f"{x['system_id']} does not list {y['system_id']} ({y['mac']}) as a "
                                                      "neighbor although it is heard — adjacency stuck in INIT.", **ev))
    for sid, macs in sid_macs.items():
        if len(macs) > 1:
            F.append(make("isis_duplicate_sysid", f"System ID {sid} used by {len(macs)} devices: {', '.join(sorted(macs))}.",
                          entities=[sid] + sorted(macs)))
    dur = max(pk[-1].ts - pk[0].ts, 1)
    churn = {lid: v for lid, v in lsps.items() if len({s for _, s in v}) >= 5}
    if churn or purges:
        F.append(make("isis_lsp_churn", (f"{len(churn)} LSP(s) regenerated ≥5 times in {dur:.0f} s "
                                         f"({', '.join(list(churn)[:4])})" if churn else "") +
                      (f"; {len(purges)} LSP purge(s)" if purges else "") + ".",
                      packets=[p.no for v in churn.values() for p, _ in v[:3]][:20] + [p.no for p in purges[:5]],
                      ts=min([v[0][0].ts for v in churn.values()] + [p.ts for p in purges])))
    ctx.routing["isis"] = {"routers": [{**r, "circuit": sorted(r["circuit"]), "areas": sorted(r["areas"]),
                                        "hold": sorted(r["hold"]), "auth": sorted(map(str, r["auth"])),
                                        "hello_len": sorted(r["hello_len"]), "neighbors": sorted(r["neighbors"]),
                                        "ips": sorted(r["ips"])} for r in rs],
                           "lsps": len(lsps)}
