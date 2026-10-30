"""AI / HPC fabric expert: RoCEv2 queue pairs (PSN gaps, go-back-N retransmissions, NAK / RNR NAK, CNP and
ECN congestion signals, non-ECN-capable RoCE) and Priority Flow Control (pause storms) - the lossless-Ethernet
problems that stall GPU collective operations (all-reduce waits for the slowest flow)."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make
from ..protocols import roce

M24 = 0xFFFFFF


def run(ctx) -> None:
    qps: dict = {}
    naks, rnr, cnps = defaultdict(list), defaultdict(list), defaultdict(list)
    ecn = defaultdict(lambda: [0, 0, 0])            # (src, dst) -> [packets, CE, not-ECT]
    for p in ctx.packets:
        d = p.layers.get("roce")
        if not d:
            continue
        pair = (p.src, p.dst)
        e = ecn[pair]
        e[0] += 1
        e[1] += p.ecn == 3
        e[2] += p.ecn == 0
        if d["opcode"] == 0x81:
            cnps[pair].append(p.no)
            continue
        if d.get("aeth"):
            a = d["aeth"]
            if a["kind"] == "NAK":
                naks[pair].append((p.no, a.get("nak")))
            elif a["kind"] == "RNR NAK":
                rnr[pair].append(p.no)
            continue
        if d["opcode"] & 0x1F in roce.RESPONSES:
            continue
        key = (p.src, p.dst, d["dest_qp"])
        q = qps.get(key)
        if q is None:
            q = qps[key] = {"src": p.src, "dst": p.dst, "qp": f"0x{d['dest_qp']:06x}", "first": p.no, "ts": p.ts,
                            "packets": 0, "bytes": 0, "expected": None, "gaps": 0, "gap_nos": [], "retx": 0, "retx_nos": [],
                            "ops": defaultdict(int)}
        q["packets"] += 1
        q["bytes"] += p.wirelen
        q["ops"][d["op"]] += 1
        psn = d["psn"]
        if q["expected"] is not None and psn != q["expected"]:
            ahead = (psn - q["expected"]) & M24
            if ahead < 0x800000:
                q["gaps"] += ahead
                q["gap_nos"].append(p.no)
            else:                                   # PSN went backwards: go-back-N retransmission
                q["retx"] += 1
                q["retx_nos"].append(p.no)
        nxt = (psn + 1) & M24
        if q["expected"] is None or ((nxt - q["expected"]) & M24) < 0x800000:
            q["expected"] = nxt
    pfc: dict = {}
    for p in ctx.packets:
        d = p.layers.get("pfc")
        if not d or d["type"] not in ("PFC", "PAUSE"):
            continue
        prios = d["priorities"] if d["type"] == "PFC" else {"all": d["quanta"]}
        for prio, quanta in prios.items():
            s = pfc.setdefault((p.eth_src, prio), {"mac": p.eth_src, "priority": prio, "kind": d["type"], "frames": 0,
                                                   "pausing": 0, "resumes": 0, "max_quanta": 0, "first": p.ts, "last": p.ts,
                                                   "nos": []})
            s["frames"] += 1
            s["pausing" if quanta else "resumes"] += 1
            s["max_quanta"] = max(s["max_quanta"], quanta)
            s["last"] = p.ts
            if len(s["nos"]) < 20:
                s["nos"].append(p.no)
    ctx.fabric = {
        "qps": [{**{k: v for k, v in q.items() if k not in ("expected", "gap_nos", "retx_nos")}, "ops": dict(q["ops"]),
                 "naks": len(naks.get((q["src"], q["dst"]), [])) + len(naks.get((q["dst"], q["src"]), [])),
                 "cnps": len(cnps.get((q["dst"], q["src"]), [])),
                 "ce": ecn[(q["src"], q["dst"])][1], "not_ect": ecn[(q["src"], q["dst"])][2]} for q in qps.values()][:500],
        "pfc": [{**{k: v for k, v in s.items() if k != "nos"}, "rate_per_s": round(s["frames"] / max(s["last"] - s["first"], 1e-3), 1)}
                for s in pfc.values()][:200],
    }
    _findings(ctx, qps, naks, rnr, cnps, ecn, pfc)


def _findings(ctx, qps, naks, rnr, cnps, ecn, pfc):
    F = ctx.findings
    lossy = [q for q in qps.values() if q["gaps"] or q["retx"]]
    all_naks = [(pair, n) for pair, lst in naks.items() for n in lst]
    if lossy or all_naks:
        F.append(make("roce_packet_loss", "; ".join(
            f"QP {q['qp']} {q['src']} → {q['dst']}: {q['gaps']} missing PSN(s), {q['retx']} go-back-N retransmission(s)"
            for q in lossy[:5]) + (f"; {len(all_naks)} NAK(s): " + ", ".join(sorted({n[1] for _, n in all_naks})) if all_naks else ""),
            packets=[n for q in lossy[:5] for n in (q["gap_nos"][:4] + q["retx_nos"][:4])] + [n[0] for _, n in all_naks[:10]],
            ts=min([q["ts"] for q in lossy] or [ctx.pkt(all_naks[0][1][0]).ts]), count=sum(q["gaps"] for q in lossy) + len(all_naks),
            entities=sorted({x for q in lossy for x in (q["src"], q["dst"])} | {x for pair, _ in all_naks for x in pair})[:15]))
    rnrs = [(pair, n) for pair, lst in rnr.items() for n in lst]
    if rnrs:
        F.append(make("roce_rnr", f"{len(rnrs)} RNR NAK(s): the responder had no receive buffer posted: " + ", ".join(
            f"{a} → {b}" for (a, b) in sorted({pair for pair, _ in rnrs})[:6]), packets=[n for _, n in rnrs[:20]],
            ts=ctx.pkt(rnrs[0][1]).ts, count=len(rnrs)))
    roce_pkts = sum(e[0] for e in ecn.values())
    ce = sum(e[1] for e in ecn.values())
    n_cnp = sum(len(v) for v in cnps.values())
    if ce or n_cnp:
        F.append(make("roce_congestion", f"{n_cnp} Congestion Notification Packet(s) and {ce} ECN-CE marked RoCE packet(s) "
                      f"({ce / max(roce_pkts, 1):.0%} of {roce_pkts}): " + ", ".join(
                          f"{b} told {a} to slow down ({len(v)} CNP)" for (b, a), v in list(cnps.items())[:5]),
                      packets=[n for v in cnps.values() for n in v[:5]][:20], ts=ctx.packets[0].ts if ctx.packets else None,
                      count=n_cnp + ce, entities=sorted({x for pair in cnps for x in pair})[:15]))
    not_ect = [(pair, e) for pair, e in ecn.items() if e[0] >= 5 and e[2] == e[0]]
    if not_ect:
        F.append(make("roce_not_ect", "; ".join(f"{a} → {b}: {e[0]} RoCE packets, none ECN-capable" for (a, b), e in not_ect[:6]),
                      count=sum(e[0] for _, e in not_ect), entities=sorted({x for pair, _ in not_ect for x in pair})[:15]))
    storms = [s for s in pfc.values() if s["pausing"] >= 20 and s["pausing"] / max(s["last"] - s["first"], 1e-3) >= 50]
    if storms:
        F.append(make("pfc_storm", "; ".join(
            f"{s['mac']} priority {s['priority']}: {s['pausing']} pause frames in {s['last'] - s['first']:.2f}s "
            f"(max {s['max_quanta']} quanta, {s['resumes']} resume)" for s in storms[:5]),
            packets=[n for s in storms[:5] for n in s["nos"][:5]], ts=storms[0]["first"], count=sum(s["pausing"] for s in storms),
            entities=[s["mac"] for s in storms][:15]))
    calm = [s for s in pfc.values() if s not in storms]
    if calm:
        F.append(make("pfc_active", "; ".join(f"{s['mac']} {s['kind']} priority {s['priority']}: {s['frames']} frame(s)"
                                              for s in calm[:6]),
                      packets=[n for s in calm[:5] for n in s["nos"][:3]], ts=calm[0]["first"], count=sum(s["frames"] for s in calm),
                      entities=[s["mac"] for s in calm][:15]))
