"""Multi-point analysis: two captures of the same traffic taken at different points.

Matching every TCP segment between the captures answers the question a single
capture cannot: *where* on the path packets are lost and how long each part of
the path takes.

* For each direction, the capture that saw more of the sender's segments is the
  upstream point; segments present upstream but absent downstream were lost
  **between** the two capture points.
* A retransmission whose original reached the downstream point means the loss
  happened **outside** the two points (beyond the downstream point, or the ACK
  was lost on the way back).
* Matched segments give the clock offset between the capture hosts and the
  one-way delay of the path segment between them (assuming symmetric delay).

Addresses are matched exactly first; if little matches (NAT between the points),
segments are matched on sequence/ack/length/flags only.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .analyzer import Analysis, analyze_file
from .correlate import RootCause
from .knowledge import make

RETRANS = ("retransmission", "fast_retransmission", "spurious_retransmission")


def _dir(p) -> tuple:
    return (p.src, p.sport, p.dst, p.dport)


def _segments(a: Analysis, nat: bool) -> list:
    """[(key, packet)] for every TCP segment carrying data or SYN/FIN/RST.

    The key identifies the same segment in both captures; a trailing occurrence
    index separates an original from its retransmissions."""
    seen: dict = defaultdict(int)
    out = []
    for p in a.packets:
        t = p.tcp
        if t is None or not (t.payload_len or t.syn or t.fin or t.rst):
            continue
        base = (t.seq, t.ack if t.ackf else 0, t.payload_len, t.flags) if nat else _dir(p) + (t.seq, t.payload_len, t.flags)
        seen[base] += 1
        out.append((base + (seen[base],), p))
    return out


def _closer_to_sender(a: Analysis, b: Analysis, dkey: tuple) -> str:
    """Tie-break with handshake timing: the capture nearer the sender sees the shorter iRTT half."""
    def half(an):
        for st in an.flows.streams:
            if (st.client, st.cport, st.server, st.sport) == dkey:
                return st.client_side_rtt          # sender is the client
            if (st.server, st.sport, st.client, st.cport) == dkey:
                return st.server_side_rtt          # sender is the server
        return None
    ha, hb = half(a), half(b)
    if ha is not None and hb is not None and ha != hb:
        return "A" if ha < hb else "B"
    return "A"


def compare(a: Analysis, b: Analysis) -> dict:
    nat = False
    sa, sb = _segments(a, False), _segments(b, False)
    kb = {k for k, _ in sb}
    if sa and sb and sum(1 for k, _ in sa if k in kb) < 0.2 * min(len(sa), len(sb)):
        nat = True                                     # addresses/ports rewritten between the points
        sa, sb = _segments(a, True), _segments(b, True)
    ia, ib = dict(sa), dict(sb)
    bmap: dict = {}
    if nat:                                            # learn B-direction -> A-direction from matched segments
        votes: dict = defaultdict(Counter)
        for k, p in sb:
            if k in ia:
                votes[_dir(p)][_dir(ia[k])] += 1
        bmap = {bd: c.most_common(1)[0][0] for bd, c in votes.items()}
    dirs: dict = defaultdict(lambda: {"a": [], "b": []})
    for k, p in sa:
        dirs[_dir(p)]["a"].append(k)
    for k, p in sb:
        bd = _dir(p)
        if nat and bd not in bmap:
            continue
        dirs[bmap.get(bd, bd)]["b"].append(k)

    results, deltas, lost_pkts = [], {}, []
    for dkey, sides in dirs.items():
        A, B = set(sides["a"]), set(sides["b"])
        only_a = [k for k in sides["a"] if k not in B]
        only_b = [k for k in sides["b"] if k not in A]
        matched = [k for k in sides["a"] if k in B]
        if len(only_a) != len(only_b):
            up = "A" if len(only_a) > len(only_b) else "B"
        else:
            up = _closer_to_sender(a, b, dkey)
        up_keys, up_idx, down = (sides["a"], ia, B) if up == "A" else (sides["b"], ib, A)
        lost = only_a if up == "A" else only_b
        between = outside = 0
        first_by_seq: dict = {}            # original transmission of each sequence number (any segment size)
        for k in up_keys:
            first_by_seq.setdefault(up_idx[k].tcp.seq, k)
            if any(f in up_idx[k].tcp.analysis for f in RETRANS):
                orig = first_by_seq[up_idx[k].tcp.seq]
                if orig != k and orig not in down:
                    between += 1               # the original vanished between the points
                else:
                    outside += 1               # original reached the downstream point: loss further on / ACK loss
        # downstream minus upstream arrival: min() = one-way delay ± clock offset (queueing only adds)
        sign = 1 if up == "A" else -1
        deltas[dkey] = (up, [sign * (ib[k].ts - ia[k].ts) for k in matched])
        results.append({
            "direction": f"{dkey[0]}:{dkey[1]} → {dkey[2]}:{dkey[3]}", "upstream": up,
            "segments_a": len(sides["a"]), "segments_b": len(sides["b"]), "matched": len(matched),
            "lost_between": len(lost), "retrans_loss_between": between, "retrans_loss_outside": outside,
            "lost_packets_upstream": [up_idx[k].no for k in lost[:30]],
        })
        lost_pkts += [(up, up_idx[k]) for k in lost[:30]]
    # A-upstream: min(tB - tA) = owd + off ; B-upstream: min(tA - tB) = owd - off  (off = clock of B minus A)
    offset = one_way = None
    for dkey, (up, d) in deltas.items():
        rup, rev = deltas.get((dkey[2], dkey[3], dkey[0], dkey[1]), (None, []))
        if d and rev and up != rup:
            m_a, m_b = (min(d), min(rev)) if up == "A" else (min(rev), min(d))
            one_way, offset = (m_a + m_b) / 2, (m_a - m_b) / 2
            break
    if offset is None:
        allv = [x if up == "A" else -x for up, d in deltas.values() for x in d]
        offset = min(allv) if allv else None   # offset + delay, cannot be separated
    return {"capture_a": a.source, "capture_b": b.source, "nat_mode": nat, "directions": results,
            "clock_offset_s": offset, "one_way_delay_s": one_way,
            "lost_between": sum(r["lost_between"] for r in results),
            "retrans_loss_outside": sum(r["retrans_loss_outside"] for r in results), "lost_between_pkts": lost_pkts}


def compare_files(path_a: str, path_b: str, keylog_path: str | None = None) -> tuple[Analysis, Analysis, dict]:
    a = analyze_file(path_a, keylog_path=keylog_path)
    b = analyze_file(path_b, keylog_path=keylog_path)
    return a, b, compare(a, b)


def _on_a_clock(a: Analysis, p, side: str, res: dict):
    """Time of packet ``p`` on capture A's relative timeline (B packets shifted by the estimated clock offset)."""
    if side == "A":
        return round(p.rel_ts, 6)
    if res["clock_offset_s"] is None:
        return None
    return round(p.ts - res["clock_offset_s"] - a.t0, 6)


def annotate(a: Analysis, res: dict) -> None:
    """Add multi-point findings/root causes to analysis ``a`` so the normal reports show them."""
    import os
    other = os.path.basename(res["capture_b"])
    lost = res["lost_between"]
    dirs = [d for d in res["directions"] if d["lost_between"] or d["retrans_loss_between"]]
    timing = ""
    if res["one_way_delay_s"] is not None:
        timing = (f" One-way delay between the capture points ≈{res['one_way_delay_s'] * 1000:.2f} ms; "
                  f"clock offset between the capture hosts ≈{res['clock_offset_s']:.3f} s.")
    elif res["clock_offset_s"] is not None:
        timing = f" Clock offset/delay between captures ≈{res['clock_offset_s']:.3f} s (one direction only)."
    data_lost = [p for _, p in res["lost_between_pkts"] if p.tcp.payload_len]
    mtu_hint = ""
    if data_lost and all(p.tcp.payload_len >= 1300 for p in data_lost):
        mtu_hint = (f" Every lost data segment is full-size ({min(p.tcp.payload_len for p in data_lost)}+ bytes) while smaller "
                    "packets got through: a link between the capture points has a smaller MTU and drops large packets "
                    "(MTU/PMTUD black hole).")
    timing = mtu_hint + timing
    if lost:
        f = make("cmp_loss_between",
                 f"{lost} segment(s) seen at the upstream capture never reached the downstream capture ({other}): "
                 + "; ".join(f"{d['direction']}: {d['lost_between']} lost (upstream = capture {d['upstream']})" for d in dirs[:4])
                 + "." + timing,
                 packets=[p.no for side, p in res["lost_between_pkts"] if side == "A"][:30],
                 entities=[d["direction"] for d in dirs], details={k: v for k, v in res.items() if k != "lost_between_pkts"})
        f.uid = f"M{len(a.findings) + 1:03d}"
        a.findings.insert(0, f)
        a.root_causes.insert(0, RootCause(
            "loss_between_points", "Packet loss located between the two capture points", "critical", 0.95,
            f"Proven by multi-point capture: {lost} packet(s) left the upstream point and never arrived at the downstream point.",
            "Matching every TCP segment between the two captures shows exactly which packets vanished in transit. The end hosts "
            "and anything outside the two points are exonerated for these losses." + timing,
            sorted(({"t": _on_a_clock(a, p, side, res), "no": p.no if side == "A" else None, "layer": "Transport",
                     "text": f"{p.src}→{p.dst} [{p.tcp.flag_str()}] seq={p.tcp.seq} len={p.tcp.payload_len} seen at capture "
                             f"{side}{'' if side == 'A' else f' (#{p.no})'}, never arrived at the other capture"}
                    for side, p in res["lost_between_pkts"][:8]), key=lambda x: (x["t"] is None, x["t"] or 0)),
            [f.uid], [d["direction"] for d in dirs],
            f.perspectives, f.remediation, f.recommendations, "network"))
    elif res["retrans_loss_outside"]:
        f = make("cmp_loss_outside",
                 f"All retransmitted segments' originals reached both capture points ({res['retrans_loss_outside']} retransmissions): "
                 "the loss happened outside the two points, or ACKs were lost on the return path." + timing,
                 details={k: v for k, v in res.items() if k != "lost_between_pkts"})
        f.uid = f"M{len(a.findings) + 1:03d}"
        a.findings.insert(0, f)
    a.warnings.append(f"Multi-point comparison with {other}: {sum(d['matched'] for d in res['directions'])} segments matched"
                      + (" (NAT mode: matched on seq/ack/len)" if res["nat_mode"] else "") + "." + timing)


def text(res: dict) -> str:
    import os
    lines = [f"Multi-point comparison: A={os.path.basename(res['capture_a'])}  B={os.path.basename(res['capture_b'])}"
             + ("  [NAT mode]" if res["nat_mode"] else "")]
    if res["clock_offset_s"] is not None:
        lines.append(f"  Clock offset (B − A): {res['clock_offset_s']:.6f} s"
                     + (f"   One-way delay between points: {res['one_way_delay_s'] * 1000:.3f} ms" if res["one_way_delay_s"] is not None else ""))
    for d in res["directions"]:
        lines.append(f"  {d['direction']}: A={d['segments_a']} B={d['segments_b']} matched={d['matched']} upstream={d['upstream']} "
                     f"lost-between={d['lost_between']} retrans(loss between={d['retrans_loss_between']}, outside={d['retrans_loss_outside']})")
    if res["lost_between"]:
        lines.append(f"  VERDICT: {res['lost_between']} packet(s) lost BETWEEN the capture points — the fault is in the path between them.")
    elif res["retrans_loss_outside"]:
        lines.append("  VERDICT: no loss between the capture points; retransmissions were caused outside them.")
    else:
        lines.append("  VERDICT: no loss detected between or outside the capture points.")
    return "\n".join(lines)
