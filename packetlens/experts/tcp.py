"""TCP expert: converts per-stream analysis into findings."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make

RETRANS = ("retransmission", "fast_retransmission")


def _data_retrans(st) -> int:
    """Data retransmissions (handshake SYN/SYN-ACK retries are reported separately)."""
    return (st.count("retransmission") + st.count("fast_retransmission")
            - st.count("syn_retransmission") - st.count("synack_retransmission"))


def _pkts(st, *flags, limit=20):
    return [no for no, f, _ in st.events if f in flags][:limit]


def run(ctx) -> None:
    streams = ctx.flows.streams
    total_data_pkts = sum(1 for p in ctx.packets if p.tcp and p.tcp.payload_len) or 1
    F = ctx.findings

    # ---------------------------------------------------- retransmissions ---
    retrans_streams = [s for s in streams if _data_retrans(s) > 0]
    retrans_total = sum(_data_retrans(s) for s in retrans_streams)
    if retrans_streams:
        rate = retrans_total / total_data_pkts * 100
        worst = sorted(retrans_streams, key=lambda s: -_data_retrans(s))[:10]
        by_server = defaultdict(int)
        for s in retrans_streams:
            by_server[s.server] += _data_retrans(s)
        spread = "many servers (likely a shared-path / local-link problem)" if len(by_server) > 3 else \
            "a limited set of servers (problem likely on the path to those servers)"
        sender_side = defaultdict(int)
        for s in retrans_streams:
            syn_nos = {n for n, f, _ in s.events if f in ("syn_retransmission", "synack_retransmission")}
            for n, f, d in s.events:
                if f in RETRANS and n not in syn_nos:
                    sender_side["client" if d == "c2s" else "server"] += 1
        sev = "high" if rate >= 2 else "medium" if rate >= 0.5 else "low"
        F.append(make("tcp_retransmissions",
                      f"{retrans_total} retransmissions across {len(retrans_streams)} TCP stream(s) "
                      f"(≈{rate:.2f}% of data segments). Retransmissions affect {spread}. "
                      f"Retransmitted by: server {sender_side['server']}, client {sender_side['client']}.",
                      severity=sev, count=retrans_total,
                      packets=[n for s in worst for n in _pkts(s, *RETRANS, limit=5)],
                      entities=[f"stream {s.id}: {s.client}:{s.cport} ↔ {s.server}:{s.sport}" for s in worst],
                      ts=min(s.first_ts for s in retrans_streams),
                      details={"rate_pct": round(rate, 3), "by_server": dict(by_server),
                               "streams": [s.id for s in worst]},
                      extra_perspectives={"network": f"Server-side retransmissions ({sender_side['server']}) mean data "
                                                     f"from the server was lost toward the client; client-side "
                                                     f"({sender_side['client']}) the opposite direction."}))
    dup = sum(s.count("duplicate_ack") for s in streams)
    if dup >= 3:
        worst = sorted(streams, key=lambda s: -s.count("duplicate_ack"))[:5]
        F.append(make("tcp_duplicate_acks", f"{dup} duplicate ACKs; max {worst[0].count('duplicate_ack')} in stream {worst[0].id}.",
                      count=dup, packets=[n for s in worst for n in _pkts(s, "duplicate_ack", limit=5)],
                      severity="medium" if dup > 20 else "low", ts=worst[0].first_ts))
    ooo = sum(s.count("out_of_order") for s in streams)
    if ooo:
        worst = sorted(streams, key=lambda s: -s.count("out_of_order"))[:5]
        F.append(make("tcp_out_of_order", f"{ooo} out-of-order segments.", count=ooo,
                      packets=[n for s in worst for n in _pkts(s, "out_of_order", limit=5)], ts=worst[0].first_ts))
    sp = sum(s.count("spurious_retransmission") for s in streams)
    if sp:
        worst = sorted(streams, key=lambda s: -s.count("spurious_retransmission"))[:5]
        F.append(make("tcp_spurious_retrans", f"{sp} spurious retransmissions (data already ACKed).", count=sp,
                      packets=[n for s in worst for n in _pkts(s, "spurious_retransmission", limit=5)], ts=worst[0].first_ts))
    # scanners craft packets with arbitrary seq/ack numbers: they say nothing about capture quality
    real = [s for s in streams if s.client not in ctx.scanners]
    lost = sum(s.count("lost_segment") for s in real)
    unseen = sum(s.count("ack_unseen") for s in real)
    if lost or unseen:
        worst = sorted(real, key=lambda s: -(s.count("lost_segment") + s.count("ack_unseen")))[:5]
        verdict = ("Most gaps were later ACKed by the receiver ⇒ the CAPTURE dropped packets, not the network."
                   if unseen > lost and unseen >= 3 else
                   "Gaps not ACKed by the receiver ⇒ real loss upstream of the capture point is likely.")
        F.append(make("tcp_lost_segment", f"{lost} 'previous segment not captured' and {unseen} 'ACKed unseen segment' events. {verdict}",
                      count=lost + unseen, packets=[n for s in worst for n in _pkts(s, "lost_segment", "ack_unseen", limit=5)],
                      severity="medium" if lost + unseen > 5 else "low", ts=worst[0].first_ts))

    # ----------------------------------------------------- handshake / RST --
    no_answer = [s for s in streams if s.syn_count and not s.synack_count and not s.rst and s.client not in ctx.scanners]
    if no_answer:
        dests = defaultdict(list)
        for s in no_answer:
            dests[f"{s.server}:{s.sport}"].append(s)
        # separate scans (handled by security expert) from genuine failures
        genuine = {k: v for k, v in dests.items() if any(x.syn_count > 1 for x in v) or len(dests) <= 10}
        for dest, sts in list(genuine.items())[:15]:
            tries = sum(x.syn_count for x in sts)
            waited = max(x.last_ts - (x.first_syn_ts or x.first_ts) for x in sts)
            F.append(make("tcp_syn_no_response",
                          f"{len(sts)} connection attempt(s) from {sts[0].client} to {dest}: {tries} SYNs sent, "
                          f"no SYN-ACK received (client waited {waited:.1f} s).",
                          packets=[x.first_no for x in sts] + [n for x in sts for n in _pkts(x, "syn_retransmission", limit=4)],
                          entities=[sts[0].client, dest], ts=sts[0].first_ts, count=tries,
                          details={"server": dest.rsplit(":", 1)[0], "port": int(dest.rsplit(":", 1)[1]),
                                   "client": sts[0].client, "syns": tries, "wait_s": round(waited, 3)}))
    refused = [s for s in streams if s.rst and s.rst["kind"] == "refused"]
    if refused:
        groups = defaultdict(list)
        for s in refused:
            groups[(s.client, s.server)].append(s)
        for (cli, srv), sts in groups.items():
            ports = sorted({x.sport for x in sts})
            if len(ports) > 15 or cli in ctx.scanners:
                continue  # port scan, reported by the security expert
            F.append(make("tcp_conn_refused",
                          f"{srv} refused {len(sts)} connection(s) from {cli} on port(s) {', '.join(map(str, ports[:10]))} "
                          f"(SYN answered with RST).",
                          packets=[x.rst["no"] for x in sts][:20], entities=[cli, srv], ts=sts[0].first_ts,
                          count=len(sts), details={"server": srv, "client": cli, "ports": ports}))
    # "early" resets after a completed handshake count; half-open scanner resets do not
    aborts = [s for s in streams if s.rst and (s.rst["kind"] == "abort" or
                                               (s.rst["kind"] == "early" and s.completeness & 4))]
    if aborts:
        by_sender = defaultdict(int)
        for s in aborts:
            by_sender[s.rst["from"]] += 1
        F.append(make("tcp_reset_abort",
                      f"{len(aborts)} established connection(s) aborted with RST "
                      f"(sent by server: {by_sender['server']}, client: {by_sender['client']}).",
                      packets=[s.rst["no"] for s in aborts][:20],
                      entities=[f"stream {s.id}: {s.client}:{s.cport} ↔ {s.server}:{s.sport} (RST from {s.rst['from']})" for s in aborts[:10]],
                      ts=aborts[0].rst["ts"], count=len(aborts)))

    # --------------------------------------------------------- windows ------
    zw = [s for s in streams if s.count("zero_window")]
    if zw:
        parts = []
        for s in zw[:10]:
            sides = {d for _, f, d in s.events if f == "zero_window"}
            who = " & ".join(sorted(("client " + s.client) if d == "c2s" else ("server " + s.server) for d in sides))
            parts.append(f"stream {s.id} ({who})")
        F.append(make("tcp_zero_window",
                      f"{sum(s.count('zero_window') for s in zw)} zero-window advertisements in {len(zw)} stream(s): "
                      + "; ".join(parts) + ". The advertising host's application is not reading data fast enough.",
                      packets=[n for s in zw for n in _pkts(s, "zero_window", "zero_window_probe", limit=6)],
                      ts=zw[0].first_ts, count=sum(s.count('zero_window') for s in zw),
                      details={"streams": [s.id for s in zw]}))
    wf = [s for s in streams if s.count("window_full")]
    if wf:
        F.append(make("tcp_window_full",
                      f"{sum(s.count('window_full') for s in wf)} 'window full' events in {len(wf)} stream(s): senders were "
                      f"blocked by the receiver's window.",
                      packets=[n for s in wf for n in _pkts(s, "window_full", limit=5)], ts=wf[0].first_ts,
                      severity="medium" if len(wf) > 1 or sum(s.count('window_full') for s in wf) > 5 else "low"))
    low = [s for s in streams if s.completeness & 8 and any(w is not None and 0 < w <= 2920 for w in (s.c.min_win, s.s.min_win))]
    if low:
        F.append(make("tcp_low_rwin", f"{len(low)} stream(s) advertised a receive window ≤ 2920 bytes "
                                      f"(Chris Greer 'Low RWin' button).",
                      entities=[f"stream {s.id}" for s in low[:10]], ts=low[0].first_ts))

    # ------------------------------------------------------ latency ---------
    slow = [s for s in streams if s.irtt is not None and s.irtt > 0.2]
    if slow:
        slow.sort(key=lambda s: -s.irtt)
        s0 = slow[0]
        where = ("server side of the capture point" if (s0.server_side_rtt or 0) > (s0.client_side_rtt or 0)
                 else "client side of the capture point")
        F.append(make("tcp_high_irtt",
                      f"{len(slow)} handshake(s) with iRTT > 200 ms; worst {s0.irtt * 1000:.0f} ms "
                      f"(stream {s0.id} to {s0.server}:{s0.sport}; SYN→SYN-ACK {s0.server_side_rtt * 1000:.0f} ms, "
                      f"SYN-ACK→ACK {s0.client_side_rtt * 1000:.0f} ms ⇒ latency lives on the {where}).",
                      severity="high" if s0.irtt > 1 else "medium", packets=[s.first_no for s in slow[:10]],
                      entities=[f"{s.server}:{s.sport} iRTT {s.irtt * 1000:.0f} ms" for s in slow[:10]], ts=s0.first_ts))

    # request/response timing is meaningless for routing-protocol sessions (keepalive-driven)
    # > 30 s between a client message and the next server data is server push / long-poll, not think time
    rts = [(s, a, b, t) for s in streams if 179 not in (s.sport, s.cport)
           for a, b, t in s.response_times if 1.0 < t <= 30.0]
    if rts:
        rts.sort(key=lambda x: -x[3])
        F.append(make("tcp_slow_response",
                      f"{len(rts)} request/response exchange(s) where the server took > 1 s to start responding; "
                      f"worst {rts[0][3]:.2f} s (stream {rts[0][0].id}, {rts[0][0].server}:{rts[0][0].sport}, "
                      f"request pkt {rts[0][1]} → response pkt {rts[0][2]}).",
                      severity="high" if rts[0][3] > 2 else "medium",
                      packets=[x for r in rts[:10] for x in (r[1], r[2])],
                      entities=list({f"{r[0].server}:{r[0].sport}" for r in rts[:10]}), ts=rts[0][0].first_ts,
                      details={"worst_s": round(rts[0][3], 3)}))
    gaps = [(s, g) for s in streams for g in s.gaps]
    if gaps:
        causes = defaultdict(int)
        for _, g in gaps:
            causes[g["cause"].split(":")[0]] += 1
        F.append(make("tcp_idle_gaps",
                      f"{len(gaps)} gaps > 1 s inside TCP conversations. Attribution: "
                      + ", ".join(f"{k} {v}" for k, v in sorted(causes.items(), key=lambda x: -x[1])) + ".",
                      packets=[g["no"] for _, g in gaps[:20]], ts=gaps[0][0].first_ts,
                      details={"attribution": dict(causes),
                               "gaps": [{"stream": s.id, **g} for s, g in gaps[:30]]}))

    # --------------------------------------------------- negotiation --------
    hs = [s for s in streams if s.syn_count and s.synack_count]
    no_ws = [s for s in hs if s.c.wscale < 0 or s.s.wscale < 0]
    if no_ws:
        F.append(make("tcp_no_wscale", f"{len(no_ws)} of {len(hs)} handshakes without window scaling on at least one side.",
                      entities=[f"stream {s.id} ({'client' if s.c.wscale < 0 else 'server'} omitted)" for s in no_ws[:10]],
                      packets=[s.first_no for s in no_ws[:10]], ts=no_ws[0].first_ts,
                      severity="medium" if any(s.s.payload_bytes + s.c.payload_bytes > 1_000_000 for s in no_ws) else "low"))
    no_sack = [s for s in hs if not (s.c.sack_perm and s.s.sack_perm)]
    if no_sack:
        F.append(make("tcp_no_sack", f"{len(no_sack)} of {len(hs)} handshakes without SACK.",
                      packets=[s.first_no for s in no_sack[:10]], ts=no_sack[0].first_ts))
    small = [s for s in hs if min(x for x in (s.c.mss, s.s.mss) if x) < 1400] if hs else []
    small = [s for s in small if s.c.mss and s.s.mss]
    if small:
        F.append(make("tcp_small_mss", f"{len(small)} handshake(s) negotiated MSS < 1400 "
                                       f"(e.g. stream {small[0].id}: client {small[0].c.mss} / server {small[0].s.mss}).",
                      packets=[s.first_no for s in small[:10]], ts=small[0].first_ts))

    # --------------------------------------------------- capture point ------
    splits = [(s.server_side_rtt, s.client_side_rtt) for s in hs if s.irtt]
    if splits:
        srv = sorted(a for a, _ in splits)[len(splits) // 2]
        cli = sorted(b for _, b in splits)[len(splits) // 2]
        if cli < srv * 0.2:
            loc = "near the CLIENT(s) — SYN-ACK→ACK is almost instant"
        elif srv < cli * 0.2:
            loc = "near the SERVER(s) — SYN→SYN-ACK is almost instant"
        else:
            loc = "in the MIDDLE of the path (both halves contribute latency)"
        ctx.capture_point = loc
        F.append(make("tcp_capture_point",
                      f"Capture appears to have been taken {loc}. Median SYN→SYN-ACK {srv * 1000:.2f} ms, "
                      f"SYN-ACK→ACK {cli * 1000:.2f} ms over {len(splits)} handshakes.", severity="info",
                      details={"median_server_side_ms": round(srv * 1000, 3), "median_client_side_ms": round(cli * 1000, 3)}))
