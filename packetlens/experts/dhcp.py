"""DHCP expert: DORA transaction reconstruction and failure analysis."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make


def run(ctx) -> None:
    F = ctx.findings
    by_xid: dict[int, dict] = {}
    servers = defaultdict(set)   # server id -> offered IPs
    for p in ctx.packets:
        d = p.layers.get("dhcp")
        if not d or not d["msg_type"]:
            continue
        t = by_xid.setdefault(d["xid"], {"xid": f"0x{d['xid']:08x}", "client_mac": d["chaddr"], "ts": p.ts,
                                         "t": p.rel_ts, "messages": [], "offers": [], "servers": set(),
                                         "relay": None, "yiaddr": None, "nak_msg": None, "hostname": None,
                                         "lease": None, "first_no": p.no, "last_ts": p.ts})
        mt = d["msg_type"]
        t["messages"].append((p.no, mt, round(p.rel_ts, 6)))
        t["last_ts"] = p.ts
        sid = d["options"].get("server_id") or (p.src if d["op"] == 2 else None)
        if d["giaddr"] != "0.0.0.0":
            t["relay"] = d["giaddr"]
        if d["options"].get("hostname"):
            t["hostname"] = d["options"]["hostname"]
        if mt == "OFFER":
            t["offers"].append({"server": sid, "ip": d["yiaddr"], "router": d["options"].get("router"),
                                "dns": d["options"].get("dns_servers"), "no": p.no})
            t["servers"].add(sid)
            servers[sid].add(d["yiaddr"])
            if d["options"].get("router"):
                ctx.gateways.update(d["options"]["router"])
        elif mt == "ACK":
            t["yiaddr"] = d["yiaddr"] if d["yiaddr"] != "0.0.0.0" else d["ciaddr"]
            t["lease"] = d["options"].get("lease_time")
            t["servers"].add(sid)
            if d["options"].get("router"):
                ctx.gateways.update(d["options"]["router"])
        elif mt == "NAK":
            t["nak_msg"] = d["options"].get("message")
    txs = []
    for t in by_xid.values():
        types = [m[1] for m in t["messages"]]
        if "ACK" in types:
            outcome = "success"
        elif "NAK" in types:
            outcome = "nak"
        elif "DECLINE" in types:
            outcome = "decline"
        elif "REQUEST" in types:
            outcome = "no_ack"
        elif "OFFER" in types:
            outcome = "no_request"
        elif "DISCOVER" in types:
            outcome = "no_offer"
        else:
            outcome = "other"
        txs.append({**t, "servers": sorted(s for s in t["servers"] if s), "outcome": outcome,
                    "duration_ms": round((t["last_ts"] - t["ts"]) * 1000, 3), "sequence": " → ".join(types)})
    ctx.dhcp_transactions = txs
    if not txs:
        return

    def emit(fid, items, text, **kw):
        if items:
            F.append(make(fid, text, packets=[m[0] for t in items[:10] for m in t["messages"][:4]],
                          entities=sorted({t["client_mac"] for t in items})[:10], ts=items[0]["ts"],
                          count=len(items), **kw))

    no_offer = [t for t in txs if t["outcome"] == "no_offer"]
    emit("dhcp_no_offer", no_offer,
         f"{len(no_offer)} client(s) sent DISCOVER with no OFFER "
         f"({sum(len(t['messages']) for t in no_offer)} DISCOVERs). Clients: {', '.join(sorted({t['client_mac'] for t in no_offer})[:5])}."
         + (" A relay (giaddr) was present — check relay→server path." if any(t["relay"] for t in no_offer) else
            " No relay seen — check 'ip helper-address' on the VLAN gateway."))
    no_ack = [t for t in txs if t["outcome"] == "no_ack"]
    emit("dhcp_no_ack", no_ack, f"{len(no_ack)} DHCP REQUEST(s) without ACK/NAK.")
    naks = [t for t in txs if t["outcome"] == "nak"]
    emit("dhcp_nak", naks, f"{len(naks)} NAK(s): " + "; ".join(f"{t['client_mac']}: {t['nak_msg'] or 'no message'}" for t in naks[:5]))
    dec = [t for t in txs if t["outcome"] == "decline"]
    emit("dhcp_decline", dec, f"{len(dec)} DECLINE(s) — client detected the offered address already in use.")
    multi = [t for t in txs if len({o["server"] for o in t["offers"]}) > 1]
    all_servers = sorted(s for s in servers if s)
    if multi or len(all_servers) > 1:
        detail = "; ".join(f"{s} offering {', '.join(sorted(servers[s])[:3])}" for s in all_servers)
        emit("dhcp_multiple_servers", multi or txs,
             f"{len(all_servers)} DHCP servers are answering on this segment: {detail}. "
             "Unless this is a configured failover pair, one of them is rogue.",
             details={"servers": {s: sorted(servers[s]) for s in all_servers},
                      "offers": [o for t in multi for o in t["offers"]]})
    slow = [t for t in txs if t["outcome"] == "success" and t["duration_ms"] > 2000]
    emit("dhcp_slow", slow, f"{len(slow)} DORA exchange(s) took more than 2 s (worst "
                            f"{max((t['duration_ms'] for t in slow), default=0) / 1000:.1f} s).")
