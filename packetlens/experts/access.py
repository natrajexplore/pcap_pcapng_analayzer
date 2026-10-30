"""Network access control expert: 802.1X (EAPOL/EAP) sessions and RADIUS transactions."""
from __future__ import annotations

from collections import Counter

from ..knowledge import make

WEAK_METHODS = {"MD5-Challenge": "no mutual authentication, no session keys, offline dictionary attack on the hash",
                "GTC": "cleartext token unless wrapped in a tunnel"}


def run(ctx) -> None:
    _dot1x(ctx)
    _radius(ctx)


def _dot1x(ctx) -> None:
    F = ctx.findings
    sess: dict = {}
    last_by_auth: dict = {}
    last_real = None                      # most recent supplicant MAC seen (wired: one supplicant per port)
    for p in ctx.packets:
        d = p.layers.get("eapol")
        if not d:
            continue
        w = p.layers.get("wlan") or {}
        e = d.get("eap") or {}
        if d["type"] == "EAPOL-Key":            # 4-way handshake runs both ways between AP (BSSID) and client
            supp, authr = (p.eth_dst, p.eth_src) if p.eth_src == w.get("bssid") else (p.eth_src, p.eth_dst)
        elif e.get("code") == "Response" or d["type"] != "EAP-Packet":   # sent by the supplicant
            supp, authr = p.eth_src, p.eth_dst
        else:                                                            # Request/Success/Failure: authenticator
            supp, authr = p.eth_dst, p.eth_src
        # wired 802.1X addresses the PAE group MAC (01:80:c2:00:00:03) instead of the peer
        supp = None if _group(supp) else supp
        authr = None if _group(authr) else authr
        if supp is None:
            supp = last_by_auth.get(authr) or last_real or f"unknown ({authr or '?'})"
        else:
            last_real = supp
            placeholder = next((k for k in sess if k.startswith("unknown")), None)
            if supp not in sess and placeholder:          # adopt the session the authenticator started
                sess[supp] = sess.pop(placeholder)
                sess[supp]["supplicant"] = supp
        if authr and not supp.startswith("unknown"):
            last_by_auth[authr] = supp
        s = sess.setdefault(supp, {"supplicant": supp, "authenticator": authr, "identity": None,
                                   "methods": [], "naks": [], "outcome": None, "first_no": p.no, "ts": p.ts,
                                   "last_ts": p.ts, "wireless": bool(w), "packets": [], "key_msgs": 0})
        s["authenticator"] = s["authenticator"] or authr
        s["last_ts"] = p.ts
        s["packets"].append(p.no)
        if d["type"] == "EAPOL-Key":
            s["key_msgs"] += 1
        if e.get("identity") and e["code"] == "Response":
            s["identity"] = e["identity"]
        if e.get("method") and e["method"] not in ("Identity", "NAK") and e["method"] not in s["methods"]:
            s["methods"].append(e["method"])
        if e.get("method") == "NAK":
            s["naks"].append(e.get("desired"))
        if e.get("code") in ("Success", "Failure"):
            s["outcome"] = e["code"]
    if not sess:
        return
    ss = list(sess.values())
    F.append(make("dot1x_sessions", f"{len(ss)} 802.1X {'wireless' if ss[0]['wireless'] else 'wired'} session(s): " + "; ".join(
        f"{s['identity'] or s['supplicant']} via {'/'.join(s['methods']) or '?'} → {s['outcome'] or 'no result in capture'} "
        f"({(s['last_ts'] - s['ts']) * 1000:.0f} ms)"
        + (f", {s['key_msgs']}-message WPA key handshake" if s["key_msgs"] else "") for s in ss[:6]) + ".",
        entities=[s["identity"] or s["supplicant"] for s in ss], ts=ss[0]["ts"], packets=[s["first_no"] for s in ss][:10],
        details={"sessions": [{k: v for k, v in s.items() if k != "packets"} for s in ss]}))
    failed = [s for s in ss if s["outcome"] == "Failure"]
    if failed:
        F.append(make("dot1x_failure", f"802.1X authentication FAILED for " +
                      ", ".join(f"{s['identity'] or s['supplicant']} ({'/'.join(s['methods']) or '?'})" for s in failed) + ".",
                      entities=[s["identity"] or s["supplicant"] for s in failed], ts=failed[0]["ts"],
                      packets=[n for s in failed for n in s["packets"][-2:]]))
    stuck = [s for s in ss if not s["outcome"] and len(s["packets"]) >= 2]
    if stuck:
        F.append(make("dot1x_incomplete", f"{len(stuck)} 802.1X exchange(s) never reached EAP-Success/Failure: " +
                      ", ".join(f"{s['identity'] or s['supplicant']} (last step {len(s['packets'])} packets in)" for s in stuck[:5]) + ".",
                      entities=[s["supplicant"] for s in stuck], ts=stuck[0]["ts"],
                      packets=[s["packets"][-1] for s in stuck][:10]))
    weak = [(s, m) for s in ss for m in s["methods"] if m in WEAK_METHODS]
    if weak:
        F.append(make("dot1x_weak_method", "Weak EAP method in use: " + "; ".join(
            f"{s['identity'] or s['supplicant']} uses {m} ({WEAK_METHODS[m]})" for s, m in weak[:4]) + ".",
            entities=sorted({s["supplicant"] for s, _ in weak}), ts=weak[0][0]["ts"]))
    naks = [s for s in ss if s["naks"]]
    if naks:
        F.append(make("dot1x_method_nak", "Supplicant rejected the method offered by the server (EAP-NAK): " + "; ".join(
            f"{s['identity'] or s['supplicant']} wants {', '.join(x for n in s['naks'] for x in (n or []))}" for s in naks[:4]) + ".",
            entities=[s["supplicant"] for s in naks], ts=naks[0]["ts"]))


def _group(mac: str | None) -> bool:
    return bool(mac) and int(mac[:2], 16) & 1 == 1


def _radius(ctx) -> None:
    F = ctx.findings
    pending: dict = {}
    txs = []
    for p in ctx.packets:
        d = p.layers.get("radius")
        if not d:
            continue
        if d["code_num"] in (1, 4, 12, 40, 43):
            t = {"no": p.no, "ts": p.ts, "nas": p.src, "server": p.dst, "id": d["id"], "code": d["code"],
                 "user": d.get("user"), "calling_station": d.get("calling_station"), "response": None, "time_ms": None,
                 "reply_message": None}
            pending[(p.src, p.sport, p.dst, d["id"])] = t
            txs.append(t)
        else:
            t = pending.pop((p.dst, p.dport, p.src, d["id"]), None)
            if t:
                t.update(response=d["code"], time_ms=round((p.ts - t["ts"]) * 1000, 3), response_no=p.no,
                         reply_message=d.get("reply_message"))
    if not txs:
        return
    ctx.routing["radius"] = txs[:500]
    auths = [t for t in txs if t["code"] == "Access-Request"]
    F.append(make("radius_summary", f"{len(txs)} RADIUS request(s) from NAS {', '.join(sorted({t['nas'] for t in txs}))} to "
                                    f"{', '.join(sorted({t['server'] for t in txs}))}: "
                                    + ", ".join(f"{k} {v}" for k, v in Counter(t["response"] or "no response" for t in auths).items())
                                    + (f"; {len(txs) - len(auths)} accounting/other" if len(txs) > len(auths) else "") + ".",
                  ts=txs[0]["ts"], entities=sorted({t["server"] for t in txs})))
    rej = [t for t in txs if t["response"] == "Access-Reject"]
    if rej:
        F.append(make("radius_reject", f"{len(rej)} Access-Reject(s): " + "; ".join(
            f"{t['user'] or t['calling_station'] or '?'}" + (f" ('{t['reply_message']}')" if t["reply_message"] else "")
            for t in rej[:5]) + ".", packets=[t["response_no"] for t in rej[:10]], ts=rej[0]["ts"],
            entities=sorted({t["user"] or "?" for t in rej})))
    lost = [t for t in txs if t["response"] is None]
    if lost:
        F.append(make("radius_no_response", f"{len(lost)} RADIUS request(s) to {', '.join(sorted({t['server'] for t in lost}))} "
                                            "were never answered.", packets=[t["no"] for t in lost[:10]], ts=lost[0]["ts"],
                      entities=sorted({t["server"] for t in lost})))
    slow = [t for t in txs if t["time_ms"] and t["time_ms"] > 1000]
    if slow:
        F.append(make("radius_slow", f"{len(slow)} RADIUS response(s) slower than 1 s (worst "
                                     f"{max(t['time_ms'] for t in slow) / 1000:.1f} s).", ts=slow[0]["ts"],
                      packets=[t["no"] for t in slow[:10]]))
