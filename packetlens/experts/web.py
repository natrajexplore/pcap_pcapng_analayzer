"""Web expert: HTTP request/response pairing, URL inventory, TLS handshake analysis."""
from __future__ import annotations

import re
from collections import defaultdict

from ..knowledge import make

SUSPICIOUS_UA = re.compile(r"(?i)(nmap|gobuster|sqlmap|nikto|dirbuster|masscan|wfuzz|hydra|zgrab|Mozilla/4\.0)")
FILE_EXT = re.compile(r"(?i)\.(exe|zip|bin|ps1|dll|msi|tar|scr|bat|hta|jar|vbs)(\?|$)")


def run(ctx) -> None:
    F = ctx.findings
    # ------------------------------------------------------------ HTTP ------
    open_reqs: dict[int, list] = defaultdict(list)
    txs = []
    for p in ctx.packets:
        d = p.layers.get("http")
        if not d or not p.tcp:
            continue
        sid = p.tcp.stream
        if d["type"] == "request":
            t = {"no": p.no, "ts": p.ts, "t": round(p.rel_ts, 6), "stream": sid, "client": p.src, "server": f"{p.dst}:{p.dport}",
                 "method": d["method"], "url": d["url"], "uri": d["uri"], "host": d["host"], "version": d["version"],
                 "user_agent": d["user_agent"], "status": None, "reason": None, "time_ms": None, "response_no": None,
                 "auth": "authorization" in d["headers"], "body": d["body_preview"], "content_type": None}
            open_reqs[sid].append(t)
            txs.append(t)
        elif open_reqs.get(sid):
            t = open_reqs[sid].pop(0)
            t.update(status=d["status"], reason=d["reason"], time_ms=round((p.ts - t["ts"]) * 1000, 3),
                     response_no=p.no, content_type=d["content_type"])
    ctx.http_transactions = txs
    for t in txs:
        ctx.urls.append({"url": t["url"], "method": t["method"], "status": t["status"], "time_ms": t["time_ms"], "no": t["no"]})

    def emit(fid, items, text, **kw):
        if items:
            F.append(make(fid, text, packets=[x for t in items[:15] for x in (t["no"], t["response_no"]) if x],
                          entities=sorted({t["url"] for t in items})[:15], ts=items[0]["ts"], count=len(items), **kw))

    s5 = [t for t in txs if t["status"] and t["status"] >= 500]
    emit("http_server_errors", s5, f"{len(s5)} HTTP 5xx responses: " +
         "; ".join(f"{t['status']} {t['reason']} for {t['method']} {t['url']}" for t in s5[:5]))
    s4 = [t for t in txs if t["status"] and 400 <= t["status"] < 500]
    if s4:
        per_client = defaultdict(int)
        for t in s4:
            per_client[t["client"]] += 1
        heavy = {c: n for c, n in per_client.items() if n >= 20}
        emit("http_client_errors", s4, f"{len(s4)} HTTP 4xx responses" +
             (f"; enumeration-like volume from {', '.join(heavy)}" if heavy else "") + ": " +
             "; ".join(f"{t['status']} {t['url']}" for t in s4[:5]), severity="medium" if heavy else None)
    slow = sorted([t for t in txs if t["time_ms"] and t["time_ms"] > 2000], key=lambda t: -t["time_ms"])
    emit("http_slow_response", slow, f"{len(slow)} HTTP responses slower than 2 s; worst {slow[0]['time_ms'] / 1000:.2f} s "
                                     f"for {slow[0]['url']}." if slow else "")
    emit("http_old_version", [t for t in txs if t["version"] == "HTTP/1.0"], "Requests using HTTP/1.0.")
    emit("http_no_user_agent", [t for t in txs if not t["user_agent"]], "HTTP requests without a User-Agent header.")
    sua = [t for t in txs if t["user_agent"] and SUSPICIOUS_UA.search(t["user_agent"])]
    emit("http_suspicious_user_agent", sua, "Suspicious User-Agents: " +
         ", ".join(sorted({f"{t['client']} → '{t['user_agent']}'" for t in sua})[:5]))
    emit("http_file_download", [t for t in txs if FILE_EXT.search(t["uri"])],
         "Executable/archive files requested over cleartext HTTP.")
    creds = [t for t in txs if t["auth"] or re.search(r"(?i)(pass(word|wd)?|pwd)=", t["uri"] + " " + (t["body"] or ""))]
    emit("http_cleartext_credentials", creds, f"{len(creds)} HTTP request(s) carrying credentials in cleartext "
                                             f"(Authorization header or password parameter).")

    # ------------------------------------------------------------ TLS -------
    hellos: dict[int, dict] = {}
    for p in ctx.packets:
        d = p.layers.get("tls")
        if not d or not p.tcp:
            continue
        sid = p.tcp.stream
        if "client_hello" in d:
            ch = d["client_hello"]
            hellos[sid] = {"no": p.no, "ts": p.ts, "t": round(p.rel_ts, 6), "stream": sid, "client": p.src,
                           "server": f"{p.dst}:{p.dport}", "sni": ch["sni"], "offered": ch["max_version"],
                           "offered_num": ch["max_version_num"], "alpn": ch["alpn"], "ja3": ch["ja3"],
                           "known_bad": ch["known_bad"], "weak_offered": ch["weak_ciphers"],
                           "negotiated": None, "negotiated_num": None, "cipher": None, "weak_selected": None,
                           "alert": None, "server_hello_no": None, "handshake_ms": None}
        if "server_hello" in d and sid in hellos:
            sh = d["server_hello"]
            h = hellos[sid]
            h.update(negotiated=sh["version"], negotiated_num=sh["version_num"], cipher=f"0x{sh['cipher']:04x}",
                     weak_selected=sh["weak_cipher"], server_hello_no=p.no, handshake_ms=round((p.ts - h["ts"]) * 1000, 3))
        if "alert" in d and sid in hellos and hellos[sid]["alert"] is None:
            hellos[sid]["alert"] = {**d["alert"], "no": p.no, "from": "client" if p.src == hellos[sid]["client"] else "server"}
    tls_list = list(hellos.values())
    ctx.tls_sessions = tls_list
    if not tls_list:
        return
    for h in tls_list:
        if h["sni"]:
            ctx.urls.append({"url": f"https://{h['sni']}/", "method": "TLS", "status": h["negotiated"], "time_ms": h["handshake_ms"], "no": h["no"]})

    def emit2(fid, items, text, **kw):
        if items:
            F.append(make(fid, text, packets=[h["no"] for h in items[:20]], ts=items[0]["ts"], count=len(items),
                          entities=sorted({h["sni"] or h["server"] for h in items})[:15], **kw))

    old = [h for h in tls_list if (h["negotiated_num"] or h["offered_num"] or 0x0303) < 0x0303]
    emit2("tls_old_version", old, f"{len(old)} TLS session(s) using/offering at most SSLv3/TLS 1.0/1.1: " +
          ", ".join(f"{h['sni'] or h['server']} ({h['negotiated'] or h['offered']})" for h in old[:6]))
    weak = [h for h in tls_list if h["weak_selected"] or h["weak_offered"]]
    emit2("tls_weak_cipher", weak, "Weak cipher suites: " + "; ".join(
        f"{h['sni'] or h['server']}: " + (f"SELECTED {h['weak_selected']}" if h["weak_selected"] else f"offered {', '.join(h['weak_offered'][:3])}")
        for h in weak[:5]), severity="high" if any(h["weak_selected"] for h in weak) else None)
    alerts = [h for h in tls_list if h["alert"] and h["alert"]["code"] != 0]
    emit2("tls_alert", alerts, "TLS alerts: " + "; ".join(
        f"{h['sni'] or h['server']}: {h['alert']['level']} {h['alert']['description']} (from {h['alert']['from']})" for h in alerts[:6]))
    streams = {s.id: s for s in ctx.flows.streams}
    failed = [h for h in tls_list if h["server_hello_no"] is None and not h["alert"]]
    if failed:
        emit2("tls_handshake_failure", failed, f"{len(failed)} ClientHello(s) never answered by a ServerHello: " + "; ".join(
            f"{h['sni'] or h['server']}" + (f" (RST from {streams[h['stream']].rst['from']})" if streams.get(h['stream']) and streams[h['stream']].rst else "")
            for h in failed[:6]))
    bad = [h for h in tls_list if h["known_bad"]]
    emit2("tls_known_bad_ja3", bad, "; ".join(f"{h['client']} → {h['sni'] or h['server']}: JA3 {h['ja3']} = {h['known_bad']}" for h in bad[:5]))
    nosni = [h for h in tls_list if not h["sni"]]
    emit2("tls_missing_sni", nosni, f"{len(nosni)} ClientHello(s) without SNI.")
