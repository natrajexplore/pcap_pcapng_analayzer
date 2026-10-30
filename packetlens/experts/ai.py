"""AI / LLM traffic expert.

Recognises generative-AI services from every name the capture offers (TLS SNI, QUIC SNI, DNS answers, HTTP
Host, certificate CN/SAN) plus API request shapes (OpenAI-compatible, Anthropic, Gemini, Bedrock, Ollama,
KServe, gRPC inference) and MCP (Model Context Protocol) JSON-RPC. For each flow it measures upload volume and
the streaming profile even when the traffic is encrypted: time to first token (first response burst after the
request) and mid-stream stalls. Findings: AI services in use, consumer assistants (shadow AI), large uploads,
API keys over cleartext HTTP, unauthenticated self-hosted model servers, slow first token, stalls, rate limits.
"""
from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from ..knowledge import make
from ..protocols import ai

UPLOAD_LIMIT = 1_000_000
TTFT_SLOW = 5.0
STALL = 5.0
_TOOL = re.compile(r'"name"\s*:\s*"([^"]{1,80})"')


def _private(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def run(ctx) -> None:
    streams = {s.id: s for s in ctx.flows.streams}
    flows: dict = {}                       # key: ("tcp", stream) | ("quic", client, server)

    def add(key, provider, category, evidence, name, client, server, no, ts):
        f = flows.get(key)
        if f is None:
            f = flows[key] = {"provider": provider, "category": category, "evidence": [], "name": name, "client": client,
                              "server": server, "no": no, "t": round(ts - ctx.t0, 6), "api": set(), "transport": key[0],
                              "stream": key[1] if key[0] == "tcp" else None, "notes": []}
        if evidence not in f["evidence"]:
            f["evidence"].append(evidence)
        return f

    for h in ctx.tls_sessions:
        m = ai.match(h["sni"])
        if m:
            add(("tcp", h["stream"]), *m, "TLS SNI", h["sni"], h["client"], h["server"], h["no"], h["ts"])
    for c in getattr(ctx, "certificates", []):
        names = [c.get("cn")] + list(c.get("san") or [])
        m = next((ai.match(n) for n in names if ai.match(n)), None)
        if m and c.get("role") == "leaf":
            for s in ctx.flows.streams:
                if f"{s.server}:{s.sport}" == c.get("server"):
                    add(("tcp", s.id), *m, "certificate", c["cn"], s.client, c["server"], c["no"], c["ts"])
    for q in getattr(ctx, "quic_sessions", []):
        names = [q.get("sni")] + sorted(ctx.dns_names.get(q["server_ip"], []))
        for n in names:
            m = ai.match(n)
            if m:
                f = add(("quic", q["client"], q["server"]), *m, "QUIC SNI" if n == q.get("sni") else "DNS", n, q["client"], q["server"],
                        q["no"], q["ts"])
                f.update(up=q["c_bytes"], down=q["s_bytes"], packets=q["c_pkts"] + q["s_pkts"], duration=q["duration"])
                break
    for s in ctx.flows.streams:                # names learned from DNS for streams without a matching SNI
        if ("tcp", s.id) in flows:
            continue
        for n in sorted(ctx.dns_names.get(s.server, [])):
            m = ai.match(n)
            if m:
                add(("tcp", s.id), *m, "DNS", n, s.client, f"{s.server}:{s.sport}", s.first_no, s.first_ts)
                break
    mcp: list = []
    for t in ctx.http_transactions:
        kind = ai.api_kind(t["uri"])
        m = ai.match(t.get("host") or "")
        method = ai.mcp_method(t.get("body"))
        req = ctx.pkt(t["no"])
        hdrs = ((req.layers.get("http") or {}).get("headers") or {}) if req else {}
        if method or t["uri"].rstrip("/").endswith(("/mcp", "/sse")):
            tool = _TOOL.search(t.get("body") or "") if method == "tools/call" else None
            mcp.append({"no": t["no"], "t": t["t"], "client": t["client"], "server": t["server"], "method": method or "(transport)",
                        "tool": tool.group(1) if tool else None, "tls": t.get("tls"), "url": t["url"], "status": t["status"],
                        "content_type": t.get("content_type")})
        if not (m or kind):
            continue
        if m is None:
            port = int(t["server"].rsplit(":", 1)[1])
            m = (f"Self-hosted ({ai.LOCAL_PORTS.get(port) or 'OpenAI-compatible'})", "Local inference")
        f = add(("tcp", t["stream"]), *m, "HTTP", t.get("host") or t["server"], t["client"], t["server"], t["no"], t["ts"])
        if kind:
            f["api"].add(kind)
        f.setdefault("http", []).append({"no": t["no"], "method": t["method"], "uri": t["uri"][:120], "status": t["status"],
                                        "tls": t.get("tls"), "auth": bool(t["auth"] or "x-api-key" in hdrs or "api-key" in hdrs),
                                        "content_type": t.get("content_type"), "time_ms": t["time_ms"]})
    for t in ctx.http_transactions:            # gRPC inference services (HTTP/2 with hpack)
        eng = ai.grpc_inference(t.get("uri")) if t.get("grpc") else None
        if eng:
            f = add(("tcp", t["stream"]), f"{eng} (gRPC)", "Local inference" if _private(t["server"].rsplit(":", 1)[0]) else "Inference platform",
                    "gRPC", t["uri"], t["client"], t["server"], t["no"], t["ts"])
            f["api"].add(t["uri"].lstrip("/"))
    _profile(ctx, flows, streams)
    out = sorted(flows.values(), key=lambda f: f["t"])
    for f in out:
        f["api"] = sorted(f["api"])
    ctx.ai = {"flows": out[:1000], "mcp": mcp[:500], "providers": _providers(out), "clients": _clients(out)}
    _findings(ctx, out, mcp)


def _profile(ctx, flows, streams):
    """Upload volume and streaming profile per TCP flow from packet timing (works on encrypted traffic)."""
    want = {f["stream"]: f for f in flows.values() if f["transport"] == "tcp"}
    pk = defaultdict(list)
    for p in ctx.packets:
        if p.tcp is not None and p.tcp.stream in want and p.tcp.payload_len:
            pk[p.tcp.stream].append(p)
    for sid, f in want.items():
        st = streams[sid]
        f.update(up=st.c.payload_bytes, down=st.s.payload_bytes, packets=st.c.packets + st.s.packets,
                 duration=round(st.duration, 6))
        bursts = []
        for p in pk[sid]:
            side = "c" if p.src == st.client and p.sport == st.cport else "s"
            if bursts and bursts[-1][0] == side:
                bursts[-1][1].append(p)
            else:
                bursts.append((side, [p]))
        exchanges = []
        for (s1, req), (s2, resp) in zip(bursts, bursts[1:]):
            if s1 != "c" or s2 != "s":
                continue
            hello = any("server_hello" in (p.layers.get("tls") or {}) for p in resp)
            app = any(any(r["type"] == 23 for r in (p.layers.get("tls") or {}).get("records", [])) for p in req) or \
                any((p.layers.get("http") or {}).get("type") == "request" or "http2" in p.layers for p in req)
            if hello or not app:
                continue
            gaps = [b.ts - a.ts for a, b in zip(resp, resp[1:])]
            exchanges.append({"request_no": req[-1].no, "first_no": resp[0].no, "ttft_s": round(resp[0].ts - req[-1].ts, 4),
                              "gen_s": round(resp[-1].ts - resp[0].ts, 4), "chunks": len(resp),
                              "max_gap_s": round(max(gaps), 4) if gaps else 0.0,
                              "max_gap_no": resp[gaps.index(max(gaps)) + 1].no if gaps else None,
                              "up": sum(p.tcp.payload_len for p in req), "down": sum(p.tcp.payload_len for p in resp)})
        stream_ex = [e for e in exchanges if e["chunks"] >= 8 and e["gen_s"] >= 0.5]
        f["exchanges"] = exchanges[:50]
        f["streaming"] = bool(stream_ex)
        if exchanges:
            f["ttft_s"] = max(e["ttft_s"] for e in exchanges)
            f["max_gap_s"] = max(e["max_gap_s"] for e in exchanges)


def _providers(flows):
    out: dict = {}
    for f in flows:
        p = out.setdefault(f["provider"], {"provider": f["provider"], "category": f["category"], "flows": 0, "clients": set(),
                                           "up": 0, "down": 0, "streaming": 0, "names": set()})
        p["flows"] += 1
        p["clients"].add(f["client"])
        p["up"] += f.get("up") or 0
        p["down"] += f.get("down") or 0
        p["streaming"] += bool(f.get("streaming"))
        p["names"].add(f["name"])
    return sorted(({**p, "clients": sorted(p["clients"]), "names": sorted(p["names"])[:10]} for p in out.values()),
                  key=lambda p: -(p["up"] + p["down"]))


def _clients(flows):
    out: dict = {}
    for f in flows:
        c = out.setdefault(f["client"], {"client": f["client"], "providers": set(), "up": 0, "down": 0, "flows": 0})
        c["providers"].add(f["provider"])
        c["up"] += f.get("up") or 0
        c["down"] += f.get("down") or 0
        c["flows"] += 1
    return sorted(({**c, "providers": sorted(c["providers"])} for c in out.values()), key=lambda c: -c["up"])


def _findings(ctx, flows, mcp):
    F = ctx.findings

    def emit(fid, items, text, **kw):
        if items:
            F.append(make(fid, text, packets=[i["no"] for i in items[:20]], ts=min(ctx.t0 + i["t"] for i in items), count=len(items),
                          entities=sorted({i.get("name") or i.get("server") for i in items})[:15], **kw))

    if flows:
        prov = ctx.ai["providers"]
        emit("ai_service_usage", flows, f"{len(flows)} flow(s) to {len(prov)} AI service(s) from {len(ctx.ai['clients'])} client(s): " +
             "; ".join(f"{p['provider']} ({p['category']}, {len(p['clients'])} client(s), ↑{p['up']:,} B ↓{p['down']:,} B)" for p in prov[:6]))
    consumer = [f for f in flows if f["category"] == "Chat assistant"]
    emit("ai_consumer_assistant", consumer, "Consumer AI chat assistants in use: " + "; ".join(
        f"{c} → {', '.join(sorted({f['provider'] for f in consumer if f['client'] == c}))}" for c in sorted({f["client"] for f in consumer})[:8]))
    big = [f for f in flows if (f.get("up") or 0) >= UPLOAD_LIMIT]
    emit("ai_large_upload", big, "; ".join(f"{f['client']} sent {f['up']:,} bytes to {f['provider']} ({f['name']})" for f in big[:5]),
         severity="high" if any(f["up"] >= 10 * UPLOAD_LIMIT for f in big) else None)
    clear = [dict(f, no=h["no"]) for f in flows for h in f.get("http", [])      # loopback-only traffic never leaves the host
             if not h["tls"] and h["auth"] and f["client"] != f["server"].rsplit(":", 1)[0]]
    emit("ai_cleartext_api", clear, "; ".join(f"{f['client']} → {f['server']} {f['provider']}: API key / bearer token sent over plain HTTP"
                                              for f in clear[:5]))
    local = [f for f in flows if f["category"] == "Local inference" and any(not h["tls"] and not h["auth"] for h in f.get("http", []))]
    by_srv = defaultdict(set)
    for f in local:
        by_srv[f["server"]].add(f["client"])
    emit("ai_unauth_local_inference", local, "; ".join(f"{srv} ({next(f['provider'] for f in local if f['server'] == srv)}) "
                                                       f"answered {len(cl)} client(s) without authentication: {', '.join(sorted(cl)[:5])}"
                                                       for srv, cl in by_srv.items()))
    slow = [dict(f, no=next(e["first_no"] for e in f["exchanges"] if e["ttft_s"] == f["ttft_s"])) for f in flows
            if f.get("ttft_s", 0) >= TTFT_SLOW]
    emit("ai_slow_first_token", slow, "; ".join(f"{f['client']} → {f['provider']} ({f['name']}): first response "
                                                f"{f['ttft_s']:.1f}s after the request" for f in slow[:5]))
    stall = [dict(f, no=next(e["max_gap_no"] for e in f["exchanges"] if e["max_gap_s"] == f["max_gap_s"])) for f in flows
             if f.get("streaming") and f.get("max_gap_s", 0) >= STALL]
    emit("ai_stream_stall", stall, "; ".join(f"{f['client']} ← {f['provider']} ({f['name']}): stream paused "
                                             f"{f['max_gap_s']:.1f}s mid-response" for f in stall[:5]))
    limited = [dict(f, no=h["no"]) for f in flows for h in f.get("http", []) if h["status"] in (429, 503, 529)]
    emit("ai_rate_limited", limited, "; ".join(f"{f['client']} → {f['provider']}: HTTP {h['status']} on {h['uri']}"
                                               for f in flows for h in f.get("http", []) if h["status"] in (429, 503, 529))[:600])
    if mcp:
        tools = sorted({m["tool"] for m in mcp if m["tool"]})
        clear_mcp = [m for m in mcp if not m["tls"] and m["client"] != m["server"].rsplit(":", 1)[0]]
        F.append(make("mcp_traffic", f"{len(mcp)} Model Context Protocol message(s) between "
                      f"{len({(m['client'], m['server']) for m in mcp})} client/server pair(s); methods: "
                      f"{', '.join(sorted({m['method'] for m in mcp}))}" + (f"; tools called: {', '.join(tools[:10])}" if tools else "")
                      + (f"; {len(clear_mcp)} over cleartext HTTP" if clear_mcp else ""),
                      packets=[m["no"] for m in mcp[:20]], ts=ctx.t0 + mcp[0]["t"], count=len(mcp),
                      entities=sorted({m["server"] for m in mcp})[:15], severity="medium" if clear_mcp else None))
