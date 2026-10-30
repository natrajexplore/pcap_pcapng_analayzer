"""QUIC expert: decrypts Initial packets per connection (RFC 9001 5.2 keys come from the client's first DCID),
reassembles the CRYPTO stream and recovers the TLS ClientHello / ServerHello (SNI, ALPN, key-share groups),
and flags QUIC that never gets an answer (UDP/443 blocked, browsers fall back to TCP) and version negotiation."""
from __future__ import annotations

from ..knowledge import make
from ..protocols import quic, tls


def _hello(chunks: dict, want: int):
    """Contiguous CRYPTO bytes from offset 0 -> the first handshake message of type ``want``."""
    buf, pos = bytearray(), 0
    for off in sorted(chunks):
        if off > pos:
            break
        buf += chunks[off][pos - off:]
        pos = max(pos, off + len(chunks[off]))
    if len(buf) < 4 or buf[0] != want:
        return None
    ln = int.from_bytes(buf[1:4], "big")
    if len(buf) < 4 + ln:
        return None
    body = bytes(buf[4:4 + ln])
    try:
        return tls._client_hello(body) if want == 1 else tls._server_hello(body)
    except (IndexError, ValueError):
        return None


def run(ctx) -> None:
    conns: dict = {}
    vn = []
    for p in ctx.packets:
        d = p.layers.get("quic")
        if not d or p.sport is None:
            continue
        fwd, rev = (p.src, p.sport, p.dst, p.dport), (p.dst, p.dport, p.src, p.sport)
        c = conns.get(fwd) or conns.get(rev)
        if c is None:
            if d.get("type") != "Initial":
                d.pop("raw", None)
                continue
            c = conns[fwd] = {"key": fwd, "client": p.src, "server": f"{p.dst}:{p.dport}", "server_ip": p.dst, "odcid": bytes.fromhex(d["dcid"]),
                              "version": d["version_name"], "no": p.no, "ts": p.ts, "t": round(p.rel_ts, 6),
                              "c_pkts": 0, "s_pkts": 0, "c_bytes": 0, "s_bytes": 0, "c_initials": [], "s_initials": [],
                              "crypto": {False: {}, True: {}}, "retry": False, "first_pkt": p, "last_ts": p.ts}
        server = (p.src, p.sport) != (c["key"][0], c["key"][1])
        c["s_pkts" if server else "c_pkts"] += 1
        c["s_bytes" if server else "c_bytes"] += p.wirelen
        c["last_ts"] = p.ts
        if d.get("type") == "Version Negotiation":
            vn.append((p, d))
        elif d.get("type") == "Retry":
            c["retry"] = True
        raw = d.pop("raw", None)
        if d.get("type") != "Initial":
            continue
        (c["s_initials"] if server else c["c_initials"]).append(p.no)
        if not server and c["retry"] and bytes.fromhex(d["dcid"]) != c["odcid"]:
            c["odcid"], c["retry"] = bytes.fromhex(d["dcid"]), False       # after Retry the keys follow the new DCID
        plain = quic.decrypt_initial(raw, c["odcid"], server) if raw else None
        if plain:
            d["decrypted"] = True
            for off, data in quic.crypto_frames(plain):
                c["crypto"][server].setdefault(off, data)
    sessions = []
    for c in conns.values():
        ch = _hello(c["crypto"][False], 1)
        sh = _hello(c["crypto"][True], 2)
        first = c.pop("first_pkt")
        if ch:
            q = first.layers["quic"]
            q["client_hello"], q["sni"] = ch, ch["sni"]
            first.info = quic.info(q)
        c.pop("crypto")
        c.update(sni=ch["sni"] if ch else None, alpn=ch["alpn"] if ch else [], client_hello=ch, server_hello=sh,
                 decrypted=bool(ch or sh), answered=c["s_pkts"] > 0, duration=round(c["last_ts"] - c["ts"], 6))
        sessions.append(c)
    ctx.quic_sessions = sessions
    if sessions and not quic.HAVE_CRYPTO:
        ctx.warnings.append("QUIC Initial packets found: install the optional 'cryptography' package to decode their "
                            "SNI, ALPN and post-quantum key shares (pip install cryptography).")
    F = ctx.findings
    blocked = [c for c in sessions if not c["answered"] and len(c["c_initials"]) >= 2]
    if blocked:
        tcp_after = {(s.client, s.server) for s in ctx.flows.streams if s.sport == 443}
        F.append(make("quic_blocked", f"{len(blocked)} QUIC connection(s) never got an answer: " + "; ".join(
            f"{c['client']} → {c['sni'] or c['server']} ({len(c['c_initials'])} Initials"
            + (", then fell back to TCP/TLS" if (c["client"], c["server_ip"]) in tcp_after else "") + ")" for c in blocked[:5]),
            packets=[n for c in blocked[:10] for n in c["c_initials"][:3]], ts=blocked[0]["ts"], count=len(blocked),
            entities=sorted({c["sni"] or c["server"] for c in blocked})[:15]))
    if vn:
        F.append(make("quic_version_negotiation", "; ".join(
            f"{p.src} → {p.dst}: server supports {', '.join(d['supported'])}" for p, d in vn[:5]),
            packets=[p.no for p, _ in vn[:20]], ts=vn[0][0].ts, count=len(vn)))
