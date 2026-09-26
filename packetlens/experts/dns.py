"""DNS expert: transaction matching, latency, failures, tunneling indicators."""
from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict

from ..knowledge import make


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local or a.is_multicast or a.is_loopback
    except ValueError:
        return True


def run(ctx) -> None:
    F = ctx.findings
    pending: dict[tuple, list] = defaultdict(list)
    tx: list[dict] = []
    for p in ctx.packets:
        d = p.layers.get("dns")
        if not d or p.protocol == "MDNS":
            continue
        if not d["qr"]:
            key = (p.src, p.sport, p.dst, d["id"], d["qname"])
            if pending[key]:
                pending[key][-1]["retries"] += 1
                continue
            t = {"query_no": p.no, "ts": p.ts, "t": p.rel_ts, "client": p.src, "server": p.dst, "id": d["id"],
                 "qname": d["qname"], "qtype": d["qtype"], "retries": 0, "response_no": None,
                 "rcode": None, "time_ms": None, "answers": [], "tc": False}
            pending[key].append(t)
            tx.append(t)
        else:
            key = (p.dst, p.dport, p.src, d["id"], d["qname"])
            if pending.get(key):
                t = pending[key].pop(0)
                t.update(response_no=p.no, rcode=d["rcode_name"], time_ms=round((p.ts - t["ts"]) * 1000, 3),
                         answers=[f"{a['type']} {a['data']}" for a in d["answers"]][:10], tc=d["tc"],
                         answer_count=len(d["answers"]))
                for a in d["answers"]:
                    if a["type"] in ("A", "AAAA"):
                        ctx.dns_names.setdefault(a["data"], set()).add(d["qname"])
    ctx.dns_transactions = tx
    if not tx:
        return

    def emit(fid, items, text, **kw):
        if items:
            F.append(make(fid, text, packets=[t["query_no"] for t in items[:20]], count=len(items),
                          ts=items[0]["ts"], entities=sorted({t["qname"] for t in items})[:15], **kw))

    noresp = [t for t in tx if t["response_no"] is None]
    emit("dns_no_response", noresp,
         f"{len(noresp)} of {len(tx)} DNS queries never received a response "
         f"(servers: {', '.join(sorted({t['server'] for t in noresp})[:5])}; "
         f"{sum(t['retries'] for t in noresp)} client retries). Names: {', '.join(sorted({t['qname'] for t in noresp})[:5])}.",
         details={"servers": sorted({t["server"] for t in noresp})})
    answered = [t for t in tx if t["time_ms"] is not None]
    slow = [t for t in answered if t["time_ms"] > 50]
    if slow:
        worst = max(slow, key=lambda t: t["time_ms"])
        emit("dns_slow", sorted(slow, key=lambda t: -t["time_ms"]),
             f"{len(slow)} of {len(answered)} DNS responses slower than 50 ms; worst {worst['time_ms']:.0f} ms "
             f"for {worst['qname']} via {worst['server']}. Median DNS time "
             f"{sorted(t['time_ms'] for t in answered)[len(answered) // 2]:.1f} ms.",
             severity="high" if worst["time_ms"] > 1000 else "medium" if worst["time_ms"] > 200 else "low")
    for rc, fid in (("NXDOMAIN", "dns_nxdomain"), ("SERVFAIL", "dns_servfail"), ("REFUSED", "dns_refused")):
        items = [t for t in answered if t["rcode"] == rc]
        emit(fid, items, f"{len(items)} {rc} responses for: {', '.join(sorted({t['qname'] for t in items})[:8])} "
                         f"(resolver(s) {', '.join(sorted({t['server'] for t in items}))}).",
             severity=("medium" if fid == "dns_nxdomain" and len(items) > 20 else None))
    emit("dns_truncated", [t for t in answered if t["tc"]], "Truncated DNS responses — clients must retry over TCP.")
    emit("dns_high_answer_count", [t for t in answered if t.get("answer_count", 0) > 5],
         "Responses with more than 5 answers (Chris Greer 'High DNS Count' rule).")
    sus = []
    for t in tx:
        first = t["qname"].split(".")[0]
        if len(t["qname"]) > 60 or (len(first) >= 20 and entropy(first) > 3.8) or t["qtype"] == "TXT" and len(first) > 30:
            sus.append(t)
    per_domain = Counter(".".join(t["qname"].split(".")[-2:]) for t in tx)
    heavy = {d: n for d, n in per_domain.items() if n > 100 and len({t["qname"] for t in tx if t["qname"].endswith(d)}) > 50}
    if sus or heavy:
        emit("dns_suspicious_names", sus or [t for t in tx if any(t["qname"].endswith(d) for d in heavy)],
             f"{len(sus)} long/high-entropy query names" + (f"; domains with very many unique sub-names: {', '.join(heavy)}" if heavy else "")
             + ". Possible DNS tunneling or DGA.")
    ext = [t for t in tx if not _private(t["server"]) and _private(t["client"])]
    if ext:
        emit("dns_non_local_resolver", ext,
             f"{len({t['client'] for t in ext})} internal host(s) querying external resolver(s) "
             f"{', '.join(sorted({t['server'] for t in ext})[:5])} directly.")
