"""Threat-hunting expert, modelled on Chris Greer's ThreatHunt Wireshark profile."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make

CLEARTEXT = {21: "FTP", 23: "Telnet", 110: "POP3", 143: "IMAP", 513: "rlogin", 514: "rsh"}
SUSPICIOUS_PORTS = {1337, 4444, 31337, 6667, 12345, 5555}
MZ_STUB = b"This program cannot be run in DOS mode"


def _scan_stats(ctx):
    per_src = defaultdict(lambda: defaultdict(set))
    incomplete = defaultdict(int)
    for s in ctx.flows.streams:
        per_src[s.client][s.server].add(s.sport)
        if s.completeness in (1, 3, 33, 35, 37, 7 | 32):
            incomplete[s.client] += 1
    return per_src, incomplete


def detect_scanners(ctx) -> set:
    """Sources probing many ports with mostly half-open/refused connections."""
    per_src, incomplete = _scan_stats(ctx)
    return {src for src, targets in per_src.items()
            if len({p for ps in targets.values() for p in ps}) >= 15 and incomplete[src] >= 10}


def run(ctx) -> None:
    F = ctx.findings
    # ---- port scans: one source, many destination ports, mostly incomplete handshakes
    per_src, incomplete = _scan_stats(ctx)
    for src, targets in per_src.items():
        ports = {p for ps in targets.values() for p in ps}
        if src in ctx.scanners:
            open_ports = sorted({s.sport for s in ctx.flows.streams if s.client == src and s.synack_count})
            F.append(make("sec_port_scan",
                          f"{src} probed {len(ports)} ports on {len(targets)} host(s); {incomplete[src]} half-open/refused connections. "
                          f"Ports that answered SYN-ACK (open): {', '.join(map(str, open_ports[:20])) or 'none'}.",
                          entities=[src] + list(targets)[:10], ts=min(s.first_ts for s in ctx.flows.streams if s.client == src),
                          details={"scanner": src, "targets": list(targets), "open_ports": open_ports,
                                   "ports_probed": len(ports)}))
    # ---- crafted packet signatures
    sig = defaultdict(list)
    for p in ctx.packets:
        for t in p.tags:
            sig[t].append(p)
    nmap = sig["nmap_syn_lowwin"] + sig["null_scan"] + sig["xmas_scan"]
    if nmap:
        kinds = [k for k in ("nmap_syn_lowwin", "null_scan", "xmas_scan", "syn_no_options") if sig[k]]
        F.append(make("sec_nmap_signature", f"Crafted scan packets: {', '.join(f'{k} ×{len(sig[k])}' for k in kinds)} "
                                            f"from {', '.join(sorted({p.src for p in nmap})[:5])}.",
                      packets=[p.no for p in nmap[:20]], ts=nmap[0].ts, entities=sorted({p.src for p in nmap})))
    # ---- cleartext and suspicious ports / payload signatures
    clear = defaultdict(set)
    susp = defaultdict(set)
    mz, jndi = [], []
    for s in ctx.flows.streams:
        if s.sport in CLEARTEXT and s.completeness & 8:
            clear[CLEARTEXT[s.sport]].add(f"{s.client} → {s.server}")
        if (s.sport in SUSPICIOUS_PORTS or s.cport in SUSPICIOUS_PORTS) and s.completeness & 2:
            susp[s.sport if s.sport in SUSPICIOUS_PORTS else s.cport].add(f"{s.client}:{s.cport} → {s.server}:{s.sport}")
    for p in ctx.packets:
        if p.payload:
            if MZ_STUB in p.payload:
                mz.append(p)
            if b"${jndi:" in p.payload.lower():
                jndi.append(p)
    if clear:
        F.append(make("sec_cleartext_protocol", "Cleartext protocols in use: " +
                      "; ".join(f"{k}: {', '.join(sorted(v)[:3])}" for k, v in clear.items())))
    if susp:
        F.append(make("sec_suspicious_port", "Connections on commonly abused ports: " +
                      "; ".join(f"{k}: {', '.join(sorted(v)[:3])}" for k, v in susp.items())))
    if mz:
        F.append(make("sec_executable", f"{len(mz)} packet(s) contain a PE/MZ DOS-stub ({', '.join(sorted({f'{p.src}→{p.dst}' for p in mz})[:3])}).",
                      packets=[p.no for p in mz[:20]], ts=mz[0].ts))
    if jndi:
        F.append(make("sec_log4j", f"{len(jndi)} packet(s) with a '${{jndi:' lookup string from {', '.join(sorted({p.src for p in jndi}))}.",
                      packets=[p.no for p in jndi[:20]], ts=jndi[0].ts))
