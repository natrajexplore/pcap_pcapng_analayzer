"""Analysis pipeline: read → dissect → track flows → expert analysis → correlation."""
from __future__ import annotations

import os
import time
from collections import Counter, defaultdict

from . import __version__
from .correlate import correlate
from .decode import dissect
from .experts import dhcp, dns, network, routing, security, tcp, web
from .findings import SEVERITY_ORDER, sort_findings
from .flows import FlowTracker
from .reader import open_capture

BAD_TCP_IGNORE = {"window_update", "keep_alive", "keep_alive_ack"}
ROUTING_PROTOS = {"OSPF", "EIGRP", "BGP", "RIP", "STP", "VRRP", "PIM", "IGMP"}


def color_rule(p) -> str:
    """Packet colouring, following the order of Chris Greer's TCP/ThreatHunt profiles."""
    t = p.tcp
    if t and set(t.analysis) - BAD_TCP_IGNORE:
        return "bad_tcp"
    if "icmp" in p.layers and (p.layers["icmp"]["type"] in (3, 4, 5, 11) or (p.layers["icmp"]["v6"] and p.layers["icmp"]["type"] < 128)):
        return "icmp_error"
    if p.ip_checksum_ok is False:
        return "checksum"
    if t and t.rst:
        return "rst"
    if t and t.syn:
        return "syn"
    if t and t.fin:
        return "fin"
    if "tls" in p.layers and ("client_hello" in p.layers["tls"] or "server_hello" in p.layers["tls"]):
        return "tls"
    if "http" in p.layers:
        return "http"
    if "dns" in p.layers:
        rc = p.layers["dns"]["rcode"]
        return "dns_error" if p.layers["dns"]["qr"] and rc in (2, 5) else "dns_warn" if rc == 3 else "dns"
    if "arp" in p.layers:
        return "arp"
    if "icmp" in p.layers:
        return "icmp"
    if p.protocol in ROUTING_PROTOS:
        return "routing"
    if p.tcp:
        return "tcp"
    if p.ip_proto == 17:
        return "udp"
    if p.eth_dst and int(p.eth_dst[:2], 16) & 1:
        return "broadcast"
    return "other"


class Analysis:
    """Holds everything learned about one capture."""

    def __init__(self, source: str):
        self.source = source
        self.packets: list = []
        self.flows = FlowTracker()
        self.findings: list = []
        self.root_causes: list = []
        self.warnings: list[str] = []
        self.dns_transactions: list = []
        self.dhcp_transactions: list = []
        self.http_transactions: list = []
        self.tls_sessions: list = []
        self.icmp_events: list = []
        self.urls: list = []
        self.dns_names: dict = {}
        self.arp_table: dict = {}
        self.gateways: set = set()
        self.routing: dict = {}
        self.capture_point = None
        self.scanners: set = set()
        self.t0 = 0.0
        self._by_no: dict = {}
        self.elapsed = 0.0

    def pkt(self, no):
        return self._by_no.get(no)

    # ------------------------------------------------------------------------
    def run(self, frames, max_packets: int | None = None) -> "Analysis":
        start = time.time()
        for i, fr in enumerate(frames, 1):
            if max_packets and i > max_packets:
                self.warnings.append(f"Stopped after {max_packets} packets (--max-packets)")
                break
            p = dissect(i, fr)
            if i == 1:
                self.t0 = p.ts
            p.rel_ts = p.ts - self.t0
            self.flows.add(p)
            self.packets.append(p)
            self._by_no[i] = p
        self.scanners = security.detect_scanners(self)
        sliced = sum(1 for p in self.packets if "sliced" in p.tags)
        if sliced:
            self.warnings.append(f"{sliced} packets were sliced by the capture snaplen; TCP analysis uses IP lengths, "
                                 "but application-layer decoding (HTTP/TLS/DNS over TCP) may be incomplete.")
        for mod in (dhcp, dns, network, tcp, web, routing, security):
            try:
                mod.run(self)
            except Exception as exc:  # an expert failure must not kill the whole report
                self.warnings.append(f"{mod.__name__} failed: {exc!r}")
        self.findings = sort_findings(self.findings)
        for i, f in enumerate(self.findings):
            f.uid = f"F{i + 1:03d}"
        self.root_causes = correlate(self)
        self.elapsed = time.time() - start
        return self

    # ------------------------------------------------------------ summary ---
    def stats(self) -> dict:
        pk = self.packets
        dur = (pk[-1].ts - pk[0].ts) if len(pk) > 1 else 0.0
        total_bytes = sum(p.wirelen for p in pk)
        protos = Counter(p.protocol for p in pk)
        layers = Counter()
        for p in pk:
            if p.eth_src:
                layers["Ethernet"] += 1
            if p.vlan is not None:
                layers["802.1Q VLAN"] += 1
            if p.ip_version:
                layers[f"IPv{p.ip_version}"] += 1
            if p.tcp:
                layers["TCP"] += 1
            elif p.ip_proto == 17:
                layers["UDP"] += 1
            for name in p.layers:
                layers[name.upper()] += 1
        endpoints = defaultdict(lambda: {"tx_pkts": 0, "rx_pkts": 0, "tx_bytes": 0, "rx_bytes": 0, "ttls": set(), "macs": set()})
        for p in pk:
            if p.src:
                e = endpoints[p.src]
                e["tx_pkts"] += 1
                e["tx_bytes"] += p.wirelen
                if p.ttl is not None:
                    e["ttls"].add(p.ttl)
                if p.eth_src:
                    e["macs"].add(p.eth_src)
                r = endpoints[p.dst]
                r["rx_pkts"] += 1
                r["rx_bytes"] += p.wirelen
        from .experts.network import initial_ttl
        eps = []
        for ip, e in endpoints.items():
            ttl = max(e["ttls"]) if e["ttls"] else None
            eps.append({"ip": ip, "tx_pkts": e["tx_pkts"], "rx_pkts": e["rx_pkts"], "tx_bytes": e["tx_bytes"],
                        "rx_bytes": e["rx_bytes"], "ttl": ttl,
                        "hops": (initial_ttl(ttl) - ttl) if ttl is not None else None,
                        "os_guess": {64: "Linux/macOS/Unix", 128: "Windows", 255: "Network device", 32: "Legacy"}.get(initial_ttl(ttl)) if ttl else None,
                        "macs": sorted(e["macs"])[:4], "names": sorted(self.dns_names.get(ip, []))[:5]})
        eps.sort(key=lambda e: -(e["tx_bytes"] + e["rx_bytes"]))
        buckets = max(1, min(120, int(dur) + 1))
        width = dur / buckets if dur else 1
        timeline = [{"t": round(i * width, 3), "pkts": 0, "bytes": 0, "bad": 0} for i in range(buckets)]
        for p in pk:
            i = min(buckets - 1, int(p.rel_ts / width)) if width else 0
            timeline[i]["pkts"] += 1
            timeline[i]["bytes"] += p.wirelen
            if p.tcp and set(p.tcp.analysis) - BAD_TCP_IGNORE or "icmp" in p.layers and p.layers["icmp"]["type"] in (3, 11):
                timeline[i]["bad"] += 1
        sev = Counter(f.severity for f in self.findings)
        return {"packets": len(pk), "bytes": total_bytes, "duration": round(dur, 6),
                "start": pk[0].ts if pk else None, "end": pk[-1].ts if pk else None,
                "avg_pps": round(len(pk) / dur, 2) if dur else len(pk),
                "avg_bps": round(total_bytes * 8 / dur) if dur else 0,
                "protocols": protos.most_common(), "layers": layers.most_common(), "endpoints": eps[:200],
                "tcp_streams": len(self.flows.streams),
                "conversations": len(self.flows.conversations), "timeline": timeline, "severity": dict(sev),
                "health": self.health()}

    def health(self) -> dict:
        """0-100 health score per domain, derived from findings."""
        # each finding removes a fraction of the remaining health (diminishing, never below 0)
        penalty = {"critical": 0.40, "high": 0.22, "medium": 0.10, "low": 0.03, "info": 0.0}
        domains = {"Transport": 100.0, "Network": 100.0, "Routing": 100.0, "Application": 100.0, "Security": 100.0}
        cat_map = {"Transport": "Transport", "Capture": "Transport", "Network": "Network", "Routing": "Routing",
                   "Application": "Application", "Security": "Security"}
        for f in self.findings:
            d = cat_map.get(f.category, "Network")
            domains[d] *= 1 - penalty.get(f.severity, 0)
        domains = {k: round(v) for k, v in domains.items()}
        overall = round(min(domains.values()) * 0.5 + sum(domains.values()) / len(domains) * 0.5)
        return {"overall": overall, **domains}

    def to_dict(self, packet_limit: int = 5000) -> dict:
        streams = [s.to_dict() for s in self.flows.streams]
        return {
            "meta": {"tool": "PacketLens", "version": __version__, "source": os.path.basename(self.source),
                     "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "analysis_seconds": round(self.elapsed, 3),
                     "capture_point": self.capture_point, "warnings": self.warnings},
            "stats": self.stats(),
            "root_causes": [r.to_dict() for r in self.root_causes],
            "findings": [f.to_dict() for f in self.findings],
            "streams": streams,
            "conversations": [c.to_dict() for c in sorted(self.flows.conversations.values(),
                                                          key=lambda c: -(c.bytes_ab + c.bytes_ba))][:500],
            "ip_conversations": [c.to_dict() for c in sorted(self.flows.ip_conversations.values(),
                                                             key=lambda c: -(c.bytes_ab + c.bytes_ba))][:300],
            "dns": self.dns_transactions[:3000],
            "dhcp": self.dhcp_transactions[:1000],
            "http": [{k: v for k, v in t.items() if k != "body"} for t in self.http_transactions[:3000]],
            "tls": self.tls_sessions[:3000],
            "icmp": self.icmp_events[:2000],
            "urls": self.urls[:5000],
            "routing": self.routing,
            "arp": self.arp_table,
            "packets": [self._pkt_row(p) for p in self.packets[:packet_limit]],
            "packets_truncated": len(self.packets) > packet_limit,
        }

    @staticmethod
    def _pkt_row(p) -> dict:
        return {"no": p.no, "t": round(p.rel_ts, 6), "src": p.src or p.eth_src, "dst": p.dst or p.eth_dst,
                "sport": p.sport, "dport": p.dport, "proto": p.protocol, "len": p.wirelen, "ttl": p.ttl,
                "info": p.info[:200], "color": color_rule(p),
                "stream": p.tcp.stream if p.tcp else None,
                "delta": round(p.tcp.time_delta, 6) if p.tcp else None,
                "analysis": p.tcp.analysis if p.tcp else [], "tags": p.tags,
                "win": p.tcp.calc_window if p.tcp else None, "bif": p.tcp.bytes_in_flight if p.tcp else None}


def analyze_file(path: str, max_packets: int | None = None) -> Analysis:
    return Analysis(path).run(open_capture(path), max_packets=max_packets)


def worst_severity(a: Analysis) -> str | None:
    if not a.findings:
        return None
    return min((f.severity for f in a.findings), key=lambda s: SEVERITY_ORDER.get(s, 9))
