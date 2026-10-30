"""Wireshark-style packet workbench: packet list, details, follow stream, statistics and export."""
from __future__ import annotations

import bisect
import io
import os
import tempfile
from collections import OrderedDict, defaultdict

from ..analyzer import Analysis, color_rule
from ..decode import dissect
from ..dfilter import Ctx, compile_filter, protocol_stack
from ..fields import tree
from ..reader import RawFrame, open_capture, write_pcapng

FOLLOW_MAX = 2 * 1024 * 1024
EXPERT = {  # Wireshark expert severities for the per-packet TCP analysis flags
    "retransmission": ("Note", "This frame is a (suspected) retransmission"),
    "fast_retransmission": ("Note", "This frame is a (suspected) fast retransmission"),
    "spurious_retransmission": ("Note", "This frame is a (suspected) spurious retransmission"),
    "out_of_order": ("Warning", "This frame is a (suspected) out-of-order segment"),
    "lost_segment": ("Warning", "Previous segment(s) not captured (common at capture start)"),
    "ack_unseen": ("Warning", "ACKed segment that wasn't captured (common at capture start)"),
    "duplicate_ack": ("Note", "Duplicate ACK"),
    "zero_window": ("Warning", "TCP Zero Window segment"),
    "zero_window_probe": ("Note", "TCP Zero Window Probe"),
    "window_full": ("Warning", "TCP Window Full"),
    "window_update": ("Chat", "TCP window update"),
    "keep_alive": ("Note", "TCP keep-alive segment"),
    "keep_alive_ack": ("Note", "ACK to a TCP keep-alive segment"),
}
SEV_ORDER = ["Error", "Warning", "Note", "Chat"]


class Workbench:
    """Raw frames + filter results per capture (small LRU caches; analyses live in the Library)."""

    def __init__(self, lib):
        self.lib = lib
        self.frames_cache: OrderedDict = OrderedDict()
        self.filter_cache: OrderedDict = OrderedDict()

    # ---------------------------------------------------------------- data --
    def frames(self, key: str) -> list[RawFrame]:
        if key in self.frames_cache:
            self.frames_cache.move_to_end(key)
            return self.frames_cache[key]
        blob = self.lib.blobs.get(key)
        src = io.BytesIO(blob) if blob is not None else str(self.lib.resolve(key))
        frs = list(open_capture(src))
        self.frames_cache[key] = frs
        while len(self.frames_cache) > 6:
            self.frames_cache.popitem(last=False)
        return frs

    def matching(self, key: str, flt: str, marked: frozenset = frozenset()) -> list[int]:
        """Packet numbers matching a display filter (cached per capture + filter + marked set)."""
        ck = (key, flt.strip(), marked if "frame.marked" in flt else frozenset())
        if ck in self.filter_cache:
            self.filter_cache.move_to_end(ck)
            return self.filter_cache[ck]
        fn = compile_filter(flt)
        a: Analysis = self.lib.get(key)
        frs = self.frames(key) if flt.strip() else None
        out = [p.no for p in a.packets
               if fn(Ctx(p, (lambda n=p.no: frs[n - 1].data) if frs else (lambda: b""), p.no in marked))]
        self.filter_cache[ck] = out
        while len(self.filter_cache) > 32:
            self.filter_cache.popitem(last=False)
        return out

    # ---------------------------------------------------------------- views --
    def page(self, key, flt, offset, limit, marked):
        a = self.lib.get(key)
        nos = self.matching(key, flt, marked)
        rows = []
        for no in nos[offset:offset + limit]:
            p = a.pkt(no)
            rows.append({"no": no, "t": round(p.rel_ts, 6), "ts": p.ts, "src": p.src or p.eth_src, "dst": p.dst or p.eth_dst,
                         "proto": p.protocol, "len": p.wirelen, "info": p.info[:240], "color": color_rule(p),
                         "stream": p.tcp.stream if p.tcp else None, "sport": p.sport, "dport": p.dport,
                         "l4": "tcp" if p.tcp else "udp" if p.ip_proto == 17 and p.sport is not None else None})
        return {"total": len(a.packets), "matched": len(nos), "offset": offset, "rows": rows,
                "first_ts": a.packets[0].ts if a.packets else 0}

    def detail(self, key, no):
        a = self.lib.get(key)
        p = a.pkt(no)
        if p is None:
            raise KeyError(f"no packet {no}")
        fr = self.frames(key)[no - 1]
        return {"no": no, "tree": tree(p, fr.data, fr.linktype), "bytes": fr.data.hex(), "linktype": fr.linktype,
                "stream": p.tcp.stream if p.tcp else None}

    def index_of(self, key, flt, no, marked):
        nos = self.matching(key, flt, marked)

        i = bisect.bisect_left(nos, no)
        return {"index": i if i < len(nos) and nos[i] == no else None, "nearest": min(i, max(0, len(nos) - 1))}

    # --------------------------------------------------------- follow stream --
    def follow(self, key, no, proto="tcp"):
        a = self.lib.get(key)
        p = a.pkt(no)
        frs = self.frames(key)
        if proto == "tcp":
            if p is None or p.tcp is None:
                raise ValueError("not a TCP packet")
            sid = p.tcp.stream
            st = a.flows.streams[sid]
            pkts = [x for x in a.packets if x.tcp is not None and x.tcp.stream == sid]
            client = (st.client, st.cport)
            flt = f"tcp.stream eq {sid}"
            is_client = lambda q: (q.src, q.sport) == client  # noqa: E731
            label = (f"{st.client}:{st.cport}", f"{st.server}:{st.sport}")
        else:
            if p is None or p.ip_proto != 17 or p.sport is None:
                raise ValueError("not a UDP packet")
            ends = {(p.src, p.sport), (p.dst, p.dport)}
            pkts = [x for x in a.packets if x.ip_proto == 17 and x.sport is not None and {(x.src, x.sport), (x.dst, x.dport)} == ends]
            client = (pkts[0].src, pkts[0].sport)
            flt = f"ip.addr == {p.src} && ip.addr == {p.dst} && udp.port == {p.sport} && udp.port == {p.dport}"
            is_client = lambda q: (q.src, q.sport) == client  # noqa: E731
            label = (f"{pkts[0].src}:{pkts[0].sport}", f"{pkts[0].dst}:{pkts[0].dport}")
        chunks, total, seen = [], 0, {}
        for q in pkts:
            payload = dissect(q.no, frs[q.no - 1]).payload            # the analysis dropped payloads; re-read the frame
            if not payload:
                continue
            c = is_client(q)
            if proto == "tcp":                                        # drop bytes already delivered (retransmissions)
                seq = q.tcp.seq
                hi = seen.get(c)
                if hi is not None:
                    skip = (hi - seq) & 0xFFFFFFFF
                    if skip < 0x80000000:
                        if skip >= len(payload):
                            continue
                        payload, seq = payload[skip:], hi
                seen[c] = (seq + len(payload)) & 0xFFFFFFFF
            if chunks and chunks[-1]["client"] == c:
                chunks[-1]["data"] += payload
            else:
                chunks.append({"client": c, "no": q.no, "data": payload})
            total += len(payload)
            if total > FOLLOW_MAX:
                break
        return {"filter": flt, "client": label[0], "server": label[1], "truncated": total > FOLLOW_MAX,
                "bytes_client": sum(len(c["data"]) for c in chunks if c["client"]),
                "bytes_server": sum(len(c["data"]) for c in chunks if not c["client"]),
                "chunks": [{"client": c["client"], "no": c["no"], "hex": c["data"].hex()} for c in chunks]}

    # ------------------------------------------------------------ statistics --
    def stats(self, key, kind, flt="", marked=frozenset(), interval=None):
        a = self.lib.get(key)
        nos = set(self.matching(key, flt, marked)) if flt.strip() else None
        pk = [p for p in a.packets if nos is None or p.no in nos]
        return {"hierarchy": _hierarchy, "conversations": _conversations, "endpoints": _endpoints,
                "io": lambda pk_: _io(a, pk_, interval), "expert": lambda pk_: _expert(a, pk_)}[kind](pk)

    # ---------------------------------------------------------------- export --
    def export(self, key, nos: list[int]) -> bytes:
        frs = self.frames(key)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "export.pcapng")
            write_pcapng(path, [(frs[n - 1].ts, frs[n - 1].data, frs[n - 1].linktype, frs[n - 1].wirelen) for n in nos])
            with open(path, "rb") as fh:
                return fh.read()


def _hierarchy(pk):
    root = {"name": "Frame", "packets": 0, "bytes": 0, "children": {}}
    for p in pk:
        root["packets"] += 1
        root["bytes"] += p.wirelen
        node = root
        for name in protocol_stack(p).split(":"):
            if name == "ethertype":
                continue
            node = node["children"].setdefault(name, {"name": name, "packets": 0, "bytes": 0, "children": {}})
            node["packets"] += 1
            node["bytes"] += p.wirelen

    def conv(n):
        return {"name": n["name"], "packets": n["packets"], "bytes": n["bytes"],
                "children": sorted((conv(c) for c in n["children"].values()), key=lambda c: -c["packets"])}
    return {"total_packets": root["packets"], "total_bytes": root["bytes"], "tree": conv(root)}


def _conv_key(kind, p):
    if kind == "Ethernet" and p.eth_src:
        return p.eth_src, p.eth_dst
    if kind == "IPv4" and p.ip_version == 4:
        return p.src, p.dst
    if kind == "IPv6" and p.ip_version == 6:
        return p.src, p.dst
    if kind == "TCP" and p.tcp is not None:
        return f"{p.src}:{p.sport}", f"{p.dst}:{p.dport}"
    if kind == "UDP" and p.ip_proto == 17 and p.sport is not None:
        return f"{p.src}:{p.sport}", f"{p.dst}:{p.dport}"
    return None


KINDS = ("Ethernet", "IPv4", "IPv6", "TCP", "UDP")


def _conversations(pk):
    out = {}
    t0 = pk[0].ts if pk else 0
    for kind in KINDS:
        conv: dict = {}
        for p in pk:
            k = _conv_key(kind, p)
            if not k:
                continue
            a, b = sorted(k)
            c = conv.setdefault((a, b), {"a": a, "b": b, "packets": 0, "bytes": 0, "pkts_ab": 0, "bytes_ab": 0, "pkts_ba": 0,
                                         "bytes_ba": 0, "start": p.ts - t0, "end": p.ts - t0,
                                         "stream": p.tcp.stream if kind == "TCP" and p.tcp else None})
            fwd = k[0] == a
            c["packets"] += 1
            c["bytes"] += p.wirelen
            c["pkts_ab" if fwd else "pkts_ba"] += 1
            c["bytes_ab" if fwd else "bytes_ba"] += p.wirelen
            c["end"] = p.ts - t0
        rows = sorted(conv.values(), key=lambda c: -c["bytes"])
        for c in rows:
            c["duration"] = round(c["end"] - c["start"], 6)
            c["start"] = round(c["start"], 6)
            dur = max(c["duration"], 1e-6)
            c["bps_ab"], c["bps_ba"] = round(c["bytes_ab"] * 8 / dur), round(c["bytes_ba"] * 8 / dur)
            del c["end"]
        out[kind] = rows[:2000]
    return out


def _endpoints(pk):
    out = {}
    for kind in KINDS:
        ep: dict = defaultdict(lambda: {"packets": 0, "bytes": 0, "tx_packets": 0, "tx_bytes": 0, "rx_packets": 0, "rx_bytes": 0})
        for p in pk:
            k = _conv_key(kind, p)
            if not k:
                continue
            for addr, tx in ((k[0], True), (k[1], False)):
                e = ep[addr]
                e["packets"] += 1
                e["bytes"] += p.wirelen
                e["tx_packets" if tx else "rx_packets"] += 1
                e["tx_bytes" if tx else "rx_bytes"] += p.wirelen
        out[kind] = sorted(({"address": k, **v} for k, v in ep.items()), key=lambda e: -e["bytes"])[:2000]
    return out


def _io(a, pk, interval):
    allp = a.packets
    if not allp:
        return {"interval": 1, "bins": []}
    t_end = max(p.rel_ts for p in allp)
    if not interval:
        interval = next((x for x in (0.001, 0.01, 0.1, 1, 10, 60, 600) if t_end / x <= 400), 3600)
    n = int(t_end / interval) + 1
    bins = [{"t": round(i * interval, 6), "all": 0, "all_bytes": 0, "match": 0, "match_bytes": 0, "bad": 0} for i in range(min(n, 5000))]
    sel = {p.no for p in pk}
    for p in allp:
        i = min(len(bins) - 1, max(0, int(p.rel_ts / interval)))
        b = bins[i]
        b["all"] += 1
        b["all_bytes"] += p.wirelen
        if p.no in sel:
            b["match"] += 1
            b["match_bytes"] += p.wirelen
        if p.tcp is not None and set(p.tcp.analysis) - {"window_update", "keep_alive", "keep_alive_ack"}:
            b["bad"] += 1
    return {"interval": interval, "bins": bins}


def _expert(a, pk):
    groups: dict = {}
    for p in pk:
        items = []
        if "malformed" in p.tags:
            items.append(("Error", "Malformed Packet", p.protocol))
        if p.ip_checksum_ok is False:
            items.append(("Error", "Bad IPv4 header checksum", "IPv4"))
        if p.tcp is not None:
            for f in p.tcp.analysis:
                sev, msg = EXPERT.get(f, ("Note", f.replace("_", " ")))
                items.append((sev, msg, "TCP"))
            if p.tcp.syn and not p.tcp.ackf:
                items.append(("Chat", "Connection establish request (SYN)", "TCP"))
            if p.tcp.fin:
                items.append(("Chat", "Connection finish (FIN)", "TCP"))
            if p.tcp.rst:
                items.append(("Warning", "Connection reset (RST)", "TCP"))
        if "icmp" in p.layers and p.layers["icmp"]["type"] in (3, 11) and not p.layers["icmp"]["v6"]:
            items.append(("Warning", f"ICMP {p.layers['icmp']['type_name']}", "ICMP"))
        if "dns" in p.layers and p.layers["dns"]["qr"] and p.layers["dns"]["rcode"]:
            items.append(("Warning", f"DNS response {p.layers['dns']['rcode_name']}", "DNS"))
        for sev, msg, proto in items:
            g = groups.setdefault((sev, msg, proto), {"severity": sev, "summary": msg, "protocol": proto, "count": 0, "packets": []})
            g["count"] += 1
            if len(g["packets"]) < 500:
                g["packets"].append(p.no)
    rows = sorted(groups.values(), key=lambda g: (SEV_ORDER.index(g["severity"]), -g["count"]))
    counts = {s: sum(g["count"] for g in rows if g["severity"] == s) for s in SEV_ORDER}
    findings = [{"severity": f.severity, "title": f.title, "summary": f.summary, "packets": f.packets[:50]} for f in a.findings]
    return {"counts": counts, "groups": rows, "findings": findings}
