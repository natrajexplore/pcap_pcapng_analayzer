"""Capture library: discovers captures under a folder, analyzes them on demand and caches the results."""
from __future__ import annotations

import threading
from pathlib import Path

from ..analyzer import Analysis, analyze_file, worst_severity
from ..path import stitch

CAPTURE_EXT = (".pcap", ".pcapng", ".cap")
REPLAY_MAX = 20000
STATUS = {"ok": 0, "warn": 1, "fail": 2}


class Library:
    def __init__(self, root: str | None):
        self.root = Path(root).resolve() if root else None
        self.cache: dict[str, Analysis] = {}
        self.lock = threading.Lock()

    # ---- discovery
    def files(self) -> list[str]:
        if not self.root or not self.root.is_dir():
            return []
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                      if p.is_file() and p.suffix.lower() in CAPTURE_EXT)

    def resolve(self, rel: str) -> Path:
        """Path of a library capture; refuses anything outside the library folder."""
        if not self.root:
            raise FileNotFoundError(rel)
        p = (self.root / rel).resolve()
        if self.root not in p.parents or p.suffix.lower() not in CAPTURE_EXT or not p.is_file():
            raise FileNotFoundError(rel)
        return p

    def get(self, key: str) -> Analysis:
        with self.lock:
            if key not in self.cache:
                self.cache[key] = analyze_file(str(self.resolve(key)))
            return self.cache[key]

    def put(self, key: str, a: Analysis) -> None:
        with self.lock:
            self.cache[key] = a

    # ---- views
    def listing(self, analyze: bool) -> dict:
        folders: dict = {}
        for rel in self.files():
            folder = rel.rsplit("/", 1)[0] if "/" in rel else "(top level)"
            item = {"id": rel, "name": rel.rsplit("/", 1)[-1], "size": self.resolve(rel).stat().st_size}
            a = self.get(rel) if analyze else self.cache.get(rel)
            if a is not None:
                item.update(summary(a))
            folders.setdefault(folder, []).append(item)
        return {"root": str(self.root) if self.root else None, "pkt_skipped": self._pkt_count(),
                "folders": [{"name": k, "captures": v} for k, v in sorted(folders.items(), key=lambda x: x[0].lower())]}

    def _pkt_count(self) -> int:
        return sum(1 for _ in self.root.rglob("*.pkt")) if self.root and self.root.is_dir() else 0

    def folder_path(self, key: str) -> dict | None:
        """Stitched path of every capture in the same library folder (None when it is the only one)."""
        files = self.files()
        if key not in files:
            return None
        folder = key.rsplit("/", 1)[0] if "/" in key else ""
        sib = [f for f in files if (f.rsplit("/", 1)[0] if "/" in f else "") == folder]
        if len(sib) < 2:
            return None
        paths = [self.get(f).path for f in sib]
        return stitch([p for p in paths if p])


def summary(a: Analysis) -> dict:
    st = a.stats()
    return {"packets": st["packets"], "duration": st["duration"], "health": st["health"]["overall"],
            "worst": worst_severity(a) or "info", "findings": len(a.findings), "root_causes": len(a.root_causes),
            "top": (a.root_causes[0].title if a.root_causes else a.findings[0].title if a.findings else "No problems detected"),
            "protocols": [k for k, _ in st["protocols"][:5]]}


def capture_view(a: Analysis, folder_path: dict | None = None) -> dict:
    d = a.to_dict(packet_limit=5000)
    if folder_path:
        d["path_folder"] = folder_path
    d["replay"] = replay(a)
    return d


def replay(a: Analysis) -> dict:
    """Compact per-packet timeline for animation: [t, flow index or -1, forward?, status, protocol index, bytes]."""
    P = a.path or {"flows": []}
    by_pair, by_proto = {}, {}
    for i, f in enumerate(P["flows"]):
        if f["kind"] == "control":
            by_proto[f["label"].split()[0]] = i
        elif f["src_ip"]:
            by_pair.setdefault((f["src_ip"], f["dst_ip"]), (i, True))
            by_pair.setdefault((f["dst_ip"], f["src_ip"]), (i, False))
    protos: dict = {}
    rows = []
    for p in a.packets[:REPLAY_MAX]:
        fi, fwd = by_pair.get((p.src, p.dst)) or by_pair.get((p.eth_src, p.eth_dst)) or (by_proto.get(p.protocol, -1), True)
        status = "ok"
        if p.tcp is not None and (p.tcp.rst or set(p.tcp.analysis) & {"retransmission", "fast_retransmission", "lost_segment",
                                                                      "zero_window", "duplicate_ack", "out_of_order"}):
            status = "fail" if p.tcp.rst else "warn"
        elif "icmp" in p.layers and p.layers["icmp"]["type"] in ((1, 2, 3) if p.layers["icmp"]["v6"] else (3, 5, 11)):
            status = "fail"
        pi = protos.setdefault(p.protocol, len(protos))
        rows.append([round(p.rel_ts, 6), fi, 1 if fwd else 0, STATUS[status], pi, p.wirelen])
    return {"protocols": list(protos), "rows": rows, "truncated": len(a.packets) > REPLAY_MAX}
