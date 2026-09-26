"""Decoded packet model shared by every analyzer."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(slots=True)
class TCPInfo:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int          # raw header value (unscaled)
    hdr_len: int
    payload_len: int
    options: dict = field(default_factory=dict)
    checksum_ok: Optional[bool] = None
    # filled by the TCP stream analyzer (Wireshark "tcp.analysis.*" equivalent)
    stream: int = -1
    calc_window: int = 0
    analysis: list = field(default_factory=list)
    bytes_in_flight: int = 0
    time_delta: float = 0.0

    @property
    def syn(self): return bool(self.flags & 0x02)
    @property
    def fin(self): return bool(self.flags & 0x01)
    @property
    def rst(self): return bool(self.flags & 0x04)
    @property
    def psh(self): return bool(self.flags & 0x08)
    @property
    def ackf(self): return bool(self.flags & 0x10)
    @property
    def urg(self): return bool(self.flags & 0x20)

    def flag_str(self) -> str:
        names = [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"),
                 (0x04, "RST"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
        return ",".join(n for b, n in names if self.flags & b) or "NONE"


@dataclass(slots=True)
class Packet:
    no: int
    ts: float
    caplen: int
    wirelen: int
    rel_ts: float = 0.0
    # layer 2
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    vlan: Optional[int] = None
    ethertype: Optional[int] = None
    # layer 3
    ip_version: Optional[int] = None
    src: Optional[str] = None
    dst: Optional[str] = None
    ttl: Optional[int] = None
    ip_proto: Optional[int] = None
    ip_id: Optional[int] = None
    ip_len: Optional[int] = None
    ip_hdr_len: Optional[int] = None
    ip_df: bool = False
    ip_mf: bool = False
    ip_frag_offset: int = 0
    ip_checksum_ok: Optional[bool] = None
    dscp: int = 0
    # layer 4
    tcp: Optional[TCPInfo] = None
    sport: Optional[int] = None
    dport: Optional[int] = None
    payload: bytes = b""
    # upper layers: protocol name -> parsed dict
    layers: dict = field(default_factory=dict)
    protocol: str = "UNKNOWN"      # highest decoded protocol (Wireshark "Protocol" column)
    info: str = ""                 # Wireshark-like "Info" column
    tags: list = field(default_factory=list)  # colouring rule / signature hits

    @property
    def is_tcp(self) -> bool: return self.tcp is not None

    @property
    def is_udp(self) -> bool: return self.ip_proto == 17

    def get(self, proto: str) -> Optional[dict[str, Any]]:
        return self.layers.get(proto)

    def endpoint_pair(self) -> str:
        s = f"{self.src}:{self.sport}" if self.sport is not None else str(self.src or self.eth_src)
        d = f"{self.dst}:{self.dport}" if self.dport is not None else str(self.dst or self.eth_dst)
        return f"{s} → {d}"
