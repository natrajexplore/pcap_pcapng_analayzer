"""Tunnel headers: GRE (RFC 2784/2890) and VXLAN (RFC 7348). The dissector decodes the inner packet."""
from __future__ import annotations

import struct

VXLAN_PORT = 4789
GRE_OVERHEAD = 24          # outer IPv4 (20) + basic GRE (4)
VXLAN_OVERHEAD = 50        # outer IPv4 (20) + UDP (8) + VXLAN (8) + inner Ethernet (14)


def parse_gre(buf: bytes) -> tuple[dict, int] | None:
    """-> (header fields, offset of the payload)"""
    if len(buf) < 4:
        return None
    flags, proto = struct.unpack("!HH", buf[:4])
    if flags & 0x0007:                       # only version 0 (not PPTP enhanced GRE)
        return None
    off = 4
    d = {"proto": proto, "checksum": bool(flags & 0x8000), "key": None, "seq": None}
    if flags & 0x8000:
        off += 4
    if flags & 0x2000:
        d["key"] = struct.unpack("!I", buf[off:off + 4])[0]
        off += 4
    if flags & 0x1000:
        d["seq"] = struct.unpack("!I", buf[off:off + 4])[0]
        off += 4
    d["overhead"] = GRE_OVERHEAD + (off - 4)
    return d, off


def parse_vxlan(buf: bytes) -> dict | None:
    if len(buf) < 8 + 14 or not buf[0] & 0x08:
        return None
    return {"vni": int.from_bytes(buf[4:7], "big"), "overhead": VXLAN_OVERHEAD}
