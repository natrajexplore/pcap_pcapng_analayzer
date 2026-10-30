"""IEEE 802.11 (with optional radiotap header) -> addresses and the LLC/SNAP ethertype of data frames."""
from __future__ import annotations

import struct

from .l2 import mac

FRAME_TYPES = {0: "Management", 1: "Control", 2: "Data"}


def parse(buf: bytes, radiotap: bool) -> tuple[dict, int | None, bytes] | None:
    """-> (wlan fields, ethertype or None, payload after LLC/SNAP)."""
    off = 0
    if radiotap:
        if len(buf) < 4:
            return None
        off = struct.unpack("<H", buf[2:4])[0]
    if len(buf) < off + 24:
        return None
    fc0, fc1 = buf[off], buf[off + 1]
    ftype, sub = (fc0 >> 2) & 3, fc0 >> 4
    to_ds, from_ds = bool(fc1 & 1), bool(fc1 & 2)
    a1, a2, a3 = (mac(buf[off + i:off + i + 6]) for i in (4, 10, 16))
    d = {"type": FRAME_TYPES.get(ftype, str(ftype)), "subtype": sub, "protected": bool(fc1 & 0x40),
         "to_ds": to_ds, "from_ds": from_ds}
    if to_ds and not from_ds:
        d.update(bssid=a1, src=a2, dst=a3)
    elif from_ds and not to_ds:
        d.update(bssid=a2, src=a3, dst=a1)
    else:
        d.update(bssid=a3, src=a2, dst=a1)
    if ftype != 2 or d["protected"]:
        return d, None, b""
    hl = 24 + (6 if to_ds and from_ds else 0)
    if sub & 0x08:                       # QoS data
        hl += 2 + (4 if fc1 & 0x80 else 0)
    body = buf[off + hl:]
    if body[:3] != b"\xaa\xaa\x03" or len(body) < 8:
        return d, None, b""
    return d, struct.unpack("!H", body[6:8])[0], body[8:]
