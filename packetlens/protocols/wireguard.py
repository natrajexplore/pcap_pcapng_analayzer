"""WireGuard (Noise_IKpsk2 over UDP): handshake initiation / response, cookie reply, transport data."""
from __future__ import annotations

import struct

PORT = 51820
TYPES = {1: ("Handshake Initiation", 148), 2: ("Handshake Response", 92), 3: ("Cookie Reply", 64), 4: ("Transport Data", None)}


def parse(buf: bytes, port_hint: bool) -> dict | None:
    """Types 1-3 have fixed sizes and are recognised on any port; transport data only on the WireGuard port."""
    if len(buf) < 16 or buf[0] not in TYPES or buf[1:4] != b"\x00\x00\x00":
        return None
    t = buf[0]
    name, size = TYPES[t]
    if size is not None and len(buf) != size:
        return None
    if t == 4 and (not port_hint or (len(buf) - 16) % 16):
        return None
    d = {"type": name, "type_num": t}
    if t == 1:
        d["sender"] = struct.unpack("<I", buf[4:8])[0]
    elif t == 2:
        d["sender"], d["receiver"] = struct.unpack("<II", buf[4:12])
    elif t == 3:
        d["receiver"] = struct.unpack("<I", buf[4:8])[0]
    else:
        d["receiver"], d["counter"] = struct.unpack("<IQ", buf[4:16])
        d["data_len"] = len(buf) - 32
    return d


def info(d: dict) -> str:
    s = f"WireGuard {d['type']}"
    if "sender" in d:
        s += f", sender=0x{d['sender']:08x}"
    if "receiver" in d:
        s += f", receiver=0x{d['receiver']:08x}"
    if "counter" in d:
        s += f", counter={d['counter']}"
    return s
