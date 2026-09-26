"""RIPv1 / RIPv2 (RFC 1058 / RFC 2453) parser."""
from __future__ import annotations

import ipaddress
import struct


def parse(buf: bytes) -> dict | None:
    if len(buf) < 4 or buf[0] not in (1, 2) or buf[1] not in (1, 2):
        return None
    cmd, ver = buf[0], buf[1]
    entries, auth = [], None
    off = 4
    while off + 20 <= len(buf):
        afi, tag = struct.unpack("!HH", buf[off:off + 4])
        if afi == 0xFFFF:
            auth = struct.unpack("!H", buf[off + 2:off + 4])[0]
        else:
            ip = str(ipaddress.IPv4Address(buf[off + 4:off + 8]))
            mask = str(ipaddress.IPv4Address(buf[off + 8:off + 12]))
            nh = str(ipaddress.IPv4Address(buf[off + 12:off + 16]))
            metric = struct.unpack("!I", buf[off + 16:off + 20])[0]
            entries.append({"afi": afi, "ip": ip, "mask": mask, "next_hop": nh, "metric": metric, "tag": tag})
        off += 20
    return {"command": "Request" if cmd == 1 else "Response", "version": ver, "entries": entries,
            "auth_type": auth}


def info(d: dict) -> str:
    return f"RIPv{d['version']} {d['command']} ({len(d['entries'])} routes)"
