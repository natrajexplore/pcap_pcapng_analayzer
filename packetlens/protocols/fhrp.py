"""First-hop redundancy protocols: HSRP v1/v2 (UDP 1985) and VRRP v2/v3 (IP proto 112)."""
from __future__ import annotations

import ipaddress
import struct

HSRP_OPS = {0: "Hello", 1: "Coup", 2: "Resign", 3: "Advertise"}
HSRP_STATES = {0: "Initial", 1: "Learn", 2: "Listen", 4: "Speak", 8: "Standby", 16: "Active",
               3: "Listen", 5: "Standby", 6: "Active"}   # v2 state TLV uses 1..6


def parse_hsrp(buf: bytes) -> dict | None:
    if len(buf) >= 20 and buf[0] == 0:                        # HSRPv1
        ver, op, state, hello, hold, prio, group, _r = struct.unpack("!BBBBBBBB", buf[:8])
        auth = buf[8:16]
        return {"proto": "HSRP", "version": 1, "op": HSRP_OPS.get(op, str(op)), "state": HSRP_STATES.get(state, str(state)),
                "group": group, "priority": prio, "hello": hello, "hold": hold,
                "vip": str(ipaddress.IPv4Address(buf[16:20])),
                "auth": auth.rstrip(b"\x00").decode("latin-1", "replace"), "auth_default": auth.rstrip(b"\x00") == b"cisco"}
    off = 0
    while off + 2 <= len(buf):                                 # HSRPv2 TLVs
        ttype, tlen = buf[off], buf[off + 1]
        val = buf[off + 2:off + 2 + tlen]
        if ttype == 1 and tlen >= 40:
            _v, op, state, ipver, group = struct.unpack("!BBBBH", val[:6])
            prio, hello_ms, hold_ms = struct.unpack("!III", val[12:24])
            vip = str(ipaddress.IPv4Address(val[24:28])) if ipver == 4 else str(ipaddress.IPv6Address(val[24:40]))
            d = {"proto": "HSRP", "version": 2, "op": HSRP_OPS.get(op, str(op)), "state": HSRP_STATES.get(state, str(state)),
                 "group": group, "priority": prio, "hello": hello_ms / 1000, "hold": hold_ms / 1000, "vip": vip,
                 "auth": None, "auth_default": False}
            rest = buf[off + 2 + tlen:]
            if len(rest) >= 2 and rest[0] == 3:                # text authentication TLV
                a = rest[2:2 + rest[1]]
                d["auth"] = a.rstrip(b"\x00").decode("latin-1", "replace")
                d["auth_default"] = a.rstrip(b"\x00") == b"cisco"
            return d
        if tlen == 0:
            break
        off += 2 + tlen
    return None


def parse_vrrp(buf: bytes, v6: bool = False) -> dict | None:
    if len(buf) < 8:
        return None
    ver, typ = buf[0] >> 4, buf[0] & 0xF
    if ver not in (2, 3) or typ != 1:
        return None
    vrid, prio, count = buf[1], buf[2], buf[3]
    if ver == 2:
        auth_type, adv = buf[4], buf[5]
        ips = [str(ipaddress.IPv4Address(buf[8 + 4 * i:12 + 4 * i])) for i in range(count) if len(buf) >= 12 + 4 * i]
        interval = float(adv)
    else:
        auth_type = 0
        interval = (struct.unpack("!H", buf[4:6])[0] & 0x0FFF) / 100.0
        w = 16 if v6 else 4
        ips = [str(ipaddress.ip_address(buf[8 + w * i:8 + w * (i + 1)])) for i in range(count) if len(buf) >= 8 + w * (i + 1)]
    return {"proto": "VRRP", "version": ver, "op": "Advertisement", "state": "Master" if prio else "Master (resigning)",
            "group": vrid, "priority": prio, "hello": interval, "hold": interval * 3, "vip": ips[0] if ips else None,
            "vips": ips, "auth": auth_type, "auth_default": False}


def info(d: dict) -> str:
    return (f"{d['proto']}v{d['version']} {d['op']} group {d['group']} state {d['state']} prio {d['priority']} "
            f"VIP {d['vip']} hello {d['hello']}s")
