"""DHCP / BOOTP (RFC 2131/2132) parser."""
from __future__ import annotations

import ipaddress
import struct

MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
             6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _ip(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


def parse(buf: bytes) -> dict | None:
    if len(buf) < 240 or buf[236:240] != b"\x63\x82\x53\x63":
        return None
    op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", buf[:12])
    d = {
        "op": op, "xid": xid, "secs": secs, "broadcast": bool(flags & 0x8000),
        "ciaddr": _ip(buf[12:16]), "yiaddr": _ip(buf[16:20]),
        "siaddr": _ip(buf[20:24]), "giaddr": _ip(buf[24:28]),
        "chaddr": ":".join(f"{b:02x}" for b in buf[28:28 + min(hlen, 16)]),
        "hops": hops, "msg_type": None, "options": {},
    }
    off = 240
    opts = d["options"]
    while off < len(buf):
        code = buf[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        if off + 2 > len(buf):
            break
        ln = buf[off + 1]
        val = buf[off + 2:off + 2 + ln]
        off += 2 + ln
        if code == 53 and val:
            d["msg_type"] = MSG_TYPES.get(val[0], str(val[0]))
        elif code in (1, 50, 54, 28) and len(val) == 4:
            opts[{1: "subnet_mask", 50: "requested_ip", 54: "server_id", 28: "broadcast"}[code]] = _ip(val)
        elif code in (3, 6) and len(val) >= 4:
            opts["router" if code == 3 else "dns_servers"] = [_ip(val[i:i + 4]) for i in range(0, len(val) - 3, 4)]
        elif code in (51, 58, 59) and len(val) == 4:
            opts[{51: "lease_time", 58: "renewal_time", 59: "rebind_time"}[code]] = struct.unpack("!I", val)[0]
        elif code in (12, 15, 56, 60):
            opts[{12: "hostname", 15: "domain", 56: "message", 60: "vendor_class"}[code]] = val.decode("latin-1", "replace")
        elif code == 82:
            opts["relay_agent_info"] = val.hex()
        elif code == 55:
            opts["param_request_list"] = list(val)
    return d


def info(d: dict) -> str:
    return f"DHCP {d['msg_type'] or 'BOOTP'} - Transaction ID 0x{d['xid']:08x}"
