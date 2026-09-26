"""Cisco EIGRP (RFC 7868) parser."""
from __future__ import annotations

import ipaddress
import struct

OPCODES = {1: "Update", 2: "Request", 3: "Query", 4: "Reply", 5: "Hello", 6: "IPX SAP",
           10: "SIA-Query", 11: "SIA-Reply"}


def parse(buf: bytes) -> dict | None:
    if len(buf) < 20 or buf[0] != 2:
        return None
    ver, opcode, _cks, flags, seq, ack, _vrid, asn = struct.unpack("!BBHIIIHH", buf[:20])
    d: dict = {"opcode": OPCODES.get(opcode, str(opcode)), "opcode_num": opcode, "flags": flags,
               "init": bool(flags & 1), "cr": bool(flags & 2), "seq": seq, "ack": ack, "as": asn,
               "routes": [], "auth": False}
    if opcode == 5 and ack:
        d["opcode"] = "Hello (Ack)"
    off = 20
    while off + 4 <= len(buf):
        ttype, tlen = struct.unpack("!HH", buf[off:off + 4])
        if tlen < 4:
            break
        val = buf[off + 4:off + tlen]
        if ttype == 0x0001 and len(val) >= 8:
            k = list(val[:6])
            d["k_values"] = k[:5]
            d["hold_time"] = struct.unpack("!H", val[6:8])[0]
            if k[:5] == [255] * 5:
                d["goodbye"] = True
        elif ttype == 0x0002:
            d["auth"] = True
        elif ttype == 0x0004 and len(val) >= 4:
            d["sw_version"] = f"{val[0]}.{val[1]}/{val[2]}.{val[3]}"
        elif ttype in (0x0102, 0x0103):
            base = 0 if ttype == 0x0102 else 24
            try:
                nh = str(ipaddress.IPv4Address(val[:4]))
                delay, bw = struct.unpack("!II", val[4 + base:12 + base])
                hops = val[15 + base]
                plen = val[20 + base]
                raw = val[21 + base:21 + base + (plen + 7) // 8]
                prefix = str(ipaddress.IPv4Network((raw + b"\x00" * (4 - len(raw)), plen), strict=False))
                d["routes"].append({"prefix": prefix, "next_hop": nh, "delay": delay, "bandwidth": bw,
                                    "hops": hops, "external": ttype == 0x0103,
                                    "unreachable": delay == 0xFFFFFFFF})
            except (struct.error, IndexError, ValueError):
                pass
        off += tlen
    return d


def info(d: dict) -> str:
    s = f"EIGRP {d['opcode']} AS {d['as']} seq={d['seq']} ack={d['ack']}"
    if d.get("goodbye"):
        s += " (Goodbye)"
    if d["routes"]:
        s += f" routes={len(d['routes'])}"
    return s
