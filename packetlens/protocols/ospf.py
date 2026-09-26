"""OSPFv2 (RFC 2328) and OSPFv3 (RFC 5340) parser."""
from __future__ import annotations

import ipaddress
import struct

TYPES = {1: "Hello", 2: "DB Description", 3: "LS Request", 4: "LS Update", 5: "LS Acknowledge"}
AUTH = {0: "None", 1: "Simple password", 2: "Cryptographic (MD5)"}


def _ip(v: int) -> str:
    return str(ipaddress.IPv4Address(v))


def parse(buf: bytes) -> dict | None:
    if len(buf) < 16 or buf[0] not in (2, 3):
        return None
    ver, ptype, plen = struct.unpack("!BBH", buf[:4])
    rid, area = struct.unpack("!II", buf[4:12])
    d: dict = {"version": ver, "type": TYPES.get(ptype, str(ptype)), "type_num": ptype,
               "router_id": _ip(rid), "area": _ip(area)}
    try:
        if ver == 2:
            if len(buf) < 24:
                return None
            autype = struct.unpack("!H", buf[14:16])[0]
            d["auth_type"] = AUTH.get(autype, str(autype))
            body = buf[24:plen]
            if ptype == 1 and len(body) >= 20:
                mask, hello, opts, prio, dead, dr, bdr = struct.unpack("!IHBBIII", body[:20])
                d.update(mask=_ip(mask), hello_interval=hello, options=opts, priority=prio,
                         dead_interval=dead, dr=_ip(dr), bdr=_ip(bdr),
                         neighbors=[_ip(struct.unpack("!I", body[i:i + 4])[0]) for i in range(20, len(body) - 3, 4)])
            elif ptype == 2 and len(body) >= 8:
                mtu, opts, flags, seq = struct.unpack("!HBBI", body[:8])
                d.update(mtu=mtu, dbd_flags=flags, init=bool(flags & 4), more=bool(flags & 2),
                         master=bool(flags & 1), dd_seq=seq)
            elif ptype == 4 and len(body) >= 4:
                d["lsa_count"] = struct.unpack("!I", body[:4])[0]
        else:
            d["instance_id"] = buf[14]
            body = buf[16:plen]
            if ptype == 1 and len(body) >= 20:
                iface, prio = struct.unpack("!IB", body[:5])
                hello, dead, dr, bdr = struct.unpack("!HHII", body[8:20])
                d.update(interface_id=iface, priority=prio, hello_interval=hello, dead_interval=dead,
                         dr=_ip(dr), bdr=_ip(bdr), auth_type="None",
                         neighbors=[_ip(struct.unpack("!I", body[i:i + 4])[0]) for i in range(20, len(body) - 3, 4)])
            elif ptype == 2 and len(body) >= 12:
                mtu = struct.unpack("!H", body[4:6])[0]
                flags = body[7]
                seq = struct.unpack("!I", body[8:12])[0]
                d.update(mtu=mtu, dbd_flags=flags, init=bool(flags & 4), more=bool(flags & 2),
                         master=bool(flags & 1), dd_seq=seq)
            elif ptype == 4 and len(body) >= 4:
                d["lsa_count"] = struct.unpack("!I", body[:4])[0]
    except struct.error:
        pass
    return d


def info(d: dict) -> str:
    s = f"OSPFv{d['version']} {d['type']} Packet (RID {d['router_id']}, Area {d['area']})"
    if d["type_num"] == 1 and "hello_interval" in d:
        s += f" hello={d['hello_interval']} dead={d['dead_interval']}"
    if d["type_num"] == 2 and "mtu" in d:
        s += f" MTU={d['mtu']} I={int(d['init'])} M={int(d['more'])} MS={int(d['master'])}"
    return s
