"""BGP-4 (RFC 4271) message parser: OPEN, UPDATE, NOTIFICATION, KEEPALIVE, ROUTE-REFRESH."""
from __future__ import annotations

import ipaddress
import struct

MSG = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}
ERRORS = {
    1: ("Message Header Error", {1: "Connection Not Synchronized", 2: "Bad Message Length", 3: "Bad Message Type"}),
    2: ("OPEN Message Error", {1: "Unsupported Version Number", 2: "Bad Peer AS", 3: "Bad BGP Identifier",
                               4: "Unsupported Optional Parameter", 6: "Unacceptable Hold Time",
                               7: "Unsupported Capability"}),
    3: ("UPDATE Message Error", {1: "Malformed Attribute List", 2: "Unrecognized Well-known Attribute",
                                 3: "Missing Well-known Attribute", 4: "Attribute Flags Error",
                                 5: "Attribute Length Error", 6: "Invalid ORIGIN Attribute",
                                 8: "Invalid NEXT_HOP Attribute", 9: "Optional Attribute Error",
                                 10: "Invalid Network Field", 11: "Malformed AS_PATH"}),
    4: ("Hold Timer Expired", {}),
    5: ("Finite State Machine Error", {}),
    6: ("Cease", {1: "Maximum Number of Prefixes Reached", 2: "Administrative Shutdown",
                  3: "Peer De-configured", 4: "Administrative Reset", 5: "Connection Rejected",
                  6: "Other Configuration Change", 7: "Connection Collision Resolution",
                  8: "Out of Resources", 9: "Hard Reset", 10: "BFD Down"}),
}


def _prefixes(buf: bytes) -> list[str]:
    out, off = [], 0
    while off < len(buf):
        plen = buf[off]
        nb = (plen + 7) // 8
        raw = buf[off + 1:off + 1 + nb] + b"\x00" * (4 - nb)
        try:
            out.append(str(ipaddress.IPv4Network((raw[:4], plen), strict=False)))
        except ValueError:
            break
        off += 1 + nb
    return out


def parse(payload: bytes) -> dict | None:
    msgs = []
    off = 0
    while off + 19 <= len(payload):
        if payload[off:off + 16] != b"\xff" * 16:
            break
        ln, mtype = struct.unpack("!HB", payload[off + 16:off + 19])
        if ln < 19 or ln > 4096:
            break
        body = payload[off + 19:off + ln]
        m: dict = {"type": MSG.get(mtype, str(mtype)), "length": ln}
        try:
            if mtype == 1 and len(body) >= 10:
                ver, my_as, hold, bgp_id, optlen = struct.unpack("!BHHIB", body[:10])
                m.update(version=ver, my_as=my_as, hold_time=hold,
                         bgp_id=str(ipaddress.IPv4Address(bgp_id)), capabilities=[])
                opt = body[10:10 + optlen]
                i = 0
                while i + 2 <= len(opt):
                    ptype, plen = opt[i], opt[i + 1]
                    if ptype == 2:
                        j, cap = 0, opt[i + 2:i + 2 + plen]
                        while j + 2 <= len(cap):
                            code, cl = cap[j], cap[j + 1]
                            m["capabilities"].append(code)
                            if code == 65 and cl == 4:
                                m["as4"] = struct.unpack("!I", cap[j + 2:j + 6])[0]
                            j += 2 + cl
                    i += 2 + plen
                if "as4" in m:
                    m["my_as"] = m["as4"]
            elif mtype == 2 and len(body) >= 4:
                wl = struct.unpack("!H", body[:2])[0]
                withdrawn = _prefixes(body[2:2 + wl])
                pal = struct.unpack("!H", body[2 + wl:4 + wl])[0]
                attrs = body[4 + wl:4 + wl + pal]
                nlri = _prefixes(body[4 + wl + pal:])
                as_path, next_hop = [], None
                i = 0
                while i + 3 <= len(attrs):
                    flags, code = attrs[i], attrs[i + 1]
                    if flags & 0x10:
                        alen = struct.unpack("!H", attrs[i + 2:i + 4])[0]
                        val = attrs[i + 4:i + 4 + alen]
                        i += 4 + alen
                    else:
                        alen = attrs[i + 2]
                        val = attrs[i + 3:i + 3 + alen]
                        i += 3 + alen
                    if code == 2:
                        j = 0
                        while j + 2 <= len(val):
                            seg_n = val[j + 1]
                            width = 4 if len(val) - j - 2 == seg_n * 4 else 2
                            fmt = "!I" if width == 4 else "!H"
                            as_path += [struct.unpack(fmt, val[j + 2 + k * width:j + 2 + (k + 1) * width])[0]
                                        for k in range(seg_n)]
                            j += 2 + seg_n * width
                    elif code == 3 and len(val) == 4:
                        next_hop = str(ipaddress.IPv4Address(val))
                m.update(withdrawn=withdrawn, nlri=nlri, as_path=as_path, next_hop=next_hop)
            elif mtype == 3 and len(body) >= 2:
                code, sub = body[0], body[1]
                name, subs = ERRORS.get(code, (f"Error {code}", {}))
                m.update(error_code=code, error_subcode=sub, error=name,
                         suberror=subs.get(sub, str(sub) if sub else ""), data=body[2:].hex())
        except (struct.error, IndexError, ValueError):
            pass
        msgs.append(m)
        off += ln
    return {"messages": msgs} if msgs else None


def info(d: dict) -> str:
    parts = []
    for m in d["messages"]:
        s = m["type"]
        if m["type"] == "NOTIFICATION":
            s += f" ({m.get('error')}{' / ' + m['suberror'] if m.get('suberror') else ''})"
        elif m["type"] == "OPEN":
            s += f" AS{m.get('my_as')} hold={m.get('hold_time')}s id={m.get('bgp_id')}"
        elif m["type"] == "UPDATE":
            s += f" +{len(m.get('nlri', []))} -{len(m.get('withdrawn', []))}"
        parts.append(s)
    return ", ".join(parts)
