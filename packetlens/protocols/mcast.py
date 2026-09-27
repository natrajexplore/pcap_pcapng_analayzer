"""Multicast control: PIMv2 (RFC 7761 / 5059) and IGMP v1/v2/v3 (RFC 2236 / 3376)."""
from __future__ import annotations

import ipaddress
import struct

PIM_TYPES = {0: "Hello", 1: "Register", 2: "Register-Stop", 3: "Join/Prune", 4: "Bootstrap", 5: "Assert",
             6: "Graft", 7: "Graft-Ack", 8: "Candidate-RP-Advertisement"}
IGMP_TYPES = {0x11: "Membership Query", 0x12: "v1 Membership Report", 0x16: "v2 Membership Report",
              0x17: "Leave Group", 0x22: "v3 Membership Report"}
IGMPV3_RECORDS = {1: "IS_INCLUDE", 2: "IS_EXCLUDE", 3: "TO_INCLUDE", 4: "TO_EXCLUDE", 5: "ALLOW", 6: "BLOCK"}


def _ip4(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


def _unicast(b: bytes, off: int) -> tuple[str, int]:
    """Encoded-Unicast address (family, encoding, address) -> (address, next offset). IPv4 only."""
    return _ip4(b[off + 2:off + 6]), off + 6


def _group(b: bytes, off: int) -> tuple[str, int]:
    """Encoded-Group / Encoded-Source (family, encoding, flags, mask length, address)."""
    return f"{_ip4(b[off + 4:off + 8])}/{b[off + 3]}", off + 8


def parse_pim(buf: bytes) -> dict | None:
    if len(buf) < 4 or buf[0] >> 4 != 2:
        return None
    t = buf[0] & 0x0F
    d: dict = {"type": PIM_TYPES.get(t, str(t)), "type_num": t}
    b = buf[4:]
    try:
        if t == 0:
            off = 0
            while off + 4 <= len(b):
                ot, ol = struct.unpack("!HH", b[off:off + 4])
                v = b[off + 4:off + 4 + ol]
                if ot == 1 and ol == 2:
                    d["holdtime"] = struct.unpack("!H", v)[0]
                elif ot == 19 and ol == 4:
                    d["dr_priority"] = struct.unpack("!I", v)[0]
                elif ot == 20 and ol == 4:
                    d["generation_id"] = struct.unpack("!I", v)[0]
                off += 4 + ol
        elif t == 1 and len(b) >= 4 + 20:
            d["null_register"] = bool(b[0] & 0x40)
            inner = b[4:]
            if inner[0] >> 4 == 4:
                d["source"], d["group"] = _ip4(inner[12:16]), _ip4(inner[16:20])
        elif t == 2:
            g, off = _group(b, 0)
            d["group"] = g.split("/")[0]
            d["source"] = _unicast(b, off)[0]
        elif t == 3:
            d["upstream"], off = _unicast(b, 0)
            ngroups, hold = b[off + 1], struct.unpack("!H", b[off + 2:off + 4])[0]
            off += 4
            d["holdtime"], d["groups"] = hold, []
            for _ in range(ngroups):
                g, off = _group(b, off)
                nj, npr = struct.unpack("!HH", b[off:off + 4])
                off += 4
                joins, prunes = [], []
                for lst, n in ((joins, nj), (prunes, npr)):
                    for _ in range(n):
                        s, off = _group(b, off)
                        lst.append(s)
                d["groups"].append({"group": g, "joins": joins, "prunes": prunes})
        elif t == 4:
            d["bsr_priority"] = b[3]
            d["bsr"], off = _unicast(b, 4)
            d["rps"] = []
            while off + 12 <= len(b):
                g, off = _group(b, off)
                nrp = b[off]
                off += 4
                for _ in range(nrp):
                    rp, off = _unicast(b, off)
                    d["rps"].append({"group": g, "rp": rp, "holdtime": struct.unpack("!H", b[off:off + 2])[0],
                                     "priority": b[off + 2]})
                    off += 4
        elif t == 8:
            nprefix, prio, hold = b[0], b[1], struct.unpack("!H", b[2:4])[0]
            d["rp"], off = _unicast(b, 4)
            d.update(priority=prio, holdtime=hold, groups=[])
            for _ in range(nprefix):
                g, off = _group(b, off)
                d["groups"].append(g)
    except (struct.error, IndexError, ValueError):
        d["truncated"] = True
    return d


def pim_info(d: dict) -> str:
    s = f"PIMv2 {d['type']}"
    if d["type_num"] == 0 and "holdtime" in d:
        s += f" holdtime {d['holdtime']}s" + (f" DR priority {d['dr_priority']}" if "dr_priority" in d else "")
    elif d["type_num"] in (1, 2) and "group" in d:
        s += f" (S,G)=({d.get('source')}, {d['group']})" + (" null-register" if d.get("null_register") else "")
    elif d["type_num"] == 3:
        s += "".join(f" {g['group']} J={len(g['joins'])} P={len(g['prunes'])}" for g in d.get("groups", [])[:3])
    elif d["type_num"] == 4:
        s += f" BSR {d.get('bsr')}" + "".join(f" RP {r['rp']}" for r in d.get("rps", [])[:2])
    elif d["type_num"] == 8:
        s += f" RP {d.get('rp')} for {', '.join(d.get('groups', [])[:3])}"
    return s


def parse_igmp(buf: bytes) -> dict | None:
    if len(buf) < 8:
        return None
    t = buf[0]
    d: dict = {"type": IGMP_TYPES.get(t, f"0x{t:02x}"), "type_num": t, "group": _ip4(buf[4:8])}
    if t == 0x11:
        d["version"] = 3 if len(buf) >= 12 else (2 if buf[1] else 1)
        d["max_resp"] = buf[1] / 10
        d["general"] = d["group"] == "0.0.0.0"
    elif t == 0x22:
        d["version"], d["records"] = 3, []
        n = struct.unpack("!H", buf[6:8])[0]
        off = 8
        for _ in range(n):
            if off + 8 > len(buf):
                break
            rtype, aux, nsrc = buf[off], buf[off + 1], struct.unpack("!H", buf[off + 2:off + 4])[0]
            d["records"].append({"type": IGMPV3_RECORDS.get(rtype, str(rtype)), "group": _ip4(buf[off + 4:off + 8]),
                                 "sources": [_ip4(buf[off + 8 + 4 * i:off + 12 + 4 * i]) for i in range(nsrc)]})
            off += 8 + 4 * nsrc + 4 * aux
        d["group"] = d["records"][0]["group"] if d["records"] else ""
    else:
        d["version"] = {0x12: 1, 0x16: 2, 0x17: 2}.get(t)
    return d


def igmp_info(d: dict) -> str:
    s = f"IGMPv{d.get('version') or '?'} {d['type']}"
    if d["type_num"] == 0x11:
        s += " (general)" if d["general"] else f" for {d['group']}"
    elif d.get("group"):
        s += f" {d['group']}"
    return s
