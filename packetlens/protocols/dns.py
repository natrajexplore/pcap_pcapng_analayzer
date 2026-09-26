"""DNS (RFC 1035) message parser."""
from __future__ import annotations

import ipaddress
import struct

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
          64: "SVCB", 65: "HTTPS", 255: "ANY"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH"}


def _name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    jumped_end = None
    while True:
        if off >= len(buf) or depth > 20:
            raise ValueError("bad name")
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            if jumped_end is None:
                jumped_end = off + 2
            off = ptr
            depth += 1
            continue
        labels.append(buf[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    return ".".join(labels) or ".", (jumped_end if jumped_end is not None else off)


def parse(buf: bytes) -> dict | None:
    if len(buf) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", buf[:12])
        if qd > 64 or an > 512:
            return None
        off = 12
        questions = []
        for _ in range(qd):
            name, off = _name(buf, off)
            qtype, qclass = struct.unpack("!HH", buf[off:off + 4])
            off += 4
            questions.append({"name": name, "type": QTYPES.get(qtype, str(qtype))})
        answers = []
        for _ in range(an):
            name, off = _name(buf, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", buf[off:off + 10])
            off += 10
            rdata = buf[off:off + rdlen]
            val: str
            if rtype == 1 and rdlen == 4:
                val = str(ipaddress.IPv4Address(rdata))
            elif rtype == 28 and rdlen == 16:
                val = str(ipaddress.IPv6Address(rdata))
            elif rtype in (2, 5, 12):
                val = _name(buf, off)[0]
            elif rtype == 15:
                val = _name(buf, off + 2)[0]
            elif rtype == 16:
                val = rdata[1:1 + rdata[0]].decode("latin-1", "replace") if rdata else ""
            else:
                val = rdata.hex()[:64]
            answers.append({"name": name, "type": QTYPES.get(rtype, str(rtype)), "ttl": ttl, "data": val})
            off += rdlen
    except (ValueError, struct.error, IndexError):
        return None
    rcode = flags & 0x0F
    return {
        "id": tid,
        "qr": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "aa": bool(flags & 0x0400),
        "tc": bool(flags & 0x0200),
        "rd": bool(flags & 0x0100),
        "ra": bool(flags & 0x0080),
        "rcode": rcode,
        "rcode_name": RCODES.get(rcode, str(rcode)),
        "questions": questions,
        "answers": answers,
        "qname": questions[0]["name"] if questions else "",
        "qtype": questions[0]["type"] if questions else "",
        "counts": (qd, an, ns, ar),
    }


def info(d: dict) -> str:
    kind = "Standard query response" if d["qr"] else "Standard query"
    s = f"{kind} 0x{d['id']:04x} {d['qtype']} {d['qname']}"
    if d["qr"]:
        if d["rcode"]:
            s += f" {d['rcode_name']}"
        s += "".join(f" {a['type']} {a['data']}" for a in d["answers"][:3])
    return s
