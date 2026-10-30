"""IPsec control and data plane: ISAKMP / IKEv1, IKEv2 (RFC 7296) with RFC 9242 IKE_INTERMEDIATE and
RFC 9370 additional key exchanges (ML-KEM), RFC 7383 fragmentation, NAT-T (UDP 4500) and ESP (RFC 4303)."""
from __future__ import annotations

import struct

from . import pqc

PORTS = {500, 4500}
EXCH2 = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL", 43: "IKE_INTERMEDIATE",
         44: "IKE_FOLLOWUP_KE"}
EXCH1 = {2: "Main Mode", 4: "Aggressive Mode", 5: "Informational", 32: "Quick Mode"}
PAYLOADS = {33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ", 39: "AUTH", 40: "Nonce", 41: "Notify",
            42: "Delete", 43: "Vendor ID", 44: "TSi", 45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF"}
TTYPES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN"}
TTYPES.update({6 + i: f"ADDKE{i + 1}" for i in range(7)})
NOTIFY_ERR = {1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION", 7: "INVALID_SYNTAX",
              9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI", 14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
              24: "AUTHENTICATION_FAILED", 34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS",
              36: "INTERNAL_ADDRESS_FAILURE", 37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS",
              43: "TEMPORARY_FAILURE", 44: "CHILD_SA_NOT_FOUND", 48: "STATE_NOT_FOUND"}
NOTIFY_STATUS = {16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE",
                 16396: "MOBIKE_SUPPORTED", 16430: "IKEV2_FRAGMENTATION_SUPPORTED",
                 16431: "SIGNATURE_HASH_ALGORITHMS", 16438: "INTERMEDIATE_EXCHANGE_SUPPORTED",
                 16393: "REKEY_SA", 16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO"}
PROTO = {1: "IKE", 2: "AH", 3: "ESP"}


def _t(table, tid):
    return table.get(tid, (f"id {tid}", "unknown"))


def parse(buf: bytes, natt: bool = False) -> dict | None:
    """``buf`` is the UDP payload; on UDP/4500 IKE carries a 4-byte zero non-ESP marker."""
    if natt:
        if len(buf) < 4:
            return None
        if buf[:4] != b"\x00\x00\x00\x00":
            return parse_esp(buf, udp=True)
        buf = buf[4:]
    if len(buf) < 28:
        return None
    ispi, rspi, nxt, ver, exch, flags, mid, ln = struct.unpack("!8s8sBBBBII", buf[:28])
    major = ver >> 4
    if major not in (1, 2) or ln < 28:
        return None
    d: dict = {"kind": "ike", "version": major, "ispi": ispi.hex(), "rspi": rspi.hex(), "msg_id": mid, "length": ln,
               "exchange": (EXCH2 if major == 2 else EXCH1).get(exch, str(exch)), "exchange_num": exch,
               "payloads": [], "notify": [], "proposals": [], "ke": None, "frag": None}
    if major == 2:
        d["initiator"] = bool(flags & 0x08)
        d["response"] = bool(flags & 0x20)
    else:
        d["initiator"] = rspi == b"\x00" * 8
        d["response"] = not d["initiator"]
        d["encrypted"] = bool(flags & 0x01)
    off = 28
    end = min(ln, len(buf))
    seen = 0
    while nxt and off + 4 <= end and seen < 32:
        seen += 1
        cur, nxt = nxt, buf[off]
        plen = struct.unpack("!H", buf[off + 2:off + 4])[0]
        if plen < 4:
            break
        body = buf[off + 4:off + plen]
        d["payloads"].append(PAYLOADS.get(cur, str(cur)) if major == 2 else _V1.get(cur, str(cur)))
        try:
            if major == 2:
                _v2_payload(d, cur, body)
            elif cur == 1 and not d.get("encrypted"):
                _v1_sa(d, body)
        except (struct.error, IndexError):
            pass
        if cur in (46, 53):                     # SK / SKF: the rest is encrypted
            break
        off += plen
    return d


_V1 = {1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT", 7: "CR", 8: "HASH", 9: "SIG",
       10: "Nonce", 11: "Notification", 12: "Delete", 13: "Vendor ID", 20: "NAT-D", 21: "NAT-OA"}
_V1_ATTR = {1: ("encr", {1: ("DES", "weak"), 5: ("3DES", "weak"), 7: ("AES-CBC", "classical")}),
            2: ("hash", {1: ("MD5", "weak"), 2: ("SHA1", "weak"), 4: ("SHA2-256", "classical"),
                         5: ("SHA2-384", "classical"), 6: ("SHA2-512", "classical")}),
            3: ("auth", {1: ("PSK", "classical"), 3: ("RSA-SIG", "classical"), 65001: ("XAUTH-PSK", "classical")}),
            4: ("ke", pqc.IKE_KE)}


def _v1_sa(d, body):
    # DOI(4) + situation(4), then a Proposal payload holding Transform payloads with TV/TLV attributes
    off = 8 + 4
    _pn, _pid, spi_size, ntr = struct.unpack("!BBBB", body[off:off + 4])
    off += 4 + spi_size
    for _ in range(ntr):
        tlen = struct.unpack("!H", body[off + 2:off + 4])[0]
        t = body[off + 4:off + tlen]
        a, tr = 4, {}
        while a + 4 <= len(t):
            at, av = struct.unpack("!HH", t[a:a + 4])
            if at & 0x8000:
                key = _V1_ATTR.get(at & 0x7FFF)
                if key:
                    tr[key[0]] = _t(key[1], av)
                a += 4
            else:
                a += 4 + av
        d["proposals"].append({"protocol": "IKE", "transforms": [{"type": k.upper(), "name": v[0], "status": v[1]}
                                                                 for k, v in tr.items()]})
        off += tlen
        if tlen < 8:
            break


def _v2_payload(d, ptype, body):
    if ptype == 33:
        off = 0
        while off + 8 <= len(body):
            last, _, plen, num, proto, spi_size, ntr = struct.unpack("!BBHBBBB", body[off:off + 8])
            p = {"num": num, "protocol": PROTO.get(proto, str(proto)), "transforms": []}
            t = off + 8 + spi_size
            for _ in range(ntr):
                tlast, _, tlen, ttype, _, tid = struct.unpack("!BBHBBH", body[t:t + 8])
                table = {1: pqc.IKE_ENCR, 2: pqc.IKE_PRF, 3: pqc.IKE_INTEG}.get(ttype, pqc.IKE_KE if ttype == 4 or 6 <= ttype <= 12 else {})
                name, status = _t(table, tid) if table else ({0: "No ESN", 1: "ESN"}.get(tid, str(tid)), "classical")
                keylen = None
                if tlen >= 12 and struct.unpack("!H", body[t + 8:t + 10])[0] == 0x800E:
                    keylen = struct.unpack("!H", body[t + 10:t + 12])[0]
                p["transforms"].append({"type": TTYPES.get(ttype, str(ttype)), "id": tid,
                                        "name": name + (f"-{keylen}" if keylen else ""), "status": status})
                t += max(tlen, 8)
            d["proposals"].append(p)
            off += max(plen, 8)
            if last == 0:
                break
    elif ptype == 34 and len(body) >= 4:
        g = struct.unpack("!H", body[:2])[0]
        name, status = _t(pqc.IKE_KE, g)
        d["ke"] = {"group": name, "id": g, "status": status, "len": len(body) - 4}
    elif ptype == 41 and len(body) >= 4:
        _proto, spi_size, nt = struct.unpack("!BBH", body[:4])
        data = body[4 + spi_size:]
        if nt < 16384:
            n = {"type": NOTIFY_ERR.get(nt, f"error {nt}"), "code": nt, "error": True}
            if nt == 17 and len(data) >= 2:
                g = struct.unpack("!H", data[:2])[0]
                n["accepted_group"] = _t(pqc.IKE_KE, g)[0]
        else:
            n = {"type": NOTIFY_STATUS.get(nt, f"status {nt}"), "code": nt, "error": False}
        d["notify"].append(n)
    elif ptype == 53 and len(body) >= 4:
        num, total = struct.unpack("!HH", body[:4])
        d["frag"] = {"number": num, "total": total}


def parse_esp(buf: bytes, udp: bool = False) -> dict | None:
    if len(buf) < 8:
        return None
    spi, seq = struct.unpack("!II", buf[:8])
    if spi == 0 or spi == 0xFF:
        return None                                 # 0xFF: NAT-T keepalive
    return {"kind": "esp", "spi": f"0x{spi:08x}", "seq": seq, "udp_encap": udp, "length": len(buf)}


def kex_summary(d: dict) -> tuple[str, str]:
    """(name, status) of the key exchange(s) proposed/selected in one IKE message."""
    names, statuses = [], []
    for p in d.get("proposals", []):
        for t in p["transforms"]:
            if t["type"] == "KE" or t["type"].startswith("ADDKE"):
                names.append(t["name"])
                statuses.append(t["status"])
    if not names and d.get("ke"):
        return d["ke"]["group"], d["ke"]["status"]
    if not names:
        return "unknown", "unknown"
    classical = [n for n, s in zip(names, statuses) if s != "pqc"]
    pq = [n for n, s in zip(names, statuses) if s == "pqc"]
    if pq and classical:
        return " + ".join(dict.fromkeys(classical[:1] + pq)), "hybrid"
    return ", ".join(dict.fromkeys(names)), pqc.best(statuses) if pq else pqc.worst(statuses)


def info(d: dict) -> str:
    if d["kind"] == "esp":
        return f"ESP (SPI={d['spi']}, Seq={d['seq']})" + (" [UDP-encapsulated]" if d["udp_encap"] else "")
    s = f"IKEv{d['version']} {d['exchange']} {'response' if d.get('response') else 'request'} MID={d['msg_id']}"
    errs = [n["type"] for n in d["notify"] if n["error"]]
    if errs:
        s += f" [{', '.join(errs)}]"
    if d.get("ke"):
        s += f" KE={d['ke']['group']}"
    if d.get("frag"):
        s += f" Fragment {d['frag']['number']}/{d['frag']['total']}"
    return s
