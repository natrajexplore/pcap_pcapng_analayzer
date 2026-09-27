"""Network access control: IEEE 802.1X EAPOL / EAP (RFC 3748) and RADIUS (RFC 2865/2866)."""
from __future__ import annotations

import ipaddress
import struct

EAPOL_TYPES = {0: "EAP-Packet", 1: "EAPOL-Start", 2: "EAPOL-Logoff", 3: "EAPOL-Key"}
EAP_CODES = {1: "Request", 2: "Response", 3: "Success", 4: "Failure"}
EAP_METHODS = {1: "Identity", 2: "Notification", 3: "NAK", 4: "MD5-Challenge", 6: "GTC", 13: "EAP-TLS",
               21: "EAP-TTLS", 25: "PEAP", 26: "MSCHAPv2", 43: "EAP-FAST"}
RADIUS_CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 4: "Accounting-Request",
                5: "Accounting-Response", 11: "Access-Challenge", 12: "Status-Server", 40: "Disconnect-Request",
                41: "Disconnect-ACK", 42: "Disconnect-NAK", 43: "CoA-Request", 44: "CoA-ACK", 45: "CoA-NAK"}
RADIUS_PORTS = {1812, 1813, 1645, 1646, 3799}
ACCT_STATUS = {1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}


def parse_eap(buf: bytes) -> dict | None:
    if len(buf) < 4:
        return None
    code, ident, ln = struct.unpack("!BBH", buf[:4])
    d = {"code": EAP_CODES.get(code, str(code)), "id": ident}
    if code in (1, 2) and ln >= 5 and len(buf) >= 5:
        d["method"] = EAP_METHODS.get(buf[4], str(buf[4]))
        if buf[4] == 1:
            d["identity"] = buf[5:ln].decode("latin-1", "replace")
        elif buf[4] == 3 and ln > 5:
            d["desired"] = [EAP_METHODS.get(x, str(x)) for x in buf[5:ln]]
    return d


def parse_eapol(buf: bytes) -> dict | None:
    if len(buf) < 4 or buf[1] not in EAPOL_TYPES:
        return None
    ver, typ, ln = struct.unpack("!BBH", buf[:4])
    d: dict = {"version": ver, "type": EAPOL_TYPES[typ]}
    if typ == 0:
        eap = parse_eap(buf[4:4 + ln])
        if eap:
            d["eap"] = eap
    return d


def eapol_info(d: dict) -> str:
    e = d.get("eap")
    if not e:
        return d["type"]
    s = f"EAP {e['code']}"
    if "method" in e:
        s += f", {e['method']}"
    if e.get("identity"):
        s += f" (identity {e['identity']})"
    return s


def parse_radius(buf: bytes) -> dict | None:
    if len(buf) < 20:
        return None
    code, ident, ln = struct.unpack("!BBH", buf[:4])
    if code not in RADIUS_CODES or not 20 <= ln <= len(buf):
        return None
    d: dict = {"code": RADIUS_CODES[code], "code_num": code, "id": ident, "eap": []}
    off = 20
    while off + 2 <= ln:
        t, al = buf[off], buf[off + 1]
        if al < 2:
            break
        v = buf[off + 2:off + al]
        if t == 1:
            d["user"] = v.decode("latin-1", "replace")
        elif t == 4 and len(v) == 4:
            d["nas_ip"] = str(ipaddress.IPv4Address(v))
        elif t == 5 and len(v) == 4:
            d["nas_port"] = struct.unpack("!I", v)[0]
        elif t == 18:
            d["reply_message"] = v.decode("latin-1", "replace")
        elif t == 30:
            d["called_station"] = v.decode("latin-1", "replace")
        elif t == 31:
            d["calling_station"] = v.decode("latin-1", "replace")
        elif t == 32:
            d["nas_id"] = v.decode("latin-1", "replace")
        elif t == 40 and len(v) == 4:
            d["acct_status"] = ACCT_STATUS.get(struct.unpack("!I", v)[0], str(struct.unpack("!I", v)[0]))
        elif t == 79:
            d["eap"].append(v)
        off += al
    # EAP-Message may be split across attributes; decode the concatenated message
    parts = d.pop("eap")
    eap = parse_eap(b"".join(parts)) if parts else None
    if eap:
        d["eap"] = eap
    return d


def radius_info(d: dict) -> str:
    s = f"RADIUS {d['code']} id={d['id']}"
    if d.get("user"):
        s += f" user={d['user']}"
    if d.get("acct_status"):
        s += f" ({d['acct_status']})"
    if isinstance(d.get("eap"), dict):
        s += f" [EAP {d['eap']['code']}{', ' + d['eap']['method'] if 'method' in d['eap'] else ''}]"
    return s
