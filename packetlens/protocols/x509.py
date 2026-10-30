"""Minimal X.509 v3 certificate parser (DER, RFC 5280) - enough to judge a certificate from a capture.

Extracts subject / issuer, validity, SAN, key algorithm and size, signature algorithm (including the
FIPS 204 ML-DSA and FIPS 205 SLH-DSA OIDs) and basic constraints. Never raises on malformed input.
"""
from __future__ import annotations

import calendar
import hashlib

from . import pqc

NAMES = {"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
         "1.2.840.113549.1.9.1": "emailAddress"}


class _DER:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes, i: int = 0):
        self.b, self.i = b, i

    def tlv(self):
        """(tag, content, start of element) and advance."""
        b, i = self.b, self.i
        start = i
        tag = b[i]
        ln = b[i + 1]
        i += 2
        if ln & 0x80:
            n = ln & 0x7F
            if not 1 <= n <= 4:
                raise ValueError("bad DER length")
            ln = int.from_bytes(b[i:i + n], "big")
            i += n
        if i + ln > len(b):
            raise ValueError("truncated DER")
        self.i = i + ln
        return tag, b[i:i + ln], start

    def more(self) -> bool:
        return self.i < len(self.b)


def _oid(c: bytes) -> str:
    if not c:
        return ""
    out = [c[0] // 40, c[0] % 40]
    v = 0
    for x in c[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            out.append(v)
            v = 0
    return ".".join(map(str, out))


def _time(tag: int, c: bytes) -> float | None:
    s = c.decode("ascii", "replace").rstrip("Z")
    try:
        if tag == 0x17:                       # UTCTime YYMMDDHHMM[SS]
            y = int(s[:2])
            y += 2000 if y < 50 else 1900
            s = str(y) + s[2:]
        y, mo, d, h, mi = int(s[:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]), int(s[10:12])
        sec = int(s[12:14]) if len(s) >= 14 else 0
        return float(calendar.timegm((y, mo, d, h, mi, sec, 0, 0, 0)))
    except (ValueError, IndexError):
        return None


def _name(c: bytes) -> dict:
    out: dict = {}
    seq = _DER(c)
    while seq.more():
        _, rdn, _ = seq.tlv()
        st = _DER(rdn)
        while st.more():
            _, atv, _ = st.tlv()
            a = _DER(atv)
            _, o, _ = a.tlv()
            _, v, _ = a.tlv()
            out.setdefault(NAMES.get(_oid(o), _oid(o)), v.decode("utf-8", "replace"))
    return out


def _dn(n: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in n.items())


def parse(der: bytes) -> dict | None:
    try:
        return _parse(der)
    except (ValueError, IndexError):
        return None


def _parse(der: bytes) -> dict:
    cert = _DER(_DER(der).tlv()[1])
    _, tbs, _ = cert.tlv()
    _, sigalg, _ = cert.tlv()
    t = _DER(tbs)
    tag, c, _ = t.tlv()
    version = 1
    if tag == 0xA0:
        version = _DER(c).tlv()[1][0] + 1
        tag, c, _ = t.tlv()
    serial = c.hex()
    t.tlv()                                   # inner signature algorithm (same as outer)
    _, issuer, _ = t.tlv()
    _, validity, _ = t.tlv()
    _, subject, _ = t.tlv()
    _, spki, _ = t.tlv()
    v = _DER(validity)
    nb = _time(*v.tlv()[:2])
    na = _time(*v.tlv()[:2])
    sp = _DER(spki)
    _, alg, _ = sp.tlv()
    _, keybits, _ = sp.tlv()
    a = _DER(alg)
    key_oid = _oid(a.tlv()[1])
    params = a.tlv() if a.more() else None
    key_name, key_status = pqc.oid(key_oid)
    key_size, curve = None, None
    if key_name == "RSA":
        try:
            rsa = _DER(_DER(keybits[1:]).tlv()[1])
            n = rsa.tlv()[1].lstrip(b"\x00")
            key_size = len(n) * 8 - (8 - n[0].bit_length())
        except (ValueError, IndexError):
            pass
    elif key_name == "EC" and params and params[0] == 0x06:
        curve = pqc.CURVES.get(_oid(params[1]), _oid(params[1]))
        key_size = {"P-256": 256, "P-384": 384, "P-521": 521, "secp256k1": 256}.get(curve)
    elif key_status != "pqc":                  # PQC keys are named by parameter set, not bit size
        key_size = (len(keybits) - 1) * 8
    sig_oid = _oid(_DER(sigalg).tlv()[1])
    sig_name, sig_status = pqc.oid(sig_oid)
    san, ca, path_len = [], None, None
    while t.more():
        tag, c, _ = t.tlv()
        if tag != 0xA3:
            continue
        exts = _DER(_DER(c).tlv()[1])
        while exts.more():
            e = _DER(exts.tlv()[1])
            eo = _oid(e.tlv()[1])
            tag2, val, _ = e.tlv()
            if tag2 == 0x01:                  # critical flag
                tag2, val, _ = e.tlv()
            if eo == "2.5.29.17":
                g = _DER(_DER(val).tlv()[1])
                while g.more():
                    gt, gv, _ = g.tlv()
                    if gt == 0x82:
                        san.append(gv.decode("ascii", "replace"))
                    elif gt == 0x87 and len(gv) == 4:
                        san.append(".".join(map(str, gv)))
            elif eo == "2.5.29.19":
                bc = _DER(_DER(val).tlv()[1])
                ca = False
                while bc.more():
                    bt, bv, _ = bc.tlv()
                    if bt == 0x01:
                        ca = bool(bv and bv[0])
                    elif bt == 0x02:
                        path_len = int.from_bytes(bv, "big")
    subj, iss = _name(subject), _name(issuer)
    return {"version": version, "serial": serial, "subject": _dn(subj), "issuer": _dn(iss),
            "cn": subj.get("CN"), "issuer_cn": iss.get("CN"), "self_signed": subject == issuer,
            "not_before": nb, "not_after": na, "san": san[:50], "ca": ca, "path_len": path_len,
            "key_alg": key_name, "key_size": key_size, "curve": curve, "key_status": key_status,
            "sig_alg": sig_name, "sig_status": sig_status,
            "sha256": hashlib.sha256(der).hexdigest()}


def parse_chain(body: bytes, tls13: bool = False) -> list[dict]:
    """Certificate handshake body (TLS 1.2: 3-byte list length + [3-byte len + DER]*;
    TLS 1.3 adds a request context before and an extension block after every entry)."""
    out = []
    i = 0
    if tls13:
        i = 1 + body[0]
    total = int.from_bytes(body[i:i + 3], "big")
    i += 3
    end = min(len(body), i + total)
    while i + 3 <= end:
        ln = int.from_bytes(body[i:i + 3], "big")
        i += 3
        c = parse(body[i:i + ln])
        if c:
            out.append(c)
        i += ln
        if tls13 and i + 2 <= end:
            i += 2 + int.from_bytes(body[i:i + 2], "big")
    return out
