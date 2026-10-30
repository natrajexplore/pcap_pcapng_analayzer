"""TLS record / handshake parser: ClientHello (SNI, ALPN, JA3, groups, key shares, signature algorithms,
ECH), ServerHello / HelloRetryRequest (selected key share), Certificate (X.509) and Alerts."""
from __future__ import annotations

import hashlib
import struct

from . import pqc, x509

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
ALERTS = {0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed",
          22: "record_overflow", 40: "handshake_failure", 42: "bad_certificate",
          43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
          46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca", 49: "access_denied",
          50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
          80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled",
          109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
          116: "certificate_required", 120: "no_application_protocol"}
# A representative set of weak / deprecated cipher suites.
WEAK_CIPHERS = {
    0x0000: "TLS_NULL_WITH_NULL_NULL", 0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
}
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
EXT_ECH = 0xFE0D
TLS12_RSA_KX = {0x000A, 0x002F, 0x0035, 0x003C, 0x003D, 0x009C, 0x009D, 0x0004, 0x0005}
TLS12_DHE_KX = {0x0016, 0x0033, 0x0039, 0x0067, 0x006B, 0x009E, 0x009F, 0xCCAA}
# Known-bad JA3 fingerprints (from public threat intel; Chris Greer's ThreatHunt profile flags Trickbot).
KNOWN_BAD_JA3 = {
    "6734f37431670b3ab4292b8f60f29984": "Trickbot",
    "72a589da586844d7f0818ce684948eea": "Metasploit / Meterpreter",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (default)",
    "e7d705a3286e19ea42f587b344ee6865": "Tor client",
}


def looks_like_tls(payload: bytes) -> bool:
    return len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4


def parse(payload: bytes) -> dict | None:
    if not looks_like_tls(payload):
        return None
    out: dict = {"records": [], "handshakes": []}
    off = 0
    while off + 5 <= len(payload):
        ctype, ver, ln = struct.unpack("!BHH", payload[off:off + 5])
        if ctype not in (20, 21, 22, 23) or ver >> 8 != 3:
            break
        frag = payload[off + 5:off + 5 + ln]
        out["records"].append({"type": ctype, "version": VERSIONS.get(ver, hex(ver))})
        if ctype == 22:
            _handshake(frag, out)
        elif ctype == 21 and ln == 2 and len(frag) == 2:
            out["alert"] = {"level": "fatal" if frag[0] == 2 else "warning",
                            "description": ALERTS.get(frag[1], str(frag[1])), "code": frag[1]}
        off += 5 + ln
    return out if out["records"] else None


def _handshake(frag: bytes, out: dict) -> None:
    off = 0
    while off + 4 <= len(frag):
        htype = frag[off]
        hlen = int.from_bytes(frag[off + 1:off + 4], "big")
        body = frag[off + 4:off + 4 + hlen]
        out["handshakes"].append(htype)
        try:
            if htype == 1:
                out["client_hello"] = _client_hello(body)
            elif htype == 2:
                out["server_hello"] = _server_hello(body)
            elif htype == 11 and len(body) == hlen:
                out["certificates"] = x509.parse_chain(body)
        except (struct.error, IndexError, ValueError):
            pass
        off += 4 + hlen
        if hlen == 0 or len(body) < hlen:
            break


def _exts(buf: bytes, off: int):
    if off + 2 > len(buf):
        return
    total = struct.unpack("!H", buf[off:off + 2])[0]
    off += 2
    end = min(off + total, len(buf))
    while off + 4 <= end:
        et, el = struct.unpack("!HH", buf[off:off + 4])
        yield et, buf[off + 4:off + 4 + el]
        off += 4 + el


def _client_hello(b: bytes) -> dict:
    ver = struct.unpack("!H", b[:2])[0]
    off = 34
    off += 1 + b[off]                      # session id
    cl = struct.unpack("!H", b[off:off + 2])[0]
    ciphers = [struct.unpack("!H", b[off + 2 + i:off + 4 + i])[0] for i in range(0, cl, 2)]
    off += 2 + cl
    off += 1 + b[off]                      # compression methods
    sni = None
    alpn: list[str] = []
    exts, curves, pfmts, sup_versions, shares, sigs = [], [], [], [], [], []
    ech = False
    for et, ed in _exts(b, off):
        exts.append(et)
        if et == 0 and len(ed) > 5:
            nl = struct.unpack("!H", ed[3:5])[0]
            sni = ed[5:5 + nl].decode("latin-1")
        elif et == 16 and len(ed) > 2:
            i = 2
            while i < len(ed):
                ln = ed[i]
                alpn.append(ed[i + 1:i + 1 + ln].decode("latin-1"))
                i += 1 + ln
        elif et == 10 and len(ed) >= 2:
            curves = [struct.unpack("!H", ed[2 + i:4 + i])[0] for i in range(0, struct.unpack("!H", ed[:2])[0], 2)]
        elif et == 11 and ed:
            pfmts = list(ed[1:1 + ed[0]])
        elif et == 43 and ed:
            sup_versions = [struct.unpack("!H", ed[1 + i:3 + i])[0] for i in range(0, ed[0], 2)]
        elif et == 13 and len(ed) >= 2:
            sigs = [struct.unpack("!H", ed[2 + i:4 + i])[0] for i in range(0, min(struct.unpack("!H", ed[:2])[0], len(ed) - 2), 2)]
        elif et == 51 and len(ed) >= 2:
            i, end = 2, min(len(ed), 2 + struct.unpack("!H", ed[:2])[0])
            while i + 4 <= end:
                g, kl = struct.unpack("!HH", ed[i:i + 4])
                shares.append((g, kl))
                i += 4 + kl
        elif et == EXT_ECH:
            ech = True
    ng = lambda xs: [x for x in xs if x not in GREASE]  # noqa: E731
    ja3_str = ",".join([str(ver), "-".join(map(str, ng(ciphers))), "-".join(map(str, ng(exts))),
                        "-".join(map(str, ng(curves))), "-".join(map(str, pfmts))])
    ja3 = hashlib.md5(ja3_str.encode()).hexdigest()
    sv = [v for v in ng(sup_versions)]
    max_ver = max(sv) if sv else ver
    return {"version": VERSIONS.get(ver, hex(ver)), "max_version": VERSIONS.get(max_ver, hex(max_ver)),
            "max_version_num": max_ver, "sni": sni, "random": b[2:34].hex(), "alpn": alpn, "ciphers": ciphers,
            "weak_ciphers": [WEAK_CIPHERS[c] for c in ciphers if c in WEAK_CIPHERS],
            "ja3": ja3, "ja3_str": ja3_str, "known_bad": KNOWN_BAD_JA3.get(ja3),
            "groups": [pqc.tls_group(g)[0] for g in ng(curves)], "group_codes": ng(curves),
            "key_shares": [{"group": pqc.tls_group(g)[0], "code": g, "len": kl, "status": pqc.tls_group(g)[1]}
                           for g, kl in shares if g not in GREASE],
            "sig_algs": [pqc.tls_sig(x)[0] for x in ng(sigs)], "sig_codes": ng(sigs),
            "pqc_offered": [pqc.tls_group(g)[0] for g in ng(curves) if pqc.tls_group(g)[1] in ("pqc", "hybrid", "draft")],
            "pqc_sigs_offered": [pqc.tls_sig(x)[0] for x in ng(sigs) if pqc.tls_sig(x)[1] == "pqc"],
            "ech": ech, "length": len(b) + 4}


def _server_hello(b: bytes) -> dict:
    ver = struct.unpack("!H", b[:2])[0]
    off = 34
    off += 1 + b[off]
    cipher = struct.unpack("!H", b[off:off + 2])[0]
    off += 3
    alpn = None
    hrr = b[2:34] == HRR_RANDOM
    group = None
    for et, ed in _exts(b, off):
        if et == 43 and len(ed) == 2:
            ver = struct.unpack("!H", ed)[0]
        elif et == 16 and len(ed) > 3:
            alpn = ed[3:3 + ed[2]].decode("latin-1")
        elif et == 51 and len(ed) >= 2:          # ServerHello: group + key; HelloRetryRequest: group only
            group = struct.unpack("!H", ed[:2])[0]
    d = {"version": VERSIONS.get(ver, hex(ver)), "version_num": ver, "cipher": cipher,
         "weak_cipher": WEAK_CIPHERS.get(cipher), "random": b[2:34].hex(), "alpn": alpn, "hrr": hrr}
    if group is not None:
        d["group"], d["group_status"] = pqc.tls_group(group)
        d["group_code"] = group
    return d


def key_exchange(sh: dict) -> tuple[str, str]:
    """(name, PQC status) of the key exchange a ServerHello settled on."""
    if sh.get("group"):
        return sh["group"], sh["group_status"]
    c = sh.get("cipher")
    if c in TLS12_RSA_KX:
        return "RSA key transport (no forward secrecy)", "weak"
    if c in TLS12_DHE_KX:
        return "DHE", "classical"
    if c is not None and (0xC000 <= c <= 0xC0FF or 0xCCA8 <= c <= 0xCCA9):
        return "ECDHE", "classical"
    return "unknown", "unknown"


def info(d: dict) -> str:
    parts = []
    if "client_hello" in d:
        ch = d["client_hello"]
        parts.append("Client Hello" + (f" (SNI={ch['sni']})" if ch["sni"] else "") + (" [PQC]" if ch.get("pqc_offered") else ""))
    if "server_hello" in d:
        sh = d["server_hello"]
        parts.append("Hello Retry Request" if sh.get("hrr") else "Server Hello" + (f" ({sh['group']})" if sh.get("group") else ""))
    if d.get("certificates"):
        parts.append(f"Certificate ({d['certificates'][0].get('cn') or 'chain'})")
    if "alert" in d:
        parts.append(f"Alert ({d['alert']['level']}, {d['alert']['description']})")
    if not parts:
        parts.append("Application Data" if any(r["type"] == 23 for r in d["records"]) else "TLS record")
    return ", ".join(parts)
