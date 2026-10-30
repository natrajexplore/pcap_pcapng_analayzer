"""QUIC (RFC 9000 / 9001, v2 RFC 9369): long/short headers, version negotiation, Retry, and Initial-packet
decryption (keys are derived from the public Destination Connection ID, so no secrets are needed). Decrypting
Initials recovers the TLS ClientHello / ServerHello inside CRYPTO frames: SNI, ALPN (h3), key-share groups
(ML-KEM). Decryption needs the optional ``cryptography`` package; headers decode without it."""
from __future__ import annotations

import hashlib
import hmac

from ..tlsdecrypt import hkdf_expand_label

try:  # optional dependency (AES-GCM payload + AES-ECB header protection)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except BaseException:  # pragma: no cover
    HAVE_CRYPTO = False

V1, V2 = 0x00000001, 0x6B3343CF
SALT = {V1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        V2: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")}
LABELS = {V1: ("quic key", "quic iv", "quic hp"), V2: ("quicv2 key", "quicv2 iv", "quicv2 hp")}
TYPES = {V1: {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}, V2: {1: "Initial", 2: "0-RTT", 3: "Handshake", 0: "Retry"}}


def version_name(v: int) -> str:
    if v == V1:
        return "1"
    if v == V2:
        return "2"
    if v == 0:
        return "negotiation"
    if v >> 8 == 0xFF0000:
        return f"draft-{v & 0xFF}"
    if v & 0x0F0F0F0F == 0x0A0A0A0A:
        return "grease"
    return f"0x{v:08x}"


def varint(b: bytes, i: int) -> tuple[int, int]:
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for k in range(1, n):
        v = (v << 8) | b[i + k]
    return v, i + n


def parse(buf: bytes) -> dict | None:
    """First QUIC packet of a UDP datagram (coalesced packets are counted, not decoded)."""
    if not buf:
        return None
    first = buf[0]
    if not first & 0x80:
        if not first & 0x40:
            return None
        return {"form": "short", "type": "1-RTT", "length": len(buf)}
    if len(buf) < 7:
        return None
    ver = int.from_bytes(buf[1:5], "big")
    dl = buf[5]
    if dl > 20 or 6 + dl >= len(buf):
        return None
    dcid = buf[6:6 + dl]
    sl = buf[6 + dl]
    scid = buf[7 + dl:7 + dl + sl]
    d = {"form": "long", "version": ver, "version_name": version_name(ver), "dcid": dcid.hex(), "scid": scid.hex(),
         "length": len(buf)}
    if ver == 0:
        vs = buf[7 + dl + sl:]
        d["type"] = "Version Negotiation"
        d["supported"] = [version_name(int.from_bytes(vs[i:i + 4], "big")) for i in range(0, len(vs) - 3, 4)]
        return d
    d["type"] = TYPES.get(ver, TYPES[V1]).get((first >> 4) & 0x03, "?")
    if d["type"] == "Initial":
        try:
            i = 7 + dl + sl
            tl, i = varint(buf, i)
            d["token_len"] = tl
            i += tl
            plen, i = varint(buf, i)
            d["pn_offset"], d["payload_len"] = i, plen
            d["coalesced"] = len(buf) > i + plen
        except IndexError:
            pass
    return d


def _keys(ver: int, dcid: bytes, server: bool):
    initial = hmac.new(SALT[ver], dcid, hashlib.sha256).digest()          # HKDF-Extract
    secret = hkdf_expand_label("sha256", initial, "server in" if server else "client in", b"", 32)
    lk, li, lh = LABELS[ver]
    return (hkdf_expand_label("sha256", secret, lk, b"", 16), hkdf_expand_label("sha256", secret, li, b"", 12),
            hkdf_expand_label("sha256", secret, lh, b"", 16))


def decrypt_initial(buf: bytes, odcid: bytes, server: bool) -> bytes | None:
    """Plaintext frames of an Initial packet. ``odcid``: the client's first Destination Connection ID."""
    if not HAVE_CRYPTO:
        return None
    d = parse(buf)
    if not d or d.get("type") != "Initial" or "pn_offset" not in d or d["version"] not in SALT:
        return None
    key, iv, hp = _keys(d["version"], odcid, server)
    pn_off = d["pn_offset"]
    sample = buf[pn_off + 4:pn_off + 20]
    if len(sample) < 16:
        return None
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first = buf[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn_bytes = bytes(b ^ m for b, m in zip(buf[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
    header = bytes([first]) + buf[1:pn_off] + pn_bytes
    pn = int.from_bytes(pn_bytes, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    end = pn_off + d["payload_len"]
    try:
        return AESGCM(key).decrypt(nonce, buf[pn_off + pn_len:end], header)
    except Exception:
        return None


def crypto_frames(plain: bytes) -> list[tuple[int, bytes]]:
    """[(offset, data)] of the CRYPTO frames in decrypted Initial frames (PADDING, PING, ACK skipped)."""
    out, i = [], 0
    try:
        while i < len(plain):
            ft = plain[i]
            if ft == 0x00:
                i += 1
            elif ft == 0x01:
                i += 1
            elif ft in (0x02, 0x03):
                i += 1
                _, i = varint(plain, i)                   # largest acknowledged
                _, i = varint(plain, i)                   # delay
                n, i = varint(plain, i)                   # range count
                _, i = varint(plain, i)                   # first range
                for _ in range(n):
                    _, i = varint(plain, i)
                    _, i = varint(plain, i)
                if ft == 0x03:
                    for _ in range(3):
                        _, i = varint(plain, i)
            elif ft == 0x06:
                off, i = varint(plain, i + 1)
                ln, i = varint(plain, i)
                out.append((off, plain[i:i + ln]))
                i += ln
            elif ft == 0x1C:                               # CONNECTION_CLOSE in Initial
                break
            else:
                break
    except IndexError:
        pass
    return out


def info(d: dict) -> str:
    if d["form"] == "short":
        return f"QUIC 1-RTT (short header, {d['length']} bytes)"
    if d["type"] == "Version Negotiation":
        return f"QUIC Version Negotiation (supported: {', '.join(d['supported'])})"
    s = f"QUIC v{d['version_name']} {d['type']}, DCID={d['dcid'][:16]}"
    if d.get("sni"):
        s += f", SNI={d['sni']}"
    return s
