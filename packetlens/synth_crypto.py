"""Synthetic crypto / post-quantum traffic for the demo capture and the test-suite.

TLS 1.3 with hybrid ML-KEM (X25519MLKEM768), PQC offered but not selected, HelloRetryRequest, a large PQC
ClientHello killed by a middlebox, draft Kyber, ECH, TLS 1.2 certificates (weak / expired / ML-DSA),
SSH (PQC, weak, Terrapin, failed KEX), IKEv2 with RFC 9370 ML-KEM, IKE failures, IKEv1 aggressive mode,
ESP sequence anomalies, MACsec (encrypted, integrity-only, PN gaps, PN exhaustion), MKA and EAP-TLS.
Key material is filler: only the structure and sizes are real.
"""
from __future__ import annotations

import struct
import time

from .synth import T0, Conv, client_hello as ch12

GW = "00:00:5e:00:53:01"
YEAR = 365 * 86400


# ------------------------------------------------------------------ DER ---
def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body


def _seq(*parts) -> bytes:
    return _der(0x30, b"".join(parts))


def _oid(s: str) -> bytes:
    a = list(map(int, s.split(".")))
    out = bytes([a[0] * 40 + a[1]])
    for v in a[2:]:
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return _der(0x06, out)


def _name(cn: str, org: str = "PacketLens Lab") -> bytes:
    rdn = lambda o, v: _der(0x31, _seq(_oid(o), _der(0x0C, v.encode())))  # noqa: E731
    return _seq(rdn("2.5.4.6", "US"), rdn("2.5.4.10", org), rdn("2.5.4.3", cn))


def _utc(ts: float) -> bytes:
    return _der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(ts)).encode())


def certificate(cn, issuer, not_before, not_after, key="rsa", bits=2048, sig="1.2.840.113549.1.1.11", san=(), ca=False) -> bytes:
    if key == "rsa":
        n = b"\xc1" + b"\x5a" * (bits // 8 - 1)
        spki = _seq(_seq(_oid("1.2.840.113549.1.1.1"), b"\x05\x00"),
                    _der(0x03, b"\x00" + _seq(_der(0x02, b"\x00" + n), _der(0x02, b"\x01\x00\x01"))))
    elif key == "ec":
        spki = _seq(_seq(_oid("1.2.840.10045.2.1"), _oid("1.2.840.10045.3.1.7")), _der(0x03, b"\x00\x04" + b"\x33" * 64))
    else:                                       # ML-DSA OID; public key sizes from FIPS 204
        size = {"2.16.840.1.101.3.4.3.17": 1312, "2.16.840.1.101.3.4.3.18": 1952, "2.16.840.1.101.3.4.3.19": 2592}[key]
        spki = _seq(_seq(_oid(key)), _der(0x03, b"\x00" + b"\x44" * size))
    exts = []
    if san:
        exts.append(_seq(_oid("2.5.29.17"), _der(0x04, _seq(*[_der(0x82, s.encode()) for s in san]))))
    exts.append(_seq(_oid("2.5.29.19"), _der(0x01, b"\xff"), _der(0x04, _seq(_der(0x01, b"\xff")) if ca else _seq())))
    sig_alg = _seq(_oid(sig), b"\x05\x00") if sig.startswith("1.2.840.113549") else _seq(_oid(sig))
    tbs = _seq(_der(0xA0, _der(0x02, b"\x02")), _der(0x02, b"\x10\x20\x30\x40"), sig_alg, _name(issuer),
               _seq(_utc(not_before), _utc(not_after)), _name(cn), spki, _der(0xA3, _seq(*exts)))
    sig_len = {"2.16.840.1.101.3.4.3.17": 2420, "2.16.840.1.101.3.4.3.18": 3309, "2.16.840.1.101.3.4.3.19": 4627}.get(sig, 256)
    return _seq(tbs, sig_alg, _der(0x03, b"\x00" + b"\x55" * sig_len))


def cert_msg(chain) -> bytes:
    lst = b"".join(len(c).to_bytes(3, "big") + c for c in chain)
    body = len(lst).to_bytes(3, "big") + lst
    return b"\x0b" + len(body).to_bytes(3, "big") + body


# ------------------------------------------------------------------ TLS ---
def _ext(t, body):
    return struct.pack("!HH", t, len(body)) + body


def client_hello(sni, groups, shares, sigs=(0x0403, 0x0804, 0x0401), ech=False) -> bytes:
    ext = b""
    sn = sni.encode()
    ext += _ext(0, struct.pack("!HBH", len(sn) + 3, 0, len(sn)) + sn)
    ext += _ext(10, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups))
    ext += _ext(13, struct.pack("!H", 2 * len(sigs)) + b"".join(struct.pack("!H", s) for s in sigs))
    ext += _ext(16, b"\x00\x03\x02h2")
    ext += _ext(43, b"\x04\x03\x04\x03\x03")
    ks = b"".join(struct.pack("!HH", g, n) + bytes([0x42]) * n for g, n in shares)
    ext += _ext(51, struct.pack("!H", len(ks)) + ks)
    if any(n > 1000 for _, n in shares):        # browsers pad/GREASE: a real PQC ClientHello is about 1.8 KB
        ext += _ext(21, b"\x00" * 380)
    if ech:
        ext += _ext(0xFE0D, b"\x00\x00\x01\x00\x01\x07" + b"\x20" + b"\x66" * 32 + b"\x00\x90" + b"\x77" * 0x90)
    ciphers = (0x1301, 0x1302, 0x1303)
    body = b"\x03\x03" + b"\x11" * 32 + b"\x20" + b"\x01" * 32 + struct.pack("!H", 2 * len(ciphers)) + \
        b"".join(struct.pack("!H", c) for c in ciphers) + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


def server_hello13(group, key_len, hrr=False) -> bytes:
    rnd = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") if hrr else b"\x22" * 32
    ks = struct.pack("!H", group) if hrr else struct.pack("!HH", group, key_len) + b"\x43" * key_len
    ext = _ext(43, b"\x03\x04") + _ext(51, ks)
    body = b"\x03\x03" + rnd + b"\x20" + b"\x01" * 32 + struct.pack("!HB", 0x1301, 0) + struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    rec = struct.pack("!BHH", 22, 0x0303, len(hs)) + hs
    return rec if hrr else rec + b"\x14\x03\x03\x00\x01\x01" + struct.pack("!BHH", 23, 0x0303, 40) + b"\x99" * 40


def tls12_server_flight(chain, cipher=0xC02F) -> bytes:
    body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + struct.pack("!HB", cipher, 0) + b"\x00\x00"
    hs = b"\x02" + len(body).to_bytes(3, "big") + body + cert_msg(chain) + b"\x0e\x00\x00\x00"
    out = b""
    for i in range(0, len(hs), 16000):          # handshake split over records if needed
        out += struct.pack("!BHH", 22, 0x0303, len(hs[i:i + 16000])) + hs[i:i + 16000]
    return out


def _send(conv, side, t, data, mss=1448, dt=0.0002):
    for i in range(0, len(data), mss):
        (conv.c if side == "c" else conv.s)(t + i // mss * dt, 0x18, data[i:i + mss])
    return t + (len(data) // mss + 1) * dt


def _tls13_session(g, cip, sip, cport, sni, groups, shares, sh_group, sh_len, t, ech=False, sigs=(0x0403, 0x0804)):
    c = Conv(g, "00:50:56:0a:00:10", GW, cip, sip, cport, 443, ttl_s=52)
    t = c.handshake(t, rtt_s=0.018)
    t = _send(c, "c", t + 0.001, client_hello(sni, groups, shares, sigs, ech))
    c.s(t + 0.018, 0x10)
    _send(c, "s", t + 0.019, server_hello13(sh_group, sh_len))
    c.c(t + 0.040, 0x18, struct.pack("!BHH", 23, 0x0303, 60) + b"\x98" * 60)
    c.s(t + 0.060, 0x18, struct.pack("!BHH", 23, 0x0303, 300) + b"\x97" * 300)
    c.close(t + 0.2)


def build_tls(g, t0=400.0):
    hyb = [(0x11EC, 1216), (0x001D, 32)]
    _tls13_session(g, "10.70.0.10", "104.16.10.1", 51001, "pq.example-cdn.net", [0x11EC, 0x1D, 0x17], hyb, 0x11EC, 1120, t0,
                   sigs=(0x0905, 0x0403, 0x0804))
    _tls13_session(g, "10.70.0.10", "198.51.100.20", 51002, "legacy-api.example.com", [0x11EC, 0x1D, 0x17], hyb, 0x1D, 32, t0 + 1)
    _tls13_session(g, "10.70.0.11", "198.51.100.30", 51003, "old-browser.example.org", [0x6399, 0x1D], [(0x6399, 1216), (0x1D, 32)],
                   0x6399, 1120, t0 + 2)
    _tls13_session(g, "10.70.0.12", "104.16.20.2", 51004, "cloudflare-ech.com", [0x11EC, 0x1D], hyb, 0x11EC, 1120, t0 + 3, ech=True)
    # HelloRetryRequest: client predicted X25519, server insists on X25519MLKEM768
    c = Conv(g, "00:50:56:0a:00:13", GW, "10.70.0.13", "203.0.113.40", 51005, 443, ttl_s=50)
    t = c.handshake(t0 + 4, rtt_s=0.03)
    _send(c, "c", t + 0.001, client_hello("hrr.example.net", [0x11EC, 0x1D], [(0x1D, 32)]))
    c.s(t + 0.031, 0x18, server_hello13(0x11EC, 0, hrr=True))
    _send(c, "c", t + 0.032, client_hello("hrr.example.net", [0x11EC, 0x1D], [(0x11EC, 1216)]))
    _send(c, "s", t + 0.062, server_hello13(0x11EC, 1120))
    c.close(t + 0.3)
    # large PQC ClientHello through a legacy firewall: second segment never acknowledged, then a forged RST
    c = Conv(g, "00:50:56:0a:00:14", GW, "10.70.0.14", "10.80.0.5", 51006, 443, ttl_s=62)
    t = c.handshake(t0 + 5, rtt_s=0.002)
    ch = client_hello("intranet.corp.example", [0x11EC, 0x1D, 0x17], hyb)
    seq0 = c.cseq
    c.c(t + 0.001, 0x18, ch[:1448])
    c.c(t + 0.0012, 0x18, ch[1448:])
    c.s(t + 0.004, 0x10, ack=seq0 + 1448)
    for k, dt in enumerate((0.2, 0.6, 1.4)):
        c.c(t + 0.0012 + dt, 0x18, ch[1448:], seq=seq0 + 1448)
    c.s(t + 3.0, 0x14, ack=seq0 + 1448, ttl=250)
    # TLS 1.2 with certificates visible in cleartext
    now = T0 + t0
    weak = certificate("printer.lab.local", "printer.lab.local", now - 6 * YEAR, now - 40 * 86400, bits=1024,
                       sig="1.2.840.113549.1.1.5", san=("printer.lab.local",))
    leaf = certificate("pqc-pki.example", "PQC Issuing CA", now - 30 * 86400, now + YEAR, key="2.16.840.1.101.3.4.3.18",
                       sig="2.16.840.1.101.3.4.3.18", san=("pqc-pki.example",))
    inter = certificate("PQC Issuing CA", "PQC Root CA", now - YEAR, now + 5 * YEAR, key="2.16.840.1.101.3.4.3.19",
                        sig="2.16.840.1.101.3.4.3.19", ca=True)
    for i, (sni, sip, chain) in enumerate((("printer.lab.local", "10.70.5.5", [weak]),
                                           ("pqc-pki.example", "192.0.2.80", [leaf, inter]))):
        c = Conv(g, "00:50:56:0a:00:15", GW, "10.70.0.15", sip, 51010 + i, 443, ttl_s=60)
        t = c.handshake(t0 + 9 + i, rtt_s=0.004)
        c.c(t + 0.001, 0x18, ch12(sni, ciphers=(0xC02F, 0xC030)))
        t2 = _send(c, "s", t + 0.005, tls12_server_flight(chain))
        c.c(t2 + 0.001, 0x10)
        c.close(t2 + 0.1)


# ------------------------------------------------------------------ SSH ---
def _kexinit(kex, hostkey, enc, mac) -> bytes:
    lst = lambda xs: struct.pack("!I", len(",".join(xs))) + ",".join(xs).encode()  # noqa: E731
    payload = b"\x14" + b"\x5c" * 16 + lst(kex) + lst(hostkey) + lst(enc) + lst(enc) + lst(mac) + lst(mac) + \
        lst(["none"]) + lst(["none"]) + lst([]) + lst([]) + b"\x00" + b"\x00\x00\x00\x00"
    return _ssh_pkt(payload)


def _ssh_pkt(payload: bytes) -> bytes:
    pad = 4 + (-(len(payload) + 5 + 4)) % 8      # RFC 4253: >= 4 bytes, packet a multiple of 8 (>= 16)
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def _ssh_session(g, cip, sip, cport, cbanner, sbanner, ckex, skex, t, disconnect=None):
    c = Conv(g, "00:50:56:0a:01:01", GW, cip, sip, cport, 22, ttl_s=63)
    t = c.handshake(t, rtt_s=0.003)
    c.c(t + 0.001, 0x18, cbanner + b"\r\n")
    c.s(t + 0.004, 0x18, sbanner + b"\r\n")
    _send(c, "c", t + 0.005, _kexinit(*ckex))
    _send(c, "s", t + 0.008, _kexinit(*skex))
    if disconnect:
        msg = disconnect.encode()
        c.s(t + 0.009, 0x18, _ssh_pkt(b"\x01" + struct.pack("!I", 3) + struct.pack("!I", len(msg)) + msg + b"\x00\x00\x00\x00"))
        c.close(t + 0.01)
        return
    c.c(t + 0.010, 0x18, _ssh_pkt(b"\x1e" + struct.pack("!I", 1216) + b"\x42" * 1216))
    c.s(t + 0.014, 0x18, _ssh_pkt(b"\x1f" + b"\x00" * 1200) + _ssh_pkt(b"\x15"))
    c.c(t + 0.015, 0x18, _ssh_pkt(b"\x15") + b"\x88" * 64)
    c.s(t + 0.020, 0x18, b"\x87" * 96)
    c.close(t + 0.2)


def build_ssh(g, t0=420.0):
    modern = (["mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"],
              ["ssh-ed25519", "rsa-sha2-512"], ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"],
              ["hmac-sha2-256-etm@openssh.com"])
    modern_s = (["mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256", "kex-strict-s-v00@openssh.com"],
                ["ssh-ed25519"], ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"], ["hmac-sha2-256-etm@openssh.com"])
    _ssh_session(g, "10.71.0.10", "10.71.1.10", 52001, b"SSH-2.0-OpenSSH_10.0", b"SSH-2.0-OpenSSH_10.0", modern, modern_s, t0)
    legacy_s = (["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"], ["ssh-rsa"], ["aes128-cbc", "3des-cbc"], ["hmac-sha1", "hmac-md5"])
    legacy_c = (["curve25519-sha256", "diffie-hellman-group14-sha1"], ["ssh-ed25519", "ssh-rsa"], ["aes128-ctr", "aes128-cbc"], ["hmac-sha1"])
    _ssh_session(g, "10.71.0.11", "10.71.1.11", 52002, b"SSH-2.0-OpenSSH_7.4", b"SSH-2.0-Cisco-1.25", legacy_c, legacy_s, t0 + 1)
    terr_c = (["curve25519-sha256", "ecdh-sha2-nistp256"], ["ssh-ed25519"], ["chacha20-poly1305@openssh.com"], ["hmac-sha2-256"])
    terr_s = (["curve25519-sha256"], ["ssh-ed25519"], ["chacha20-poly1305@openssh.com", "aes128-ctr"], ["hmac-sha2-256"])
    _ssh_session(g, "10.71.0.12", "10.71.1.12", 52003, b"SSH-2.0-PuTTY_Release_0.79", b"SSH-2.0-OpenSSH_8.9p1", terr_c, terr_s, t0 + 2)
    old_c = (["diffie-hellman-group1-sha1"], ["ssh-rsa"], ["aes128-cbc"], ["hmac-sha1"])
    _ssh_session(g, "10.71.0.13", "10.71.1.14", 52004, b"SSH-2.0-libssh_0.6.0", b"SSH-2.0-OpenSSH_10.0", old_c, modern_s, t0 + 3,
                 disconnect="no matching key exchange method found")


# ------------------------------------------------------------- IKE/ESP ----
def _pl(nxt, body):
    return struct.pack("!BBH", nxt, 0, 4 + len(body)) + body


def _transform(last, ttype, tid, keylen=None):
    attr = struct.pack("!HH", 0x800E, keylen) if keylen else b""
    return struct.pack("!BBHBBH", 0 if last else 3, 0, 8 + len(attr), ttype, 0, tid) + attr


def _proposal(transforms, proto=1, num=1, last=True):
    body = b"".join(_transform(i == len(transforms) - 1, *t) for i, t in enumerate(transforms))
    return struct.pack("!BBHBBBB", 0 if last else 2, 0, 8 + len(body), num, proto, 0, len(transforms)) + body


def _notify(nt, data=b""):
    return struct.pack("!BBH", 0, 0, nt) + data


def ike2(ispi, rspi, exch, response, mid, payloads) -> bytes:
    """payloads: [(type, body)]; generic headers chained."""
    body = b""
    for i, (pt, pb) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        body += _pl(nxt, pb)
    flags = 0x20 if response else 0x08
    return ispi + rspi + struct.pack("!BBBBII", payloads[0][0] if payloads else 0, 0x20, exch, flags, mid, 28 + len(body)) + body


def build_ike(g, t0=440.0):
    mac_a, mac_b = "00:00:0c:9a:00:01", "00:00:0c:9a:00:02"
    pq = [(1, 20, 256), (2, 5), (4, 19), (6, 36)]     # AES-GCM-16-256, PRF-SHA256, ECP-256 + ADDKE1 ML-KEM-768
    i1, r1 = b"\xa1" * 8, b"\xb1" * 8
    frag = (41, _notify(16430))
    inter = (41, _notify(16438))
    sa_init = [(33, _proposal(pq)), (34, struct.pack("!HH", 19, 0) + b"\x31" * 64), (40, b"\x4e" * 32), frag, inter]
    g.udp(t0, mac_a, mac_b, "10.90.0.1", "10.90.0.2", 500, 500, ike2(i1, b"\x00" * 8, 34, False, 0, sa_init))
    g.udp(t0 + 0.01, mac_b, mac_a, "10.90.0.2", "10.90.0.1", 500, 500, ike2(i1, r1, 34, True, 0, sa_init))
    for k, (ex, mid) in enumerate(((43, 1), (35, 2))):   # IKE_INTERMEDIATE (ML-KEM shares, encrypted), IKE_AUTH
        for resp in (False, True):
            src, dst = ("10.90.0.2", "10.90.0.1") if resp else ("10.90.0.1", "10.90.0.2")
            g.udp(t0 + 0.02 + k * 0.02 + resp * 0.01, mac_b if resp else mac_a, mac_a if resp else mac_b, src, dst, 4500, 4500,
                  b"\x00" * 4 + ike2(i1, r1, ex, resp, mid, [(46, b"\x00" * 8 + b"\x5e" * (1250 if ex == 43 else 400))]))
    seqs = list(range(1, 41))
    seqs = [s for s in seqs if s not in (20, 21, 22)] + [30]       # three lost, one replayed
    for k, s in enumerate(sorted(seqs)):
        g.ipv4(t0 + 0.1 + k * 0.01, mac_a, mac_b, "10.90.0.1", "10.90.0.2", 50, struct.pack("!II", 0xC0FFEE01, s) + b"\x6a" * 120)
    # NO_PROPOSAL_CHOSEN: initiator requires ML-KEM, responder has none
    i2 = b"\xa2" * 8
    g.udp(t0 + 1, mac_a, mac_b, "10.90.1.1", "10.90.1.2", 500, 500,
          ike2(i2, b"\x00" * 8, 34, False, 0, [(33, _proposal([(1, 20, 256), (2, 5), (4, 31), (6, 37)])),
                                               (34, struct.pack("!HH", 31, 0) + b"\x31" * 32), (40, b"\x4e" * 32)]))
    g.udp(t0 + 1.01, mac_b, mac_a, "10.90.1.2", "10.90.1.1", 500, 500, ike2(i2, b"\x00" * 8, 34, True, 0, [(41, _notify(14))]))
    # ML-KEM negotiated, responder without IKEv2 fragmentation: big IKE_INTERMEDIATE never answered
    i3, r3 = b"\xa3" * 8, b"\xb3" * 8
    g.udp(t0 + 2, mac_a, mac_b, "10.90.2.1", "10.90.2.2", 500, 500, ike2(i3, b"\x00" * 8, 34, False, 0, sa_init))
    g.udp(t0 + 2.01, mac_b, mac_a, "10.90.2.2", "10.90.2.1", 500, 500,
          ike2(i3, r3, 34, True, 0, [(33, _proposal(pq)), (34, struct.pack("!HH", 19, 0) + b"\x31" * 64), (40, b"\x4e" * 32), inter]))
    for k, dt in enumerate((0.02, 0.5, 1.5, 3.5)):
        g.udp(t0 + 2 + dt, mac_a, mac_b, "10.90.2.1", "10.90.2.2", 4500, 4500,
              b"\x00" * 4 + ike2(i3, r3, 43, False, 1, [(46, b"\x00" * 8 + b"\x5e" * 1250)]))
    # IKEv1 Aggressive Mode, 3DES / SHA1 / group 2 / PSK
    attrs = struct.pack("!HHHHHHHH", 0x8001, 5, 0x8002, 2, 0x8003, 1, 0x8004, 2)
    tr = struct.pack("!BBHBBH", 0, 0, 8 + len(attrs), 1, 1, 0) + attrs
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(tr), 1, 1, 0, 1) + tr
    sa = struct.pack("!II", 1, 1) + prop
    body = struct.pack("!BBH", 4, 0, 4 + len(sa)) + sa + struct.pack("!BBH", 0, 0, 4 + 128) + b"\x31" * 128
    v1 = b"\xa4" * 8 + b"\x00" * 8 + struct.pack("!BBBBII", 1, 0x10, 4, 0, 0, 28 + len(body)) + body
    g.udp(t0 + 3, mac_a, mac_b, "10.90.3.1", "10.90.3.2", 500, 500, v1)


# ------------------------------------------------------------ MACsec ------
def _sectag(an, pn, sci, encrypted=True):
    tci = 0x20 | (0x0C if encrypted else 0) | an
    return struct.pack("!BBI", tci, 0, pn) + bytes.fromhex(sci) + b"\x7e" * 80 + b"\x1c" * 16


def _mkpdu(prio, ks, sci, mi, mn, ckn, live=(), potential=(), sak=None):
    ckn_b = bytes.fromhex(ckn)
    blen = 28 + len(ckn_b)
    b2 = (0x80 if ks else 0) | 0x40 | (2 << 4) | (blen >> 8)
    body = struct.pack("!BBBB", 3, prio, b2, blen & 0xFF) + bytes.fromhex(sci) + bytes.fromhex(mi) + struct.pack("!I", mn) + \
        bytes.fromhex("0080c201") + ckn_b
    body += b"\x00" * ((-len(body)) % 4)
    for ptype, peers in ((1, live), (2, potential)):
        if peers:
            pb = b"".join(bytes.fromhex(p) + struct.pack("!I", 1) for p in peers)
            body += struct.pack("!BBBB", ptype, 0, len(pb) >> 8, len(pb) & 0xFF) + pb
    if sak:
        pb = struct.pack("!I", 1) + bytes.fromhex(sak) + b"\x2a" * 40
        body += struct.pack("!BBBB", 4, 0x40, len(pb) >> 8, len(pb) & 0xFF) + pb
    body += struct.pack("!BBBB", 255, 0, 0, 16) + b"\x1e" * 16
    return struct.pack("!BBH", 3, 5, len(body)) + body


def build_macsec(g, t0=460.0):
    sw1, sw2, sw3 = "00:1b:54:00:00:01", "00:1b:54:00:00:02", "00:1b:54:00:00:03"
    sci1, sci2, sci3 = "001b540000010001", "001b540000020001", "001b540000030001"
    mi1, mi2, mi3 = "a1" * 12, "b2" * 12, "c3" * 12
    ckn, bad_ckn = "0123456789abcdef" * 2, "fedcba9876543210" * 2
    pae = "01:80:c2:00:00:03"
    for k in range(4):
        tt = t0 + k * 2
        g.eth(tt, sw1, pae, 0x888E, _mkpdu(16, True, sci1, mi1, k + 1, ckn, live=[mi2] if k else (), potential=() if k else [mi2],
                                           sak="0080c20001000002" if k == 1 else None))
        g.eth(tt + 0.5, sw2, pae, 0x888E, _mkpdu(32, False, sci2, mi2, k + 1, ckn, live=[mi1] if k else (), potential=() if k else [mi1]))
        g.eth(tt + 1, sw3, pae, 0x888E, _mkpdu(16, False, sci3, mi3, k + 1, bad_ckn))
    dst = "00:1b:54:00:00:02"
    for pn in [p for p in range(1, 61) if p not in (33, 34, 35, 36)]:
        g.eth(t0 + 10 + pn * 0.001, sw1, dst, 0x88E5, _sectag(0, pn, sci1))
    for pn in range(1, 21):
        g.eth(t0 + 11 + pn * 0.001, sw2, sw1, 0x88E5, _sectag(1, 0xF0000000 + pn, sci2))
    for pn in range(1, 11):
        g.eth(t0 + 12 + pn * 0.001, sw3, sw1, 0x88E5, _sectag(0, pn, sci3, encrypted=False))


# ------------------------------------------------------------- EAP-TLS ----
def build_eap_tls(g, t0=480.0):
    sup, auth_ = "00:50:56:0a:02:01", "00:1b:54:00:00:10"
    pae = "01:80:c2:00:00:03"
    now = T0 + t0
    srv = certificate("radius.corp.example", "Corp Issuing CA", now - YEAR, now + 10 * 86400, bits=2048, san=("radius.corp.example",))
    body = b"\x03\x03" + b"\x22" * 32 + b"\x00" + struct.pack("!HB", 0xC030, 0) + b"\x00\x00"
    hs = b"\x02" + len(body).to_bytes(3, "big") + body + cert_msg([srv]) + b"\x0e\x00\x00\x00"
    tls_flight = struct.pack("!BHH", 22, 0x0303, len(hs)) + hs

    def eap(t, src, dst, code, ident, data):
        msg = struct.pack("!BBH", code, ident, 4 + len(data)) + data
        g.eth(t, src, dst, 0x888E, struct.pack("!BBH", 3, 0, len(msg)) + msg)

    eap(t0, auth_, sup, 1, 1, b"\x01")
    eap(t0 + 0.01, sup, pae, 2, 1, b"\x01" + b"host/laptop-42.corp.example")
    eap(t0 + 0.05, auth_, sup, 1, 2, b"\x0d\x20")                       # EAP-TLS Start
    eap(t0 + 0.06, sup, pae, 2, 2, b"\x0d\x00" + ch12("radius.corp.example", ciphers=(0xC030, 0xC02F)))
    half = len(tls_flight) // 2
    eap(t0 + 0.10, auth_, sup, 1, 3, b"\x0d\xc0" + struct.pack("!I", len(tls_flight)) + tls_flight[:half])
    eap(t0 + 0.11, sup, pae, 2, 3, b"\x0d\x00")
    eap(t0 + 0.15, auth_, sup, 1, 4, b"\x0d\x00" + tls_flight[half:])
    eap(t0 + 0.30, auth_, sup, 3, 5, b"")


def build_all(g) -> None:
    build_tls(g)
    build_ssh(g)
    build_ike(g)
    build_macsec(g)
    build_eap_tls(g)
