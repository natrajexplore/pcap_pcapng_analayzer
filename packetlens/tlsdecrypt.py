"""TLS decryption from an NSS key log (SSLKEYLOGFILE) or a pcapng Decryption Secrets Block.

Supports the AEAD cipher suites used by virtually all modern traffic:

* TLS 1.3: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
* TLS 1.2: ECDHE/DHE/RSA with AES-GCM (SHA256/SHA384 PRF) and ChaCha20-Poly1305

Key derivation (TLS 1.2 PRF, TLS 1.3 HKDF-Expand-Label) uses only the standard
library; the AEAD primitives come from the optional ``cryptography`` package.
Without it, sessions are still matched to key-log entries and reported, but not
decrypted.
"""
from __future__ import annotations

import hashlib
import hmac
import struct

try:  # optional dependency
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    from cryptography.exceptions import InvalidTag
    HAVE_CRYPTO = True
except BaseException:  # pragma: no cover - missing or broken install (some distro builds panic on import)
    HAVE_CRYPTO = False
    InvalidTag = Exception

# cipher suite -> (tls version family, aead, key length, hash)
SUITES = {
    0x1301: ("1.3", "gcm", 16, "sha256"), 0x1302: ("1.3", "gcm", 32, "sha384"), 0x1303: ("1.3", "chacha", 32, "sha256"),
    0xC02B: ("1.2", "gcm", 16, "sha256"), 0xC02F: ("1.2", "gcm", 16, "sha256"), 0x009C: ("1.2", "gcm", 16, "sha256"),
    0x009E: ("1.2", "gcm", 16, "sha256"), 0xC02C: ("1.2", "gcm", 32, "sha384"), 0xC030: ("1.2", "gcm", 32, "sha384"),
    0x009D: ("1.2", "gcm", 32, "sha384"), 0x009F: ("1.2", "gcm", 32, "sha384"),
    0xCCA8: ("1.2", "chacha", 32, "sha256"), 0xCCA9: ("1.2", "chacha", 32, "sha256"), 0xCCAA: ("1.2", "chacha", 32, "sha256"),
}
LABELS_13 = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
             "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")


class KeyLog:
    """NSS key log: ``<LABEL> <client_random hex> <secret hex>`` per line."""

    def __init__(self):
        self.entries: dict[str, dict[str, bytes]] = {}

    def load_text(self, text: str) -> "KeyLog":
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) != 3 or line.startswith("#"):
                continue
            label, cr, secret = parts
            try:
                self.entries.setdefault(cr.lower(), {})[label] = bytes.fromhex(secret)
            except ValueError:
                continue
        return self

    def load_file(self, path: str) -> "KeyLog":
        with open(path, encoding="utf-8", errors="replace") as fh:
            return self.load_text(fh.read())

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, client_random: str) -> dict | None:
        return self.entries.get(client_random.lower())


# ------------------------------------------------------------- KDFs ---------
def _p_hash(hname: str, secret: bytes, seed: bytes, n: int) -> bytes:
    out, a = b"", seed
    while len(out) < n:
        a = hmac.new(secret, a, hname).digest()
        out += hmac.new(secret, a + seed, hname).digest()
    return out[:n]


def prf12(hname: str, secret: bytes, label: bytes, seed: bytes, n: int) -> bytes:
    return _p_hash(hname, secret, label + seed, n)


def hkdf_expand_label(hname: str, secret: bytes, label: str, context: bytes, n: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", n) + bytes([len(full)]) + full + bytes([len(context)]) + context
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(secret, t + info + bytes([i]), hname).digest()
        out += t
        i += 1
    return out[:n]


def _aead(kind: str, key: bytes):
    return AESGCM(key) if kind == "gcm" else ChaCha20Poly1305(key)


def _xor_nonce(iv: bytes, seq: int) -> bytes:
    s = seq.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, s))


class _Dir:
    def __init__(self):
        self.encrypted = False
        self.seq = 0
        self.stages: list = []      # list of (aead, iv) - TLS 1.3 handshake then application keys
        self.stage = 0
        self.failed = 0
        self.after_ccs = False       # TLS 1.2: records after ChangeCipherSpec are encrypted


class TLSSession:
    """Tracks one TLS connection and decrypts its records given the key log."""

    def __init__(self, keylog: KeyLog | None):
        self.keylog = keylog
        self.client_random: str | None = None
        self.server_random: str | None = None
        self.cipher: int | None = None
        self.version: int | None = None
        self.alpn: str | None = None
        self.status = "no keys"      # no keys | unsupported cipher | decrypting | failed | no crypto library
        self.decrypted_records = 0
        self.dirs = {True: _Dir(), False: _Dir()}   # key: from_client
        self._ready = False

    # -------------------------------------------------------------- hellos --
    def observe(self, tls_layer: dict) -> None:
        ch, sh = tls_layer.get("client_hello"), tls_layer.get("server_hello")
        if ch:
            self.client_random = ch.get("random")
        if sh:
            self.server_random = sh.get("random")
            self.cipher = sh.get("cipher")
            self.version = sh.get("version_num")
            self.alpn = sh.get("alpn")
            self._setup()

    def _setup(self) -> None:
        if not (self.keylog and self.client_random):
            return
        keys = self.keylog.get(self.client_random)
        if not keys:
            self.status = "no keys"
            return
        suite = SUITES.get(self.cipher or -1)
        if not suite:
            self.status = f"unsupported cipher 0x{(self.cipher or 0):04x}"
            return
        if not HAVE_CRYPTO:
            self.status = "keys found; install 'cryptography' to decrypt"
            return
        fam, kind, klen, hname = suite
        if fam == "1.3":
            for from_client, (hs, app) in ((True, LABELS_13[0::2]), (False, LABELS_13[1::2])):
                stages = []
                for label in (hs, app):
                    sec = keys.get(label)
                    if sec:
                        stages.append((_aead(kind, hkdf_expand_label(hname, sec, "key", b"", klen)),
                                       hkdf_expand_label(hname, sec, "iv", b"", 12)))
                self.dirs[from_client].stages = stages
                self.dirs[from_client].encrypted = bool(stages)   # everything after ServerHello
        else:
            master = keys.get("CLIENT_RANDOM")
            if not master:
                self.status = "no keys"
                return
            ivlen = 4 if kind == "gcm" else 12
            kb = prf12(hname, master, b"key expansion", bytes.fromhex(self.server_random) + bytes.fromhex(self.client_random),
                       2 * klen + 2 * ivlen)
                                      # AEAD suites have no MAC keys
            ck, sk = kb[:klen], kb[klen:2 * klen]
            civ, siv = kb[2 * klen:2 * klen + ivlen], kb[2 * klen + ivlen:]
            self.dirs[True].stages = [(_aead(kind, ck), civ)]
            self.dirs[False].stages = [(_aead(kind, sk), siv)]
        self._kind, self._fam = kind, fam
        self._ready = True
        self.status = "decrypting"

    # ------------------------------------------------------------- records --
    def record(self, ctype: int, version: int, fragment: bytes, from_client: bool) -> list[tuple[int, bytes]]:
        """Feed one TLS record; returns [(inner content type, plaintext)] when decrypted."""
        d = self.dirs[from_client]
        if ctype == 20:                      # ChangeCipherSpec
            if (self.version or 0) < 0x0304:
                d.after_ccs = True
            if self._ready and self._fam == "1.2":
                d.encrypted, d.seq = True, 0
            return []
        if not (self._ready and d.encrypted and d.stages):
            return []
        if self._fam == "1.3" and ctype != 23:
            return []
        header = struct.pack("!BHH", ctype, version, len(fragment))
        for attempt in range(d.stage, len(d.stages)):
            aead, iv = d.stages[attempt]
            seq = d.seq if attempt == d.stage else 0
            try:
                if self._fam == "1.3":
                    pt = aead.decrypt(_xor_nonce(iv, seq), fragment, header)
                    body = pt.rstrip(b"\x00")
                    inner, body = (body[-1], body[:-1]) if body else (0, b"")
                elif self._kind == "gcm":
                    nonce = iv + fragment[:8]
                    ct = fragment[8:]
                    aad = struct.pack("!QBHH", seq, ctype, version, len(ct) - 16)
                    inner, body = ctype, aead.decrypt(nonce, ct, aad)
                else:
                    aad = struct.pack("!QBHH", seq, ctype, version, len(fragment) - 16)
                    inner, body = ctype, aead.decrypt(_xor_nonce(iv, seq), fragment, aad)
            except (InvalidTag, ValueError):
                continue
            d.stage, d.seq = attempt, seq + 1
            self.decrypted_records += 1
            return [(inner, body)]
        d.failed += 1
        if d.failed > 3 and not self.decrypted_records:
            self.status = "failed (wrong keys?)"
        d.seq += 1
        return []
