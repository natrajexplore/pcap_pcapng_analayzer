"""Cryptographic algorithm registry with post-quantum (PQC) classification.

One place that knows every key-exchange and signature codepoint the decoders meet
(TLS NamedGroup / SignatureScheme, SSH algorithm names, IKEv2 transform IDs and
X.509 OIDs) and how each one stands against a quantum adversary:

* ``pqc``       - pure NIST post-quantum algorithm (ML-KEM FIPS 203, ML-DSA FIPS 204, SLH-DSA FIPS 205)
* ``hybrid``    - classical + PQC combined (X25519MLKEM768, mlkem768x25519-sha256, IKEv2 + RFC 9370 ML-KEM)
* ``draft``     - pre-standard PQC (Kyber draft codepoints): protects today but must be migrated
* ``classical`` - secure today but breakable by a quantum computer (ECDHE, RSA, finite-field DH): traffic
                  recorded now can be decrypted later ("harvest now, decrypt later")
* ``weak``      - already broken or deprecated classically (DH < 2048, SHA-1, MD5, DES, RC4, ...)
"""
from __future__ import annotations

QUANTUM_SAFE = ("pqc", "hybrid")
STATUS_ORDER = {"weak": 0, "classical": 1, "unknown": 2, "draft": 3, "hybrid": 4, "pqc": 5}

# ---------------------------------------------------------------- TLS -----
TLS_GROUPS = {
    0x0017: ("secp256r1", "classical"), 0x0018: ("secp384r1", "classical"), 0x0019: ("secp521r1", "classical"),
    0x001D: ("x25519", "classical"), 0x001E: ("x448", "classical"),
    0x0015: ("secp224r1", "weak"), 0x0016: ("secp256k1", "classical"),
    0x0100: ("ffdhe2048", "classical"), 0x0101: ("ffdhe3072", "classical"), 0x0102: ("ffdhe4096", "classical"),
    0x0103: ("ffdhe6144", "classical"), 0x0104: ("ffdhe8192", "classical"),
    0x0200: ("MLKEM512", "pqc"), 0x0201: ("MLKEM768", "pqc"), 0x0202: ("MLKEM1024", "pqc"),
    0x11EB: ("SecP256r1MLKEM768", "hybrid"), 0x11EC: ("X25519MLKEM768", "hybrid"), 0x11ED: ("SecP384r1MLKEM1024", "hybrid"),
    0x6399: ("X25519Kyber768Draft00", "draft"), 0x639A: ("SecP256r1Kyber768Draft00", "draft"),
    0xFE30: ("X25519Kyber512Draft00 (OQS)", "draft"), 0xFE31: ("X25519Kyber768Draft00 (OQS)", "draft"),
}
TLS_SIGS = {
    0x0201: ("rsa_pkcs1_sha1", "weak"), 0x0203: ("ecdsa_sha1", "weak"), 0x0101: ("rsa_pkcs1_md5", "weak"),
    0x0401: ("rsa_pkcs1_sha256", "classical"), 0x0501: ("rsa_pkcs1_sha384", "classical"), 0x0601: ("rsa_pkcs1_sha512", "classical"),
    0x0403: ("ecdsa_secp256r1_sha256", "classical"), 0x0503: ("ecdsa_secp384r1_sha384", "classical"),
    0x0603: ("ecdsa_secp521r1_sha512", "classical"),
    0x0804: ("rsa_pss_rsae_sha256", "classical"), 0x0805: ("rsa_pss_rsae_sha384", "classical"), 0x0806: ("rsa_pss_rsae_sha512", "classical"),
    0x0807: ("ed25519", "classical"), 0x0808: ("ed448", "classical"),
    0x0809: ("rsa_pss_pss_sha256", "classical"), 0x080A: ("rsa_pss_pss_sha384", "classical"), 0x080B: ("rsa_pss_pss_sha512", "classical"),
    0x0904: ("mldsa44", "pqc"), 0x0905: ("mldsa65", "pqc"), 0x0906: ("mldsa87", "pqc"),
}
# TLS key exchanges carried in the cipher suite (TLS <= 1.2)
TLS12_KX = {"RSA": ("RSA key transport", "weak"), "DHE": ("DHE", "classical"), "ECDHE": ("ECDHE", "classical")}

# ---------------------------------------------------------------- SSH -----
SSH_KEX = {
    "mlkem768x25519-sha256": "hybrid", "mlkem768nistp256-sha256": "hybrid", "mlkem1024nistp384-sha384": "hybrid",
    "sntrup761x25519-sha512": "hybrid", "sntrup761x25519-sha512@openssh.com": "hybrid",
    "curve25519-sha256": "classical", "curve25519-sha256@libssh.org": "classical", "curve448-sha512": "classical",
    "ecdh-sha2-nistp256": "classical", "ecdh-sha2-nistp384": "classical", "ecdh-sha2-nistp521": "classical",
    "diffie-hellman-group14-sha256": "classical", "diffie-hellman-group16-sha512": "classical",
    "diffie-hellman-group18-sha512": "classical", "diffie-hellman-group-exchange-sha256": "classical",
    "diffie-hellman-group1-sha1": "weak", "diffie-hellman-group14-sha1": "weak",
    "diffie-hellman-group-exchange-sha1": "weak", "rsa1024-sha1": "weak",
}
SSH_HOSTKEY = {"ssh-ed25519": "classical", "ssh-ed448": "classical", "ecdsa-sha2-nistp256": "classical",
               "ecdsa-sha2-nistp384": "classical", "ecdsa-sha2-nistp521": "classical", "rsa-sha2-256": "classical",
               "rsa-sha2-512": "classical", "ssh-rsa": "weak", "ssh-dss": "weak",
               "ssh-mldsa44": "pqc", "ssh-mldsa65": "pqc", "ssh-mldsa87": "pqc"}
SSH_WEAK_CIPHERS = ("3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc",
                    "arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se", "des-cbc", "none")
SSH_WEAK_MACS = ("hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com",
                 "umac-64@openssh.com", "hmac-ripemd160", "none")

# --------------------------------------------------------------- IKEv2 ----
IKE_KE = {
    1: ("MODP-768 (group 1)", "weak"), 2: ("MODP-1024 (group 2)", "weak"), 5: ("MODP-1536 (group 5)", "weak"),
    14: ("MODP-2048 (group 14)", "classical"), 15: ("MODP-3072 (group 15)", "classical"),
    16: ("MODP-4096 (group 16)", "classical"), 17: ("MODP-6144 (group 17)", "classical"),
    18: ("MODP-8192 (group 18)", "classical"), 19: ("ECP-256 (group 19)", "classical"),
    20: ("ECP-384 (group 20)", "classical"), 21: ("ECP-521 (group 21)", "classical"),
    22: ("MODP-1024/160 (group 22)", "weak"), 23: ("MODP-2048/224 (group 23)", "weak"),
    24: ("MODP-2048/256 (group 24)", "classical"), 31: ("Curve25519 (group 31)", "classical"),
    32: ("Curve448 (group 32)", "classical"),
    35: ("ML-KEM-512", "pqc"), 36: ("ML-KEM-768", "pqc"), 37: ("ML-KEM-1024", "pqc"),
}
IKE_ENCR = {2: ("DES", "weak"), 3: ("3DES", "weak"), 11: ("NULL", "weak"), 12: ("AES-CBC", "classical"),
            13: ("AES-CTR", "classical"), 14: ("AES-CCM-8", "classical"), 18: ("AES-GCM-8", "classical"),
            19: ("AES-GCM-12", "classical"), 20: ("AES-GCM-16", "classical"), 28: ("ChaCha20-Poly1305", "classical")}
IKE_INTEG = {1: ("HMAC-MD5-96", "weak"), 2: ("HMAC-SHA1-96", "weak"), 5: ("AES-XCBC-96", "classical"),
             12: ("HMAC-SHA2-256-128", "classical"), 13: ("HMAC-SHA2-384-192", "classical"),
             14: ("HMAC-SHA2-512-256", "classical")}
IKE_PRF = {1: ("PRF-HMAC-MD5", "weak"), 2: ("PRF-HMAC-SHA1", "weak"), 4: ("PRF-AES128-XCBC", "classical"),
           5: ("PRF-HMAC-SHA2-256", "classical"), 6: ("PRF-HMAC-SHA2-384", "classical"),
           7: ("PRF-HMAC-SHA2-512", "classical")}

# --------------------------------------------------------------- X.509 ----
OIDS = {
    "1.2.840.113549.1.1.1": ("RSA", "classical"), "1.2.840.113549.1.1.10": ("RSASSA-PSS", "classical"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "weak"), "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "weak"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "classical"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "classical"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "classical"),
    "1.2.840.10045.2.1": ("EC", "classical"), "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "weak"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "classical"), "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "classical"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "classical"),
    "1.3.101.112": ("Ed25519", "classical"), "1.3.101.113": ("Ed448", "classical"),
    "1.2.840.10040.4.1": ("DSA", "weak"), "1.2.840.10040.4.3": ("dsa-with-SHA1", "weak"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "pqc"), "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "pqc"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "pqc"),
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", "pqc"), "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", "pqc"),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", "pqc"),
}
for _i, _n in enumerate(("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
                         "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
                         "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f")):
    OIDS[f"2.16.840.1.101.3.4.3.{20 + _i}"] = (_n, "pqc")
CURVES = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.132.0.10": "secp256k1"}


def tls_group(code: int) -> tuple[str, str]:
    return TLS_GROUPS.get(code, (f"0x{code:04x}", "unknown"))


_GROUP_STATUS = {n: st for n, st in TLS_GROUPS.values()}


def tls_group_status(name: str) -> str:
    return _GROUP_STATUS.get(name, "unknown")


def tls_sig(code: int) -> tuple[str, str]:
    return TLS_SIGS.get(code, (f"0x{code:04x}", "unknown"))


def oid(o: str) -> tuple[str, str]:
    return OIDS.get(o, (o, "unknown"))


def ssh_kex(name: str) -> str:
    return SSH_KEX.get(name, "unknown")


def best(statuses) -> str:
    """Strongest status among several (what a negotiation *could* reach)."""
    s = [x for x in statuses if x]
    return max(s, key=lambda x: STATUS_ORDER.get(x, 2)) if s else "unknown"


def worst(statuses) -> str:
    s = [x for x in statuses if x]
    return min(s, key=lambda x: STATUS_ORDER.get(x, 2)) if s else "unknown"
