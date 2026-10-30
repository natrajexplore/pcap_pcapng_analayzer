"""SSH transport (RFC 4253): identification string, KEXINIT algorithm lists, KEX method messages,
DISCONNECT - everything before NEWKEYS, i.e. all that is visible in cleartext."""
from __future__ import annotations

import struct

from . import pqc

MSG = {1: "DISCONNECT", 2: "IGNORE", 3: "UNIMPLEMENTED", 4: "DEBUG", 5: "SERVICE_REQUEST", 6: "SERVICE_ACCEPT",
       20: "KEXINIT", 21: "NEWKEYS", 30: "KEX_ECDH_INIT", 31: "KEX_ECDH_REPLY", 32: "KEX_DH_GEX_INIT",
       33: "KEX_DH_GEX_REPLY", 34: "KEX_DH_GEX_REQUEST"}
DISCONNECT = {1: "HOST_NOT_ALLOWED_TO_CONNECT", 2: "PROTOCOL_ERROR", 3: "KEY_EXCHANGE_FAILED", 4: "RESERVED",
              5: "MAC_ERROR", 6: "COMPRESSION_ERROR", 7: "SERVICE_NOT_AVAILABLE", 8: "PROTOCOL_VERSION_NOT_SUPPORTED",
              9: "HOST_KEY_NOT_VERIFIABLE", 10: "CONNECTION_LOST", 11: "BY_APPLICATION", 12: "TOO_MANY_CONNECTIONS",
              13: "AUTH_CANCELLED_BY_USER", 14: "NO_MORE_AUTH_METHODS_AVAILABLE", 15: "ILLEGAL_USER_NAME"}
LISTS = ("kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c")
STRICT = ("kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com")


def parse(msg: bytes) -> dict | None:
    """One framed SSH message: an identification line or a binary packet (4-byte length, padding, payload)."""
    if msg.startswith(b"SSH-"):
        line = msg.rstrip(b"\r\n").decode("latin-1", "replace")
        parts = line.split("-", 2)
        proto = parts[1] if len(parts) > 1 else "?"
        sw = parts[2] if len(parts) > 2 else ""
        return {"type": "banner", "banner": line[:255], "proto_version": proto, "software": sw.split(" ")[0]}
    if len(msg) < 6:
        return None
    pad = msg[4]
    payload = msg[5:len(msg) - pad] if pad < len(msg) - 5 else b""
    if not payload:
        return None
    code = payload[0]
    d: dict = {"type": MSG.get(code, f"msg {code}"), "code": code}
    try:
        if code == 20:
            off = 17                              # code + 16-byte cookie
            for name in LISTS:
                ln = struct.unpack("!I", payload[off:off + 4])[0]
                d[name] = [x for x in payload[off + 4:off + 4 + ln].decode("latin-1").split(",") if x]
                off += 4 + ln
        elif code == 1 and len(payload) >= 9:
            rc = struct.unpack("!I", payload[1:5])[0]
            ln = struct.unpack("!I", payload[5:9])[0]
            d["reason"] = DISCONNECT.get(rc, str(rc))
            d["description"] = payload[9:9 + ln].decode("utf-8", "replace")[:200]
        elif code in (30, 31, 32, 33):
            ln = struct.unpack("!I", payload[1:5])[0]
            d["key_len"] = ln if code in (30, 32) else None
    except (struct.error, IndexError):
        pass
    return d


def negotiate(client: list, server: list) -> str | None:
    """RFC 4253 7.1: the first client algorithm the server also supports."""
    return next((a for a in client if a in server), None)


def kex_status(name: str | None) -> str:
    return pqc.ssh_kex(name) if name else "unknown"


def info(d: dict) -> str:
    parts = []
    for m in d["messages"]:
        if m["type"] == "banner":
            parts.append(f"Protocol ({m['banner']})")
        elif m["type"] == "KEXINIT":
            pq = [k for k in m.get("kex", []) if pqc.ssh_kex(k) in pqc.QUANTUM_SAFE]
            parts.append("Key Exchange Init" + (f" [PQC: {pq[0]}]" if pq else ""))
        elif m["type"] == "DISCONNECT":
            parts.append(f"Disconnect ({m.get('reason')})")
        else:
            parts.append(m["type"].replace("_", " ").title())
    return "SSH " + ", ".join(parts)
