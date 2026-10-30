"""IEEE 802.1AE MACsec SecTAG (EtherType 0x88E5) and IEEE 802.1X-2010 MKA (EAPOL type 5) MKPDUs."""
from __future__ import annotations

import struct

ETHERTYPE = 0x88E5
CIPHER_SUITES = {"0080c20001000001": "GCM-AES-128", "0080c20001000002": "GCM-AES-256",
                 "0080c20001000003": "GCM-AES-XPN-128", "0080c20001000004": "GCM-AES-XPN-256"}
CAPABILITY = {0: "not implemented", 1: "integrity only", 2: "integrity + confidentiality (offset 0)",
              3: "integrity + confidentiality (offset 0/30/50)"}
PARAM_SETS = {1: "Live Peer List", 2: "Potential Peer List", 3: "MACsec SAK Use", 4: "Distributed SAK",
              5: "Distributed CAK", 6: "KMD", 7: "Announcement", 8: "XPN", 255: "ICV Indicator"}
ICV_LEN = 16


def parse_sectag(buf: bytes) -> dict | None:
    """``buf`` starts right after the 0x88E5 EtherType."""
    if len(buf) < 6:
        return None
    tci, sl, pn = buf[0], buf[1] & 0x3F, struct.unpack("!I", buf[2:6])[0]
    if tci & 0x80:                              # V bit must be 0
        return None
    sc = bool(tci & 0x20)
    d = {"an": tci & 0x03, "pn": pn, "es": bool(tci & 0x40), "sc": sc, "scb": bool(tci & 0x10),
         "encrypted": bool(tci & 0x08), "changed": bool(tci & 0x04), "short_length": sl}
    hdr = 6
    if sc and len(buf) >= 14:
        d["sci"] = buf[6:14].hex()
        hdr = 14
    d["mode"] = "encrypted" if d["encrypted"] and d["changed"] else "integrity-only" if not d["encrypted"] and not d["changed"] else "invalid E/C"
    d["secure_data_len"] = max(0, len(buf) - hdr - ICV_LEN)
    return d


def parse_mka(body: bytes) -> dict | None:
    """MKPDU body (after the 4-byte EAPOL header)."""
    if len(body) < 32:
        return None
    ver, prio, b2, b3 = body[:4]
    blen = ((b2 & 0x0F) << 8) | b3
    d: dict = {"mka_version": ver, "key_server_priority": prio, "key_server": bool(b2 & 0x80),
               "macsec_desired": bool(b2 & 0x40), "capability": CAPABILITY.get((b2 >> 4) & 0x03),
               "sci": body[4:12].hex(), "member_id": body[12:24].hex(), "msg_number": struct.unpack("!I", body[24:28])[0],
               "algorithm_agility": body[28:32].hex(), "param_sets": [], "live_peers": [], "potential_peers": [],
               "cipher_suite": None, "sak_distributed": False}
    ckn = body[32:4 + blen]
    d["ckn"] = ckn.hex()
    off = 4 + blen
    off += (-off) % 4
    while off + 4 <= len(body):
        ptype = body[off]
        plen = ((body[off + 2] & 0x0F) << 8) | body[off + 3]
        if ptype == 255:                        # ICV indicator: the 16-byte ICV follows
            d["param_sets"].append(PARAM_SETS[255])
            break
        pb = body[off + 4:off + 4 + plen]
        d["param_sets"].append(PARAM_SETS.get(ptype, str(ptype)))
        if ptype in (1, 2):
            peers = [pb[i:i + 12].hex() for i in range(0, len(pb) - 15, 16)]
            d["live_peers" if ptype == 1 else "potential_peers"] += peers
        elif ptype == 4:
            d["sak_distributed"] = True
            d["distributed_an"] = body[off + 1] >> 6
            d["confidentiality_offset"] = {0: 0, 1: 0, 2: 30, 3: 50}.get((body[off + 1] >> 4) & 0x03)
            d["cipher_suite"] = CIPHER_SUITES.get(pb[4:12].hex(), pb[4:12].hex()) if plen > 28 else "GCM-AES-128"
        if plen == 0 and ptype not in (1, 2, 3, 4, 5, 6, 7, 8):
            break
        off += 4 + plen
        off += (-off) % 4
    return d


def sectag_info(d: dict) -> str:
    return (f"MACsec AN={d['an']} PN={d['pn']}" + (f" SCI={d['sci']}" if d.get("sci") else "") +
            f" [{d['mode']}]")


def mka_info(d: dict) -> str:
    s = f"MKA MKPDU MN={d['msg_number']} prio={d['key_server_priority']}"
    if d["key_server"]:
        s += " KeyServer"
    s += f" live={len(d['live_peers'])} potential={len(d['potential_peers'])}"
    if d["sak_distributed"]:
        s += f" SAK({d['cipher_suite']})"
    return s
