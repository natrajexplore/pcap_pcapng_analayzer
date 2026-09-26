"""IS-IS (ISO 10589 / RFC 1195) parser: IIH hellos, LSPs and SNPs over 802.3 LLC."""
from __future__ import annotations

import struct

PDU = {15: "L1 LAN Hello", 16: "L2 LAN Hello", 17: "P2P Hello", 18: "L1 LSP", 20: "L2 LSP",
       24: "L1 CSNP", 25: "L2 CSNP", 26: "L1 PSNP", 27: "L2 PSNP"}
CIRCUIT = {1: "L1", 2: "L2", 3: "L1L2"}


def sysid(b: bytes) -> str:
    h = b.hex()
    return f"{h[0:4]}.{h[4:8]}.{h[8:12]}"


def parse(buf: bytes) -> dict | None:
    """``buf`` starts at the IS-IS header (after the 3-byte LLC 0xFE 0xFE 0x03)."""
    if len(buf) < 8 or buf[0] != 0x83:
        return None
    hlen, ptype = buf[1], buf[4] & 0x1F
    d: dict = {"pdu": PDU.get(ptype, str(ptype)), "type": ptype, "areas": [], "neighbors": [], "auth": None,
               "ip_addresses": [], "pdu_length": None}
    try:
        if ptype in (15, 16, 17):
            circ, sid, hold, plen = buf[8], buf[9:15], *struct.unpack("!HH", buf[15:19])
            d.update(circuit=CIRCUIT.get(circ & 3, str(circ)), system_id=sysid(sid), hold=hold, pdu_length=plen)
            if ptype == 17:
                d["local_circuit"] = buf[19]
            else:
                d["priority"] = buf[19] & 0x7F
                d["lan_id"] = sysid(buf[20:26]) + f".{buf[26]:02x}"
        elif ptype in (18, 20):
            plen, life = struct.unpack("!HH", buf[8:12])
            lsp = buf[12:20]
            seq, _cks = struct.unpack("!IH", buf[20:26])
            d.update(pdu_length=plen, lifetime=life, lsp_id=f"{sysid(lsp[:6])}.{lsp[6]:02x}-{lsp[7]:02x}",
                     system_id=sysid(lsp[:6]), seq=seq, purge=life == 0)
        elif ptype in (24, 25, 26, 27):
            d.update(pdu_length=struct.unpack("!H", buf[8:10])[0], system_id=sysid(buf[10:16]))
        off = hlen
        end = min(len(buf), d["pdu_length"] or len(buf))
        padding = 0
        while off + 2 <= end:
            t, ln = buf[off], buf[off + 1]
            v = buf[off + 2:off + 2 + ln]
            if t == 1:
                i = 0
                while i < len(v):
                    al = v[i]
                    d["areas"].append(v[i + 1:i + 1 + al].hex())
                    i += 1 + al
            elif t == 6:
                d["neighbors"] += [":".join(f"{x:02x}" for x in v[i:i + 6]) for i in range(0, len(v) - 5, 6)]
            elif t == 10 and v:
                d["auth"] = {1: "cleartext", 54: "HMAC-MD5"}.get(v[0], str(v[0]))
            elif t == 132:
                d["ip_addresses"] += [".".join(map(str, v[i:i + 4])) for i in range(0, len(v) - 3, 4)]
            elif t == 8:
                padding += ln + 2
            off += 2 + ln
        d["padded"] = padding > 0
    except (struct.error, IndexError):
        pass
    return d


def info(d: dict) -> str:
    s = f"IS-IS {d['pdu']}"
    if d.get("system_id"):
        s += f" {d['system_id']}"
    if d.get("circuit"):
        s += f" circuit {d['circuit']} hold {d['hold']}s"
    if d.get("areas"):
        s += " area " + ",".join(d["areas"])
    if d.get("lsp_id"):
        s += f" LSP {d['lsp_id']} seq 0x{d['seq']:x}" + (" PURGE" if d.get("purge") else "")
    return s
