"""AI / HPC fabric protocols: RoCEv2 (InfiniBand BTH/AETH over UDP 4791) and IEEE 802.3 MAC Control
PAUSE / 802.1Qbb Priority Flow Control (EtherType 0x8808)."""
from __future__ import annotations

import struct

PORT = 4791
MAC_CONTROL = 0x8808
_OPS = {0x00: "SEND First", 0x01: "SEND Middle", 0x02: "SEND Last", 0x03: "SEND Last with Immediate", 0x04: "SEND Only",
        0x05: "SEND Only with Immediate", 0x06: "RDMA WRITE First", 0x07: "RDMA WRITE Middle", 0x08: "RDMA WRITE Last",
        0x09: "RDMA WRITE Last with Immediate", 0x0A: "RDMA WRITE Only", 0x0B: "RDMA WRITE Only with Immediate",
        0x0C: "RDMA READ Request", 0x0D: "RDMA READ Response First", 0x0E: "RDMA READ Response Middle",
        0x0F: "RDMA READ Response Last", 0x10: "RDMA READ Response Only", 0x11: "Acknowledge", 0x12: "ATOMIC Acknowledge",
        0x13: "CmpSwap", 0x14: "FetchAdd", 0x16: "SEND Last with Invalidate", 0x17: "SEND Only with Invalidate"}
TRANSPORT = {0: "RC", 1: "UC", 2: "RD", 3: "UD", 4: "CNP-capable", 5: "XRC"}
NAK = {0: "PSN Sequence Error", 1: "Invalid Request", 2: "Remote Access Error", 3: "Remote Operational Error",
       4: "Invalid RD Request"}
# requests carrying a PSN the responder must see in order (everything except ACKs and responses)
RESPONSES = {0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12}


def opcode_name(op: int) -> str:
    if op == 0x81:
        return "CNP"
    t = TRANSPORT.get(op >> 5, f"{op >> 5}")
    return f"{t} {_OPS.get(op & 0x1F, f'op 0x{op & 0x1F:02x}')}"


def parse_bth(buf: bytes) -> dict | None:
    if len(buf) < 12:
        return None
    op, flags, pkey = struct.unpack("!BBH", buf[:4])
    if pkey == 0:
        return None
    qp = int.from_bytes(buf[5:8], "big")
    psn = int.from_bytes(buf[9:12], "big")
    d = {"opcode": op, "op": opcode_name(op), "dest_qp": qp, "psn": psn, "ack_req": bool(buf[8] & 0x80),
         "pkey": f"0x{pkey:04x}", "se": bool(flags & 0x80), "becn": bool(buf[4] & 0x40) if op == 0x81 else False}
    if op & 0x1F in (0x11, 0x12) and len(buf) >= 16:      # AETH
        syn = buf[12]
        kind = syn >> 5
        d["aeth"] = {"kind": {0: "ACK", 1: "RNR NAK", 3: "NAK"}.get(kind, f"reserved {kind}"), "code": syn & 0x1F,
                     "msn": int.from_bytes(buf[13:16], "big")}
        if kind == 3:
            d["aeth"]["nak"] = NAK.get(syn & 0x1F, str(syn & 0x1F))
    return d


def parse_mac_control(buf: bytes) -> dict | None:
    if len(buf) < 4:
        return None
    op = struct.unpack("!H", buf[:2])[0]
    if op == 0x0001:
        return {"type": "PAUSE", "quanta": struct.unpack("!H", buf[2:4])[0]}
    if op == 0x0101 and len(buf) >= 20:
        cev = struct.unpack("!H", buf[2:4])[0]
        times = struct.unpack("!8H", buf[4:20])
        return {"type": "PFC", "priorities": {str(p): times[p] for p in range(8) if cev & (1 << p)}}
    return {"type": f"MAC Control 0x{op:04x}"}


def bth_info(d: dict) -> str:
    s = f"RoCEv2 {d['op']} QP=0x{d['dest_qp']:06x} PSN={d['psn']}"
    if d.get("aeth"):
        a = d["aeth"]
        s += f" [{a['kind']}" + (f": {a['nak']}" if a.get("nak") else "") + "]"
    return s


def pause_info(d: dict) -> str:
    if d["type"] == "PFC":
        return "PFC Pause " + ", ".join(f"prio {p}: {q} quanta" + (" (resume)" if q == 0 else "") for p, q in d["priorities"].items())
    if d["type"] == "PAUSE":
        return f"Ethernet PAUSE {d['quanta']} quanta"
    return d["type"]
