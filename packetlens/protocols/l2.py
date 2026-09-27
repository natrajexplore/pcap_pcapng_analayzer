"""ARP, ICMP / ICMPv6 and Spanning Tree parsers."""
from __future__ import annotations

import ipaddress
import struct

ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 4: "Source quench", 5: "Redirect",
              8: "Echo request", 11: "Time exceeded", 12: "Parameter problem", 13: "Timestamp request",
              14: "Timestamp reply", 15: "Information request", 17: "Address mask request"}
UNREACH = {0: "Network unreachable", 1: "Host unreachable", 2: "Protocol unreachable",
           3: "Port unreachable", 4: "Fragmentation needed (DF set)", 5: "Source route failed",
           6: "Destination network unknown", 7: "Destination host unknown", 9: "Network administratively prohibited",
           10: "Host administratively prohibited", 13: "Communication administratively prohibited"}
ICMP6_TYPES = {1: "Destination unreachable", 2: "Packet too big", 3: "Time exceeded", 4: "Parameter problem",
               128: "Echo request", 129: "Echo reply", 133: "Router solicitation", 134: "Router advertisement",
               135: "Neighbor solicitation", 136: "Neighbor advertisement", 137: "Redirect",
               130: "Multicast listener query", 131: "Multicast listener report", 132: "Multicast listener done",
               143: "Multicast listener report v2"}
UNREACH6 = {0: "No route to destination", 1: "Communication administratively prohibited", 2: "Beyond scope of source",
            3: "Address unreachable", 4: "Port unreachable", 5: "Source address failed policy", 6: "Reject route"}


def mac(b: bytes) -> str:
    return b.hex(":")


def parse_arp(buf: bytes) -> dict | None:
    if len(buf) < 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", buf[:8])
    if hlen != 6 or plen != 4:
        return None
    d = {"op": "request" if op == 1 else "reply" if op == 2 else str(op),
         "sender_mac": mac(buf[8:14]), "sender_ip": str(ipaddress.IPv4Address(buf[14:18])),
         "target_mac": mac(buf[18:24]), "target_ip": str(ipaddress.IPv4Address(buf[24:28]))}
    d["gratuitous"] = d["sender_ip"] == d["target_ip"]
    return d


def arp_info(d: dict) -> str:
    if d["op"] == "request":
        return f"Who has {d['target_ip']}? Tell {d['sender_ip']}" + (" (gratuitous)" if d["gratuitous"] else "")
    return f"{d['sender_ip']} is at {d['sender_mac']}"


def parse_icmp(buf: bytes, v6: bool = False) -> dict | None:
    if len(buf) < 4:
        return None
    t, c = buf[0], buf[1]
    d: dict = {"type": t, "code": c, "v6": v6,
               "type_name": (ICMP6_TYPES if v6 else ICMP_TYPES).get(t, str(t))}
    if not v6:
        if t == 3:
            d["code_name"] = UNREACH.get(c, str(c))
            if c == 4:
                d["next_hop_mtu"] = struct.unpack("!H", buf[6:8])[0]
        elif t == 11:
            d["code_name"] = "TTL exceeded in transit" if c == 0 else "Fragment reassembly time exceeded"
        elif t == 5:
            d["gateway"] = str(ipaddress.IPv4Address(buf[4:8]))
        elif t in (0, 8) and len(buf) >= 8:
            d["id"], d["seq"] = struct.unpack("!HH", buf[4:8])
            d["data_len"] = len(buf) - 8
        if t in (3, 11, 12, 5, 4) and len(buf) >= 28:
            d["original"] = _embedded_ipv4(buf[8:])
    else:
        if t == 1:
            d["code_name"] = UNREACH6.get(c, str(c))
        elif t == 3:
            d["code_name"] = "Hop limit exceeded in transit" if c == 0 else "Fragment reassembly time exceeded"
        if t == 2 and len(buf) >= 8:
            d["mtu"] = struct.unpack("!I", buf[4:8])[0]
        elif t in (128, 129) and len(buf) >= 8:
            d["id"], d["seq"] = struct.unpack("!HH", buf[4:8])
            d["data_len"] = len(buf) - 8
        elif t in (135, 136) and len(buf) >= 24:
            d["target"] = str(ipaddress.IPv6Address(buf[8:24]))
            if t == 136:
                d["router"], d["solicited"], d["override"] = bool(buf[4] & 0x80), bool(buf[4] & 0x40), bool(buf[4] & 0x20)
            d.update(_nd_options(buf[24:]))
        elif t == 134 and len(buf) >= 16:
            d["hop_limit"], d["managed"], d["other"] = buf[4], bool(buf[5] & 0x80), bool(buf[5] & 0x40)
            d["router_lifetime"] = struct.unpack("!H", buf[6:8])[0]
            d.update(_nd_options(buf[16:]))
        elif t == 133:
            d.update(_nd_options(buf[8:]))
        elif t == 143 and len(buf) >= 8:                        # MLDv2 report
            d["groups"] = [str(ipaddress.IPv6Address(buf[off + 4:off + 20]))
                           for off in _mld2_records(buf)]
        if t in (1, 2, 3) and len(buf) >= 48:
            ob = buf[8:]
            d["original"] = {"src": str(ipaddress.IPv6Address(ob[8:24])),
                             "dst": str(ipaddress.IPv6Address(ob[24:40])), "proto": ob[6],
                             "sport": struct.unpack("!H", ob[40:42])[0] if len(ob) >= 44 else None,
                             "dport": struct.unpack("!H", ob[42:44])[0] if len(ob) >= 44 else None}
    return d


def _nd_options(b: bytes) -> dict:
    """Neighbor Discovery options: link-layer address, prefix information, MTU."""
    o: dict = {}
    off = 0
    while off + 8 <= len(b) and b[off + 1]:
        t, ln = b[off], b[off + 1] * 8
        v = b[off:off + ln]
        if t in (1, 2) and ln >= 8:
            o["source_lladdr" if t == 1 else "target_lladdr"] = mac(v[2:8])
        elif t == 3 and ln >= 32:
            o.setdefault("prefixes", []).append({
                "prefix": f"{ipaddress.IPv6Address(v[16:32])}/{v[2]}", "on_link": bool(v[3] & 0x80),
                "autonomous": bool(v[3] & 0x40), "valid_lifetime": struct.unpack("!I", v[4:8])[0],
                "preferred_lifetime": struct.unpack("!I", v[8:12])[0]})
        elif t == 5 and ln >= 8:
            o["mtu"] = struct.unpack("!I", v[4:8])[0]
        off += ln
    return o


def _mld2_records(b: bytes):
    off = 8
    for _ in range(struct.unpack("!H", b[6:8])[0]):
        if off + 20 > len(b):
            return
        yield off
        off += 20 + 16 * struct.unpack("!H", b[off + 2:off + 4])[0] + 4 * b[off + 1]


def _embedded_ipv4(ob: bytes) -> dict | None:
    if len(ob) < 20 or ob[0] >> 4 != 4:
        return None
    ihl = (ob[0] & 0xF) * 4
    o = {"src": str(ipaddress.IPv4Address(ob[12:16])), "dst": str(ipaddress.IPv4Address(ob[16:20])),
         "proto": ob[9], "ttl": ob[8], "length": struct.unpack("!H", ob[2:4])[0], "sport": None, "dport": None}
    if o["proto"] in (6, 17) and len(ob) >= ihl + 4:
        o["sport"], o["dport"] = struct.unpack("!HH", ob[ihl:ihl + 4])
    return o


def icmp_info(d: dict) -> str:
    s = d["type_name"]
    if "code_name" in d:
        s += f" ({d['code_name']})"
    if "next_hop_mtu" in d:
        s += f" next-hop MTU={d['next_hop_mtu']}"
    if "mtu" in d:
        s += f" MTU={d['mtu']}"
    if "seq" in d:
        s += f" id=0x{d['id']:04x} seq={d['seq']}"
    if "target" in d:
        s += f" for {d['target']}"
    if d.get("prefixes"):
        s += " prefix " + ", ".join(x["prefix"] for x in d["prefixes"])
    return s


def parse_stp(buf: bytes) -> dict | None:
    # LLC header already stripped by caller; buf starts at BPDU
    if len(buf) < 4 or buf[:2] != b"\x00\x00":
        return None
    ver, btype = buf[2], buf[3]
    d = {"version": ver, "bpdu_type": {0: "Config", 0x80: "TCN", 2: "RST/MST"}.get(btype, hex(btype)),
         "tc": False}
    if btype in (0, 2) and len(buf) >= 35:
        flags = buf[4]
        d["tc"] = bool(flags & 0x01)
        d["root"] = f"{struct.unpack('!H', buf[5:7])[0]}/{mac(buf[7:13])}"
        d["root_cost"] = struct.unpack("!I", buf[13:17])[0]
        d["bridge"] = f"{struct.unpack('!H', buf[17:19])[0]}/{mac(buf[19:25])}"
    elif btype == 0x80:
        d["tc"] = True
    return d


def stp_info(d: dict) -> str:
    s = f"STP {d['bpdu_type']} BPDU"
    if d.get("root"):
        s += f" Root={d['root']} Cost={d['root_cost']}"
    if d["tc"]:
        s += " [Topology Change]"
    return s
