"""Packet details tree (Wireshark's middle pane) with byte ranges for the hex pane.

Headers (Frame, Ethernet, VLAN, ISL, LLC/SNAP, 802.11, IPv4, IPv6, TCP, UDP, ICMP, ARP, GRE, VXLAN) are
re-parsed from the raw bytes so every field maps to its exact bytes. Application layers are shown from the
analyzer's decoded fields and map to the whole payload. Nodes carry a filter ``field`` + ``value`` when the
display-filter engine knows that field, so the UI can offer "Apply as filter".
"""
from __future__ import annotations

import socket
import struct
import time

from .dfilter import FIELDS, protocol_stack
from .protocols import l2ctl

TCP_OPTS = {0: "End of Option List", 1: "No-Operation (NOP)", 2: "Maximum segment size", 3: "Window scale",
            4: "SACK permitted", 5: "SACK", 8: "Timestamps"}
ETYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q Virtual LAN", 0x88A8: "802.1ad",
          0x888E: "802.1X Authentication", 0x88CC: "LLDP", 0x9000: "Loopback", 0x6002: "DEC MOP Remote Console",
          0x8035: "RARP"}
IP_PROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 88: "EIGRP",
            89: "OSPF", 103: "PIM", 112: "VRRP"}
SKIP_LAYERS = {"wlan", "isl", "gre", "vxlan", "arp", "icmp"}
DF_TEXT = ", Don't fragment"


def bits(value: int, mask: int, width: int = 8) -> str:
    """Wireshark bit-field notation: ``.... ..1.`` for the bits of ``mask`` in ``value``."""
    s = "".join(("1" if value & (1 << i) else "0") if mask & (1 << i) else "." for i in range(width - 1, -1, -1))
    return " ".join(s[i:i + 4] for i in range(0, width, 4))


def N(label, start=None, length=None, children=None, field=None, value=None):
    n = {"label": label}
    if start is not None and length is not None and length > 0:
        n["range"] = [start, length]
    if children:
        n["children"] = children
    if field in FIELDS:                               # only fields the display-filter engine understands
        n["field"], n["value"] = field, value
    return n


def tree(p, raw: bytes, linktype: int) -> list[dict]:
    """The details tree for decoded packet ``p`` and its captured bytes."""
    out = [_frame(p, raw)]
    try:
        if linktype == 1:
            out += _ethernet(p, raw, 0)
        elif linktype in (101, 12, 14, 228, 229):
            out += _ip(p, raw, 0)
        elif linktype in (0, 108):
            out.append(N("Null/Loopback", 0, 4))
            out += _ip(p, raw, 4)
        elif linktype == 113:
            out.append(N("Linux cooked capture v1", 0, 16))
            out += _ethertype(p, raw, 16, struct.unpack("!H", raw[14:16])[0])
        elif linktype == 276:
            out.append(N("Linux cooked capture v2", 0, 20))
            out += _ethertype(p, raw, 20, struct.unpack("!H", raw[0:2])[0])
        elif linktype in (105, 127):
            out += _wlan(p, raw, linktype == 127)
        else:
            out.append(N(f"Link type {linktype} (not decoded)", 0, len(raw)))
    except (struct.error, IndexError, ValueError, OSError):
        out.append(N("[Malformed Packet: the remaining bytes could not be decoded]"))
    return out


def _frame(p, raw):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(p.ts)) + f".{int((p.ts % 1) * 1e9):09d} UTC"
    ch = [N(f"Arrival Time: {ts}"), N(f"Epoch Arrival Time: {p.ts:.9f}"),
          N(f"Time since reference or first frame: {p.rel_ts:.9f} seconds", field="frame.time_relative", value=round(p.rel_ts, 9)),
          N(f"Frame Number: {p.no}", field="frame.number", value=p.no),
          N(f"Frame Length: {p.wirelen} bytes ({p.wirelen * 8} bits)", field="frame.len", value=p.wirelen),
          N(f"Capture Length: {len(raw)} bytes ({len(raw) * 8} bits)", field="frame.cap_len", value=len(raw)),
          N(f"[Protocols in frame: {protocol_stack(p)}]")]
    if p.tags:
        ch.append(N(f"[PacketLens tags: {', '.join(p.tags)}]"))
    return N(f"Frame {p.no}: {p.wirelen} bytes on wire ({p.wirelen * 8} bits), {len(raw)} bytes captured ({len(raw) * 8} bits)",
             0, len(raw), ch)


# ------------------------------------------------------------------ layer 2 --
def _mac(b):
    return b.hex(":")


def _ethernet(p, raw, off):
    out = []
    if raw[off:off + 5] == l2ctl.ISL_DA and len(raw) >= off + 26:
        vlan = struct.unpack("!H", raw[off + 20:off + 22])[0] >> 1
        out.append(N(f"Cisco ISL, VLAN {vlan}", off, 26, [N(f"Destination: {_mac(raw[off:off + 6])}", off, 6),
                                                         N(f"Source: {_mac(raw[off + 6:off + 12])}", off + 6, 6),
                                                         N(f"VLAN ID: {vlan}", off + 20, 2, field="vlan.id", value=vlan)]))
        return out + _ethernet(p, raw, off + 26)
    dst, src, et = raw[off:off + 6], raw[off + 6:off + 12], struct.unpack("!H", raw[off + 12:off + 14])[0]
    kids = [N(f"Destination: {_mac(dst)}", off, 6, field="eth.dst", value=_mac(dst)),
            N(f"Source: {_mac(src)}", off + 6, 6, field="eth.src", value=_mac(src))]
    if et <= 1500:
        kids.append(N(f"Length: {et}", off + 12, 2))
        out.append(N(f"IEEE 802.3 Ethernet, Src: {_mac(src)}, Dst: {_mac(dst)}", off, 14, kids))
        return out + _llc(p, raw, off + 14, et)
    kids.append(N(f"Type: {ETYPES.get(et, 'Unknown')} (0x{et:04x})", off + 12, 2, field="eth.type", value=f"0x{et:04x}"))
    out.append(N(f"Ethernet II, Src: {_mac(src)}, Dst: {_mac(dst)}", off, 14, kids))
    off += 14
    while et in (0x8100, 0x88A8, 0x9100):
        tci, et2 = struct.unpack("!HH", raw[off:off + 4])
        vid = tci & 0x0FFF
        out.append(N(f"802.1Q Virtual LAN, PRI: {tci >> 13}, DEI: {(tci >> 12) & 1}, ID: {vid}", off, 4, [
            N(f"Priority: {tci >> 13}", off, 2), N(f"DEI: {(tci >> 12) & 1}", off, 2),
            N(f"ID: {vid}", off, 2, field="vlan.id", value=vid),
            N(f"Type: {ETYPES.get(et2, 'Length' if et2 <= 1500 else 'Unknown')} (0x{et2:04x})", off + 2, 2)]))
        et = et2
        off += 4
        if et <= 1500:
            return out + _llc(p, raw, off, et)
    return out + _ethertype(p, raw, off, et)


def _llc(p, raw, off, length):
    end = min(len(raw), off + length)
    dsap, ssap, ctl = raw[off], raw[off + 1], raw[off + 2]
    kids = [N(f"DSAP: 0x{dsap:02x}", off, 1), N(f"SSAP: 0x{ssap:02x}", off + 1, 1), N(f"Control field: 0x{ctl:02x}", off + 2, 1)]
    out = [N("Logical-Link Control", off, 3, kids)]
    off += 3
    if dsap == 0xAA:
        oui, pid = raw[off:off + 3].hex(), struct.unpack("!H", raw[off + 3:off + 5])[0]
        out.append(N(f"SNAP: Organization Code 0x{oui}{' (Cisco)' if oui == '00000c' else ''}, PID 0x{pid:04x}", off, 5))
        off += 5
    return out + _app(p, raw, off, end)


def _ethertype(p, raw, off, et):
    if et in (0x0800, 0x86DD):
        return _ip(p, raw, off)
    if et == 0x0806:
        return [_arp(raw, off)]
    return _app(p, raw, off, len(raw), fallback=ETYPES.get(et, f"Ethertype 0x{et:04x}"))


def _arp(raw, off):
    op = struct.unpack("!H", raw[off + 6:off + 8])[0]
    sip, tip = socket.inet_ntoa(raw[off + 14:off + 18]), socket.inet_ntoa(raw[off + 24:off + 28])
    return N(f"Address Resolution Protocol ({'request' if op == 1 else 'reply' if op == 2 else op})", off, 28, [
        N("Hardware type: Ethernet (1)", off, 2), N("Protocol type: IPv4 (0x0800)", off + 2, 2),
        N("Hardware size: 6", off + 4, 1), N("Protocol size: 4", off + 5, 1),
        N(f"Opcode: {'request' if op == 1 else 'reply' if op == 2 else op} ({op})", off + 6, 2, field="arp.opcode", value=op),
        N(f"Sender MAC address: {_mac(raw[off + 8:off + 14])}", off + 8, 6, field="arp.src.hw_mac", value=_mac(raw[off + 8:off + 14])),
        N(f"Sender IP address: {sip}", off + 14, 4, field="arp.src.proto_ipv4", value=sip),
        N(f"Target MAC address: {_mac(raw[off + 18:off + 24])}", off + 18, 6, field="arp.dst.hw_mac", value=_mac(raw[off + 18:off + 24])),
        N(f"Target IP address: {tip}", off + 24, 4, field="arp.dst.proto_ipv4", value=tip)])


def _wlan(p, raw, radiotap):
    out, off = [], 0
    if radiotap:
        off = struct.unpack("<H", raw[2:4])[0]
        out.append(N(f"Radiotap Header v{raw[0]}, Length {off}", 0, off))
    w = p.layers.get("wlan") or {}
    fc1 = raw[off + 1]
    hl = 24 + (6 if fc1 & 3 == 3 else 0) + (2 if (raw[off] >> 4) & 8 and (raw[off] >> 2) & 3 == 2 else 0)
    out.append(N(f"IEEE 802.11 {w.get('type', 'frame')}, Flags: {'protected ' if fc1 & 0x40 else ''}", off, hl, [
        N(f"BSS Id: {w.get('bssid')}"), N(f"Source address: {w.get('src')}"), N(f"Destination address: {w.get('dst')}")]))
    off += hl
    if w.get("type") == "Data" and not w.get("protected") and raw[off:off + 3] == b"\xaa\xaa\x03":
        et = struct.unpack("!H", raw[off + 6:off + 8])[0]
        out.append(N(f"Logical-Link Control, SNAP, Type {ETYPES.get(et, hex(et))}", off, 8))
        out += _ethertype(p, raw, off + 8, et)
    return out


# ------------------------------------------------------------------ layer 3 --
def _ip(p, raw, off):
    ver = raw[off] >> 4
    if ver == 6:
        return _ip6(p, raw, off)
    ihl = (raw[off] & 15) * 4
    tos, tot, ident, frag, ttl, proto, cks = struct.unpack("!BHHHBBH", raw[off + 1:off + 12])
    src, dst = socket.inet_ntoa(raw[off + 12:off + 16]), socket.inet_ntoa(raw[off + 16:off + 20])
    df, mf, fo = bool(frag & 0x4000), bool(frag & 0x2000), (frag & 0x1FFF) * 8
    kids = [N(f"{ver:04b} .... = Version: {ver}", off, 1), N(f".... {ihl // 4:04b} = Header Length: {ihl} bytes ({ihl // 4})", off, 1),
            N(f"Differentiated Services Field: 0x{tos:02x} (DSCP: {tos >> 2}, ECN: {tos & 3})", off + 1, 1,
              field="ip.dsfield.dscp", value=tos >> 2),
            N(f"Total Length: {tot}", off + 2, 2, field="ip.len", value=tot),
            N(f"Identification: 0x{ident:04x} ({ident})", off + 4, 2, field="ip.id", value=ident),
            N(f"Flags: 0x{frag >> 13:x}{DF_TEXT if df else ''}{', More fragments' if mf else ''}", off + 6, 1, [
                N(f".{int(df)}.. .... = Don't fragment: {'Set' if df else 'Not set'}", off + 6, 1, field="ip.flags.df", value=int(df)),
                N(f"..{int(mf)}. .... = More fragments: {'Set' if mf else 'Not set'}", off + 6, 1, field="ip.flags.mf", value=int(mf))]),
            N(f"Fragment Offset: {fo}", off + 6, 2, field="ip.frag_offset", value=fo),
            N(f"Time to Live: {ttl}", off + 8, 1, field="ip.ttl", value=ttl),
            N(f"Protocol: {IP_PROTO.get(proto, 'Unknown')} ({proto})", off + 9, 1, field="ip.proto", value=proto),
            N(f"Header Checksum: 0x{cks:04x} [{'correct' if p.ip_checksum_ok else 'incorrect' if p.ip_checksum_ok is False else 'unverified'}]",
              off + 10, 2),
            N(f"Source Address: {src}", off + 12, 4, field="ip.src", value=src),
            N(f"Destination Address: {dst}", off + 16, 4, field="ip.dst", value=dst)]
    out = [N(f"Internet Protocol Version 4, Src: {src}, Dst: {dst}", off, ihl, kids)]
    end = min(len(raw), off + tot) if tot >= ihl else len(raw)
    if fo or mf:
        if "ip_reassembled" in p.tags:
            out.append(N(f"[Reassembled IPv4 datagram; this fragment carries bytes {fo}–{fo + end - off - ihl - 1}]"))
            return out + _app(p, raw, off + ihl, end, fallback="Fragment data")
        return out + [N(f"Fragment data ({end - off - ihl} bytes, offset {fo})", off + ihl, end - off - ihl)]
    return out + _l4(p, raw, off + ihl, end, proto)


def _ip6(p, raw, off):
    plen, nh, hlim = struct.unpack("!HBB", raw[off + 4:off + 8])
    src = socket.inet_ntop(socket.AF_INET6, raw[off + 8:off + 24])
    dst = socket.inet_ntop(socket.AF_INET6, raw[off + 24:off + 40])
    kids = [N("0110 .... = Version: 6", off, 1), N(f"Payload Length: {plen}", off + 4, 2),
            N(f"Next Header: {IP_PROTO.get(nh, nh)} ({nh})", off + 6, 1, field="ipv6.nxt", value=nh),
            N(f"Hop Limit: {hlim}", off + 7, 1, field="ipv6.hlim", value=hlim),
            N(f"Source Address: {src}", off + 8, 16, field="ipv6.src", value=src),
            N(f"Destination Address: {dst}", off + 24, 16, field="ipv6.dst", value=dst)]
    out = [N(f"Internet Protocol Version 6, Src: {src}, Dst: {dst}", off, 40, kids)]
    end = min(len(raw), off + 40 + plen) if plen else len(raw)
    o = off + 40
    while nh in (0, 43, 44, 60, 51):
        ln = 8 if nh == 44 else (raw[o + 1] + 2) * 4 if nh == 51 else (raw[o + 1] + 1) * 8
        out.append(N({0: "Hop-by-Hop Options", 43: "Routing Header", 44: "Fragment Header", 60: "Destination Options",
                      51: "Authentication Header"}[nh], o, ln))
        if nh == 44 and struct.unpack("!H", raw[o + 2:o + 4])[0] & 0xFFF9:
            return out + [N("Fragment data", o + 8, end - o - 8)]
        nh, o = raw[o], o + ln
    return out + _l4(p, raw, o, end, nh)


# ------------------------------------------------------------------ layer 4 --
def _l4(p, raw, off, end, proto):
    if proto == 6 and end - off >= 20:
        return _tcp(p, raw, off, end)
    if proto == 17 and end - off >= 8:
        return _udp(p, raw, off, end)
    if proto in (1, 58) and end - off >= 4:
        return [_icmp(p, raw, off, end, proto == 58)]
    if proto == 47:
        return _gre(p, raw, off, end)
    return _app(p, raw, off, end, fallback=IP_PROTO.get(proto, f"IP protocol {proto}"))


def _tcp(p, raw, off, end):
    sp, dp, seq, ack, offf, fl, win, cks, urg = struct.unpack("!HHIIBBHHH", raw[off:off + 20])
    hl = (offf >> 4) * 4
    t = p.tcp
    flags = [(0x80, "Congestion Window Reduced"), (0x40, "ECN-Echo"), (0x20, "Urgent"), (0x10, "Acknowledgment"),
             (0x08, "Push"), (0x04, "Reset"), (0x02, "Syn"), (0x01, "Fin")]
    fnames = {0x20: "tcp.flags.urg", 0x10: "tcp.flags.ack", 0x08: "tcp.flags.push", 0x04: "tcp.flags.reset",
              0x02: "tcp.flags.syn", 0x01: "tcp.flags.fin"}
    fkids = [N(f"{bits(fl, b)} = {name}: {'Set' if fl & b else 'Not set'}", off + 13, 1, field=fnames.get(b),
               value=int(bool(fl & b))) for b, name in flags]
    kids = [N(f"Source Port: {sp}", off, 2, field="tcp.srcport", value=sp),
            N(f"Destination Port: {dp}", off + 2, 2, field="tcp.dstport", value=dp)]
    if t is not None:
        kids.append(N(f"[Stream index: {t.stream}]", field="tcp.stream", value=t.stream))
        kids.append(N(f"[TCP Segment Len: {t.payload_len}]", field="tcp.len", value=t.payload_len))
    kids += [N(f"Sequence Number (raw): {seq}", off + 4, 4, field="tcp.seq", value=seq),
             N(f"Acknowledgment Number (raw): {ack}", off + 8, 4, field="tcp.ack", value=ack),
             N(f"{offf >> 4:04b} .... = Header Length: {hl} bytes ({offf >> 4})", off + 12, 1, field="tcp.hdr_len", value=hl),
             N(f"Flags: 0x{fl:03x} ({t.flag_str() if t else fl})", off + 12, 2, fkids, field="tcp.flags", value=f"0x{fl:03x}"),
             N(f"Window: {win}", off + 14, 2, field="tcp.window_size_value", value=win)]
    if t is not None and t.calc_window != win:
        kids.append(N(f"[Calculated window size: {t.calc_window}]", field="tcp.window_size", value=t.calc_window))
    kids += [N(f"Checksum: 0x{cks:04x} [unverified]", off + 16, 2), N(f"Urgent Pointer: {urg}", off + 18, 2)]
    if hl > 20:
        kids.append(N(f"Options: ({hl - 20} bytes)", off + 20, hl - 20, _tcp_options(raw, off + 20, off + hl)))
    if t is not None:
        an = []
        if t.analysis:
            an += [N(f"[Expert Info: {a.replace('_', ' ')}]", field=f"tcp.analysis.{_analysis_field(a)}", value=None)
                   for a in t.analysis]
        if t.bytes_in_flight:
            an.append(N(f"[Bytes in flight: {t.bytes_in_flight}]", field="tcp.analysis.bytes_in_flight", value=t.bytes_in_flight))
        an.append(N(f"[Time since previous frame in this TCP stream: {t.time_delta:.9f} seconds]", field="tcp.time_delta",
                    value=round(t.time_delta, 9)))
        kids.append(N("[SEQ/ACK analysis]", None, None, an))
    out = [N(f"Transmission Control Protocol, Src Port: {sp}, Dst Port: {dp}, Seq: {seq}, Ack: {ack}, Len: {max(0, end - off - hl)}",
             off, hl, kids)]
    return out + _app(p, raw, off + hl, end)


def _analysis_field(flag):
    return {"ack_unseen": "ack_lost_segment"}.get(flag, flag)


def _tcp_options(raw, off, end):
    out = []
    while off < end:
        kind = raw[off]
        if kind in (0, 1):
            out.append(N(f"TCP Option - {TCP_OPTS[kind]}", off, 1))
            off += 1
            if kind == 0:
                break
            continue
        ln = raw[off + 1] if off + 1 < end else 0
        if ln < 2:
            break
        v = raw[off + 2:off + ln]
        desc = TCP_OPTS.get(kind, f"Unknown ({kind})")
        if kind == 2 and len(v) == 2:
            desc += f": {struct.unpack('!H', v)[0]} bytes"
        elif kind == 3 and len(v) == 1:
            desc += f": {v[0]} (multiply by {2 ** v[0]})"
        elif kind == 8 and len(v) == 8:
            desc += ": TSval {}, TSecr {}".format(*struct.unpack("!II", v))
        out.append(N(f"TCP Option - {desc}", off, ln, field="tcp.options.mss_val" if kind == 2 else None,
                     value=struct.unpack("!H", v)[0] if kind == 2 and len(v) == 2 else None))
        off += ln
    return out


def _udp(p, raw, off, end):
    sp, dp, ln, cks = struct.unpack("!HHHH", raw[off:off + 8])
    out = [N(f"User Datagram Protocol, Src Port: {sp}, Dst Port: {dp}", off, 8, [
        N(f"Source Port: {sp}", off, 2, field="udp.srcport", value=sp),
        N(f"Destination Port: {dp}", off + 2, 2, field="udp.dstport", value=dp),
        N(f"Length: {ln}", off + 4, 2), N(f"Checksum: 0x{cks:04x} [unverified]", off + 6, 2)])]
    if "vxlan" in p.layers and dp == 4789:
        vni = int.from_bytes(raw[off + 12:off + 15], "big")
        out.append(N(f"Virtual eXtensible Local Area Network, VNI: {vni}", off + 8, 8, [
            N(f"Flags: 0x{raw[off + 8]:02x}", off + 8, 1), N(f"VXLAN Network Identifier (VNI): {vni}", off + 12, 3,
                                                               field="vxlan.vni", value=vni)]))
        return out + _ethernet(p, raw, off + 16)
    return out + _app(p, raw, off + 8, end)


def _icmp(p, raw, off, end, v6):
    t, c, cks = raw[off], raw[off + 1], struct.unpack("!H", raw[off + 2:off + 4])[0]
    d = p.layers.get("icmp") or {}
    fld = "icmpv6" if v6 else "icmp"
    kids = [N(f"Type: {t} ({d.get('type_name', '')})", off, 1, field=f"{fld}.type", value=t),
            N(f"Code: {c}" + (f" ({d['code_name']})" if d.get("code_name") else ""), off + 1, 1, field=f"{fld}.code", value=c),
            N(f"Checksum: 0x{cks:04x}", off + 2, 2)]
    if "id" in d:
        kids += [N(f"Identifier (BE): {d['id']} (0x{d['id']:04x})", off + 4, 2), N(f"Sequence Number (BE): {d['seq']}", off + 6, 2)]
    for k in ("next_hop_mtu", "mtu", "gateway", "target", "router_lifetime"):
        if k in d:
            kids.append(N(f"{k.replace('_', ' ').capitalize()}: {d[k]}"))
    if d.get("original") and not v6 and end - off >= 28:
        o = d["original"]
        kids.append(N(f"Internet Protocol Version 4 (original), Src: {o['src']}, Dst: {o['dst']}", off + 8, min(end - off - 8, 28), [
            N(f"Source: {o['src']}"), N(f"Destination: {o['dst']}"), N(f"Protocol: {o['proto']}"),
            N(f"Ports: {o.get('sport')} → {o.get('dport')}")]))
    elif end - off > 8:
        kids.append(N(f"Data ({end - off - 8} bytes)", off + 8, end - off - 8))
    return N(f"Internet Control Message Protocol{'v6' if v6 else ''}", off, end - off, kids)


def _gre(p, raw, off, end):
    flags, proto = struct.unpack("!HH", raw[off:off + 4])
    hl = 4 + 4 * sum(1 for b in (0x8000, 0x2000, 0x1000) if flags & b)
    out = [N(f"Generic Routing Encapsulation ({ETYPES.get(proto, hex(proto))})", off, hl, [
        N(f"Flags and Version: 0x{flags:04x}", off, 2), N(f"Protocol Type: {ETYPES.get(proto, hex(proto))} (0x{proto:04x})", off + 2, 2,
                                                          field="gre.proto", value=proto)])]
    if proto in (0x0800, 0x86DD):
        return out + _ip(p, raw, off + hl)
    return out + [N("Data", off + hl, end - off - hl)]


# ---------------------------------------------------------- application ----
def _app(p, raw, off, end, fallback=None):
    """Decoded application layers of the packet, mapped onto the remaining payload bytes."""
    length = max(0, end - off)
    names = [n for n in p.layers if n not in SKIP_LAYERS]
    if not names:
        if length <= 0:
            return []
        return [N(f"{fallback or 'Data'} ({length} bytes)", off, length)]
    out = []
    for name in names:
        out.append(N(_app_title(name, p), off, length, _dict_nodes(p.layers[name], name, off, length)))
    return out


def _app_title(name, p):
    titles = {"dns": "Domain Name System", "http": "Hypertext Transfer Protocol", "tls": "Transport Layer Security",
              "http2": "HyperText Transfer Protocol 2", "dhcp": "Dynamic Host Configuration Protocol", "bgp": "Border Gateway Protocol",
              "ospf": "Open Shortest Path First", "eigrp": "Cisco EIGRP", "rip": "Routing Information Protocol",
              "stp": "Spanning Tree Protocol", "isis": "ISO 10589 IS-IS", "cdp": "Cisco Discovery Protocol",
              "dtp": "Dynamic Trunking Protocol", "lldp": "Link Layer Discovery Protocol", "pim": "Protocol Independent Multicast",
              "igmp": "Internet Group Management Protocol", "eapol": "802.1X Authentication", "radius": "RADIUS Protocol",
              "fhrp": "First Hop Redundancy Protocol"}
    return f"{titles.get(name, name.upper())} — {p.info[:100]}"


FIELD_OF = {("dns", "qname"): "dns.qry.name", ("dns", "id"): "dns.id", ("dns", "rcode"): "dns.flags.rcode",
            ("http", "method"): "http.request.method", ("http", "uri"): "http.request.uri", ("http", "host"): "http.host",
            ("http", "status"): "http.response.code", ("http", "user_agent"): "http.user_agent",
            ("http", "content_type"): "http.content_type", ("dhcp", "msg_type"): "dhcp.option.dhcp",
            ("cdp", "device_id"): "cdp.deviceid", ("cdp", "native_vlan"): "cdp.native_vlan",
            ("radius", "code_num"): "radius.code", ("radius", "user"): "radius.User_Name",
            ("ospf", "router_id"): "ospf.srcrouter", ("ospf", "area"): "ospf.area_id", ("pim", "type_num"): "pim.type",
            ("igmp", "type_num"): "igmp.type", ("vxlan", "vni"): "vxlan.vni"}


def _dict_nodes(d, layer, off, length, depth=0):
    out = []
    if not isinstance(d, dict) or depth > 3:
        return out
    for k, v in list(d.items())[:40]:
        if k in ("body_preview",) and not v:
            continue
        key = k.replace("_", " ").capitalize()
        f = FIELD_OF.get((layer, k))
        if isinstance(v, dict):
            out.append(N(key, off, length, _dict_nodes(v, layer, off, length, depth + 1)))
        elif isinstance(v, list):
            kids = [N(key + f" #{i + 1}", off, length, _dict_nodes(x, layer, off, length, depth + 1)) if isinstance(x, dict)
                    else N(str(x)[:200], off, length) for i, x in enumerate(v[:20])]
            out.append(N(f"{key} ({len(v)})", off, length, kids))
        else:
            out.append(N(f"{key}: {_fmt(v)}", off, length, field=f, value=v))
    return out


def _fmt(v):
    if isinstance(v, bytes):
        return v.hex()
    s = str(v)
    return s if len(s) <= 200 else s[:200] + "…"

