"""Layered dissector: link layer -> IP -> TCP/UDP/ICMP/routing -> application."""
from __future__ import annotations

import ipaddress
import struct

from .packet import Packet, TCPInfo
from .protocols import bgp, dhcp, dns, eigrp, http, l2, ospf, rip, tls
from .reader import RawFrame

IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
             88: "EIGRP", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}
WELL_KNOWN = {20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 67: "DHCP",
              68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "KERBEROS", 110: "POP3", 123: "NTP", 137: "NBNS",
              138: "NBDS", 139: "NBSS", 143: "IMAP", 161: "SNMP", 162: "SNMP-TRAP", 179: "BGP",
              389: "LDAP", 443: "TLS", 445: "SMB", 465: "SMTPS", 514: "SYSLOG", 520: "RIP", 521: "RIPng",
              546: "DHCPv6", 547: "DHCPv6", 587: "SMTP", 636: "LDAPS", 853: "DoT", 993: "IMAPS",
              995: "POP3S", 1433: "MSSQL", 1494: "CITRIX", 1812: "RADIUS", 1900: "SSDP", 2598: "CITRIX",
              3306: "MYSQL", 3389: "RDP", 5060: "SIP", 5353: "MDNS", 5432: "POSTGRES", 8080: "HTTP",
              8000: "HTTP", 8443: "TLS"}


def _ones_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def dissect(no: int, frame: RawFrame) -> Packet:
    p = Packet(no=no, ts=frame.ts, caplen=len(frame.data), wirelen=frame.wirelen)
    buf = frame.data
    lt = frame.linktype
    try:
        if lt == 1:
            _ethernet(p, buf)
        elif lt in (101, 12, 14, 228, 229):
            _ip(p, buf)
        elif lt == 0 or lt == 108:  # BSD loopback (null)
            _ip(p, buf[4:])
        elif lt == 113:  # Linux cooked SLL
            _ethertype(p, struct.unpack("!H", buf[14:16])[0], buf[16:])
        elif lt == 276:  # Linux cooked SLL2
            _ethertype(p, struct.unpack("!H", buf[0:2])[0], buf[20:])
        else:
            p.protocol = f"LINKTYPE_{lt}"
    except (struct.error, IndexError, ValueError) as exc:  # malformed packet
        p.tags.append("malformed")
        p.info = p.info or f"[Malformed packet: {exc.__class__.__name__}]"
    if not p.info:
        p.info = p.protocol
    return p


def _ethernet(p: Packet, buf: bytes) -> None:
    p.eth_dst, p.eth_src = l2.mac(buf[0:6]), l2.mac(buf[6:12])
    p.protocol = "ETH"
    etype = struct.unpack("!H", buf[12:14])[0]
    off = 14
    while etype in (0x8100, 0x88A8, 0x9100):
        p.vlan = struct.unpack("!H", buf[off:off + 2])[0] & 0x0FFF
        etype = struct.unpack("!H", buf[off + 2:off + 4])[0]
        off += 4
    if etype <= 1500:  # IEEE 802.3 length + LLC
        llc = buf[off:off + 3]
        if llc[:2] == b"\x42\x42":
            d = l2.parse_stp(buf[off + 3:])
            if d:
                p.layers["stp"] = d
                p.protocol = "STP"
                p.info = l2.stp_info(d)
                return
        p.protocol = "LLC"
        return
    _ethertype(p, etype, buf[off:])


def _ethertype(p: Packet, etype: int, buf: bytes) -> None:
    p.ethertype = etype
    if etype in (0x0800, 0x86DD):
        _ip(p, buf)
    elif etype == 0x0806:
        d = l2.parse_arp(buf)
        if d:
            p.layers["arp"] = d
            p.protocol = "ARP"
            p.info = l2.arp_info(d)
    elif etype == 0x88CC:
        p.protocol = "LLDP"
    else:
        p.protocol = f"0x{etype:04x}"


def _ip(p: Packet, buf: bytes) -> None:
    ver = buf[0] >> 4
    if ver == 4:
        ihl = (buf[0] & 0x0F) * 4
        tot, ident, frag, ttl, proto = struct.unpack("!HHHBB", buf[2:10])
        p.ip_version, p.ip_hdr_len, p.ip_len, p.ip_id, p.ttl, p.ip_proto = 4, ihl, tot, ident, ttl, proto
        p.dscp = buf[1] >> 2
        p.ip_df, p.ip_mf, p.ip_frag_offset = bool(frag & 0x4000), bool(frag & 0x2000), (frag & 0x1FFF) * 8
        p.src = str(ipaddress.IPv4Address(buf[12:16]))
        p.dst = str(ipaddress.IPv4Address(buf[16:20]))
        cks = struct.unpack("!H", buf[10:12])[0]
        p.ip_checksum_ok = None if cks == 0 else _ones_sum(buf[:ihl]) == 0xFFFF
        p.protocol = "IPv4"
        end = min(len(buf), tot) if tot >= ihl else len(buf)
        payload = buf[ihl:end]
        wire_l4 = tot - ihl if tot > ihl else None   # tot == 0 with TSO/GSO: fall back to captured length
        if p.ip_frag_offset or p.ip_mf:
            p.tags.append("ip_fragment")
            if p.ip_frag_offset:
                p.protocol = "IPv4"
                p.info = f"Fragmented IP protocol (proto={proto}, off={p.ip_frag_offset}, ID={ident:04x})"
                return
    elif ver == 6:
        plen, nh, hlim = struct.unpack("!HBB", buf[4:8])
        p.ip_version, p.ttl, p.ip_hdr_len = 6, hlim, 40
        p.src = str(ipaddress.IPv6Address(buf[8:24]))
        p.dst = str(ipaddress.IPv6Address(buf[24:40]))
        p.ip_len = plen + 40
        p.protocol = "IPv6"
        off = 40
        while nh in (0, 43, 44, 60, 51):
            if nh == 44:
                nh2 = buf[off]
                off += 8
                nh = nh2
                p.tags.append("ip_fragment")
                continue
            ext_len = (buf[off + 1] + 2) * 4 if nh == 51 else (buf[off + 1] + 1) * 8
            nh = buf[off]
            off += ext_len
        proto = nh
        p.ip_proto = proto
        payload = buf[off:40 + plen] if plen else buf[off:]
        wire_l4 = plen + 40 - off if plen else None
    else:
        p.protocol = "UNKNOWN-L3"
        return
    _l4(p, proto, payload, wire_l4)


def _l4(p: Packet, proto: int, buf: bytes, wire_l4: int | None = None) -> None:
    if proto == 6 and len(buf) >= 20:
        sport, dport, seq, ack, offf, flags, win = struct.unpack("!HHIIBBH", buf[:16])
        hl = (offf >> 4) * 4
        opts = _tcp_options(buf[20:hl])
        payload = buf[hl:]
        # segment length comes from the IP header, not the captured bytes, so sliced
        # captures (snaplen) still give correct sequence analysis
        seg_len = max(0, wire_l4 - hl) if wire_l4 is not None and wire_l4 >= hl else len(payload)
        if seg_len > len(payload):
            p.tags.append("sliced")
        t = TCPInfo(sport, dport, seq, ack, flags, win, hl, seg_len, opts)
        p.tcp, p.sport, p.dport, p.payload = t, sport, dport, payload
        p.protocol = "TCP"
        p.info = f"{sport} → {dport} [{t.flag_str()}] Seq={seq} Ack={ack} Win={win} Len={seg_len}"
        if payload:
            _tcp_app(p, payload)
    elif proto == 17 and len(buf) >= 8:
        sport, dport, ulen, _cks = struct.unpack("!HHHH", buf[:8])
        p.sport, p.dport, p.payload = sport, dport, buf[8:]
        p.protocol = "UDP"
        p.info = f"{sport} → {dport} Len={len(buf) - 8}"
        _udp_app(p, buf[8:])
    elif proto in (1, 58):
        d = l2.parse_icmp(buf, v6=proto == 58)
        if d:
            p.layers["icmp"] = d
            p.protocol = "ICMPv6" if proto == 58 else "ICMP"
            p.info = l2.icmp_info(d)
    elif proto == 89:
        d = ospf.parse(buf)
        if d:
            p.layers["ospf"] = d
            p.protocol = "OSPF"
            p.info = ospf.info(d)
    elif proto == 88:
        d = eigrp.parse(buf)
        if d:
            p.layers["eigrp"] = d
            p.protocol = "EIGRP"
            p.info = eigrp.info(d)
    else:
        p.protocol = IP_PROTOS.get(proto, f"IP-{proto}")
        p.info = p.protocol


def _tcp_options(buf: bytes) -> dict:
    o: dict = {}
    i = 0
    nops = 0
    while i < len(buf):
        kind = buf[i]
        if kind == 0:
            break
        if kind == 1:
            nops += 1
            i += 1
            continue
        if i + 1 >= len(buf):
            break
        ln = buf[i + 1]
        if ln < 2:
            break
        val = buf[i + 2:i + ln]
        if kind == 2 and len(val) == 2:
            o["mss"] = struct.unpack("!H", val)[0]
        elif kind == 3 and len(val) == 1:
            o["wscale"] = val[0]
        elif kind == 4:
            o["sack_perm"] = True
        elif kind == 5:
            o["sack"] = [struct.unpack("!II", val[j:j + 8]) for j in range(0, len(val) - 7, 8)]
        elif kind == 8 and len(val) == 8:
            o["ts"] = struct.unpack("!II", val)
        i += ln
    if nops:
        o["nops"] = nops
    return o


def _set(p: Packet, name: str, d: dict, info: str) -> None:
    p.layers[name] = d
    p.protocol = name.upper()
    p.info = info


def _tcp_app(p: Packet, payload: bytes) -> None:
    ports = (p.sport, p.dport)
    if 179 in ports:
        d = bgp.parse(payload)
        if d:
            return _set(p, "bgp", d, bgp.info(d))
    if http.looks_like_http(payload):
        d = http.parse(payload)
        if d:
            return _set(p, "http", d, http.info(d))
    if tls.looks_like_tls(payload):
        d = tls.parse(payload)
        if d:
            return _set(p, "tls", d, tls.info(d))
    if 53 in ports and len(payload) > 14:
        d = dns.parse(payload[2:])
        if d:
            return _set(p, "dns", d, dns.info(d))
    name = WELL_KNOWN.get(min(ports)) or WELL_KNOWN.get(max(ports))
    if name and name not in ("HTTP", "TLS"):
        p.protocol = name
        p.info = f"{name} data ({len(payload)} bytes) " + p.info


def _udp_app(p: Packet, payload: bytes) -> None:
    ports = (p.sport, p.dport)
    if 53 in ports or 5353 in ports:
        d = dns.parse(payload)
        if d:
            _set(p, "dns", d, dns.info(d))
            if 5353 in ports:
                p.protocol = "MDNS"
            return
    if 67 in ports or 68 in ports:
        d = dhcp.parse(payload)
        if d:
            return _set(p, "dhcp", d, dhcp.info(d))
    if 520 in ports:
        d = rip.parse(payload)
        if d:
            return _set(p, "rip", d, rip.info(d))
    if 443 in ports and payload and payload[0] & 0x80:
        p.protocol = "QUIC"
        p.info = f"QUIC long header ({len(payload)} bytes)"
        return
    name = WELL_KNOWN.get(p.dport) or WELL_KNOWN.get(p.sport)
    if name:
        p.protocol = name
        p.info = f"{name} " + p.info
