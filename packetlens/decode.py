"""Layered dissector: link layer -> IP -> TCP/UDP/ICMP/routing -> application."""
from __future__ import annotations

import socket
import struct

from .packet import Packet, TCPInfo
from .protocols import auth, bgp, dhcp, dns, eigrp, fhrp, http, isis, l2, l2ctl, mcast, ospf, rip, tls, tunnel, wlan
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
        elif lt in (105, 127):  # IEEE 802.11 (127: with radiotap header)
            _wlan(p, buf, lt == 127)
        else:
            p.protocol = f"LINKTYPE_{lt}"
    except (struct.error, IndexError, ValueError, OSError) as exc:  # malformed packet (inet_ntoa raises OSError)
        p.tags.append("malformed")
        p.info = p.info or f"[Malformed packet: {exc.__class__.__name__}]"
    if not p.info:
        p.info = p.protocol
    return p


def _wlan(p: Packet, buf: bytes, radiotap: bool) -> None:
    r = wlan.parse(buf, radiotap)
    if r is None:
        p.protocol = "802.11"
        return
    d, etype, payload = r
    p.layers["wlan"] = d
    p.eth_src, p.eth_dst = d["src"], d["dst"]
    p.protocol = "802.11"
    p.info = f"802.11 {d['type']}" + (" (protected)" if d["protected"] else "")
    if etype is not None:
        _ethertype(p, etype, payload)


def _ethernet(p: Packet, buf: bytes) -> None:
    isl = l2ctl.parse_isl(buf)
    if isl is not None:                  # Cisco ISL trunk: decode the encapsulated frame
        vlan, inner = isl
        p.layers["isl"] = {"vlan": vlan}
        _ethernet(p, inner)
        p.vlan = vlan
        return
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
        if llc[:2] == b"\xfe\xfe":
            d = isis.parse(buf[off + 3:])
            if d:
                p.layers["isis"] = d
                p.protocol = "ISIS"
                p.info = isis.info(d)
                return
        if llc == b"\xaa\xaa\x03" and buf[off + 3:off + 6] == l2ctl.CISCO_OUI:
            if _cisco_snap(p, struct.unpack("!H", buf[off + 6:off + 8])[0], buf[off + 8:off + etype]):
                return
        p.protocol = "LLC"
        return
    _ethertype(p, etype, buf[off:])


def _cisco_snap(p: Packet, pid: int, body: bytes) -> bool:
    if pid == 0x2000:
        d, name, info = l2ctl.parse_cdp(body), "CDP", l2ctl.cdp_info
    elif pid == 0x2004:
        d, name, info = l2ctl.parse_dtp(body), "DTP", l2ctl.dtp_info
    elif pid == 0x010B:                  # PVST+: a normal BPDU followed by the VLAN TLV
        d, name, info = l2.parse_stp(body), "STP", l2.stp_info
        if d:
            d["pvst"] = True
            d["vlan"] = l2ctl.pvst_vlan(body) or p.vlan
    else:
        return False
    if not d:
        return False
    p.layers[name.lower()] = d
    p.protocol = name
    p.info = info(d)
    return True


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
        d = l2ctl.parse_lldp(buf)
        if d:
            p.layers["lldp"] = d
            p.info = l2ctl.lldp_info(d)
    elif etype == 0x888E:
        p.protocol = "EAPOL"
        d = auth.parse_eapol(buf)
        if d:
            p.layers["eapol"] = d
            p.info = auth.eapol_info(d)
    elif etype in l2ctl.ETHERTYPE_LABELS:
        p.protocol = l2ctl.ETHERTYPE_LABELS[etype]
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
        p.src = socket.inet_ntoa(buf[12:16])
        p.dst = socket.inet_ntoa(buf[16:20])
        cks = struct.unpack("!H", buf[10:12])[0]
        p.ip_checksum_ok = None if cks == 0 else _ones_sum(buf[:ihl]) == 0xFFFF
        p.protocol = "IPv4"
        end = min(len(buf), tot) if tot >= ihl else len(buf)
        payload = buf[ihl:end]
        wire_l4 = tot - ihl if tot > ihl else None   # tot == 0 with TSO/GSO: fall back to captured length
        if p.ip_frag_offset or p.ip_mf:
            p.tags.append("ip_fragment")
            p.frag = ((4, p.src, p.dst, ident, proto), p.ip_frag_offset, p.ip_mf, payload, proto)
            p.info = f"Fragmented IP protocol (proto={proto}, off={p.ip_frag_offset}, ID={ident:04x})"
            return                                   # decoded when the datagram is reassembled
    elif ver == 6:
        plen, nh, hlim = struct.unpack("!HBB", buf[4:8])
        p.ip_version, p.ttl, p.ip_hdr_len = 6, hlim, 40
        p.src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
        p.dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
        p.ip_len = plen + 40
        p.protocol = "IPv6"
        off = 40
        frag = None
        while nh in (0, 43, 44, 60, 51):
            if nh == 44:
                nh2 = buf[off]
                offm, ident = struct.unpack("!HI", buf[off + 2:off + 8])
                frag = (offm & 0xFFF8, bool(offm & 1), ident)
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
        if frag is not None:
            p.ip_frag_offset, p.ip_mf = frag[0], frag[1]
            p.frag = ((6, p.src, p.dst, frag[2], proto), frag[0], frag[1], payload, proto)
            p.info = f"IPv6 fragment (proto={proto}, off={frag[0]}, ID={frag[2]:08x})"
            return
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
    elif proto == 112:
        d = fhrp.parse_vrrp(buf, v6=p.ip_version == 6)
        if d:
            p.layers["fhrp"] = d
            p.protocol = "VRRP"
            p.info = fhrp.info(d)
    elif proto == 88:
        d = eigrp.parse(buf)
        if d:
            p.layers["eigrp"] = d
            p.protocol = "EIGRP"
            p.info = eigrp.info(d)
    elif proto == 103 and (d := mcast.parse_pim(buf)):
        _set(p, "pim", d, mcast.pim_info(d))
    elif proto == 2 and (d := mcast.parse_igmp(buf)):
        _set(p, "igmp", d, mcast.igmp_info(d))
    elif proto == 47 and (r := tunnel.parse_gre(buf)) and r[0]["proto"] in (0x0800, 0x86DD):
        g, off = r
        _decap(p, "gre", g)
        _ip(p, buf[off:])
        if p.protocol in ("IPv4", "IPv6"):
            p.protocol = "GRE"
        p.info = f"GRE {g['outer_src']} → {g['outer_dst']} | {p.info or p.protocol}"
    else:
        p.protocol = IP_PROTOS.get(proto, f"IP-{proto}")
        p.info = p.protocol


def _decap(p: Packet, name: str, d: dict) -> None:
    """Record the outer (tunnel) header, then clear the fields the inner packet will fill."""
    d.update(outer_src=p.src, outer_dst=p.dst, outer_ttl=p.ttl, outer_len=p.ip_len, outer_df=p.ip_df,
             outer_dscp=p.dscp, outer_sport=p.sport, outer_dport=p.dport,
             outer_eth_src=p.eth_src, outer_eth_dst=p.eth_dst)   # VXLAN replaces the MACs with the inner frame's
    p.layers[name] = d
    p.tags.append("tunneled")
    p.src = p.dst = p.ttl = p.ip_proto = p.ip_len = p.ip_id = p.ip_version = p.sport = p.dport = None
    p.ip_df = p.ip_mf = False
    p.ip_frag_offset = p.dscp = 0
    p.payload = b""


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
    if p.dport == tunnel.VXLAN_PORT and (d := tunnel.parse_vxlan(payload)):
        _decap(p, "vxlan", d)
        _ethernet(p, payload[8:])
        p.info = f"VXLAN VNI {d['vni']} {d['outer_src']} → {d['outer_dst']} | {p.info or p.protocol}"
        if p.protocol in ("ETH", "IPv4", "IPv6"):
            p.protocol = "VXLAN"
        return
    if ports[0] in auth.RADIUS_PORTS or ports[1] in auth.RADIUS_PORTS:
        d = auth.parse_radius(payload)
        if d:
            return _set(p, "radius", d, auth.radius_info(d))
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
    if 1985 in ports or 2029 in ports:
        d = fhrp.parse_hsrp(payload)
        if d:
            _set(p, "fhrp", d, fhrp.info(d))
            p.protocol = "HSRP"
            return
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


def decode_reassembled(p: Packet, proto: int, data: bytes) -> None:
    """Decode the transport/application layers of a reassembled IP datagram onto its last fragment."""
    p.protocol = "IPv4" if p.ip_version == 4 else "IPv6"
    p.tags.append("ip_reassembled")
    try:
        _l4(p, proto, data, len(data))
    except (struct.error, IndexError, ValueError):
        p.tags.append("malformed")
    if p.protocol in ("IPv4", "IPv6"):
        p.info = f"Reassembled IP datagram (proto={proto}, {len(data)} bytes)"
