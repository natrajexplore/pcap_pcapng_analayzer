"""Layer-2 control protocols: Cisco ISL trunk encapsulation, CDP, DTP, PVST+ and LLDP."""
from __future__ import annotations

import ipaddress
import struct

from .l2 import mac

CISCO_OUI = b"\x00\x00\x0c"
ISL_DA = bytes.fromhex("01000c0000")
DTP_TAS = {1: "on", 2: "off", 3: "desirable", 4: "auto"}          # trunk administrative status
DTP_TRUNK_TYPE = {2: "ISL", 5: "802.1Q"}                          # trunk operational type (top 3 bits)
CDP_CAPS = [(0x01, "Router"), (0x02, "Trans-Bridge"), (0x04, "Source-Route-Bridge"), (0x08, "Switch"),
            (0x10, "Host"), (0x20, "IGMP"), (0x40, "Repeater"), (0x80, "Phone")]
LLDP_CAPS = [(0x04, "Bridge"), (0x10, "Router"), (0x20, "Phone"), (0x80, "Station")]
ETHERTYPE_LABELS = {0x9000: "LOOP", 0x6002: "DEC-MOP-RC", 0x8035: "RARP"}


def parse_isl(buf: bytes) -> tuple[int, bytes] | None:
    """ISL frame -> (VLAN, encapsulated Ethernet frame without the trailing ISL CRC)."""
    if len(buf) < 26 + 14 or buf[:5] != ISL_DA or buf[14:17] != b"\xaa\xaa\x03" or buf[17:20] != CISCO_OUI:
        return None
    vlan = struct.unpack("!H", buf[20:22])[0] >> 1
    end = min(len(buf), 14 + struct.unpack("!H", buf[12:14])[0]) - 4
    return vlan, buf[26:end]


def _caps(v: int, table) -> list[str]:
    return [n for b, n in table if v & b]


def parse_cdp(buf: bytes) -> dict | None:
    if len(buf) < 4 or buf[0] not in (1, 2):
        return None
    d: dict = {"version": buf[0], "ttl": buf[1], "addresses": []}
    off = 4
    while off + 4 <= len(buf):
        t, ln = struct.unpack("!HH", buf[off:off + 4])
        if ln < 4:
            break
        v = buf[off + 4:off + ln]
        if t == 0x0001:
            d["device_id"] = v.decode("latin-1", "replace")
        elif t == 0x0003:
            d["port_id"] = v.decode("latin-1", "replace")
        elif t == 0x0004 and len(v) == 4:
            d["capabilities"] = _caps(struct.unpack("!I", v)[0], CDP_CAPS)
        elif t == 0x0005:
            d["software"] = v.decode("latin-1", "replace").split("\n")[0][:160]
        elif t == 0x0006:
            d["platform"] = v.decode("latin-1", "replace")
        elif t == 0x000A and len(v) == 2:
            d["native_vlan"] = struct.unpack("!H", v)[0]
        elif t == 0x000B and len(v) == 1:
            d["duplex"] = "full" if v[0] else "half"
        elif t in (0x0002, 0x0016) and len(v) >= 4:
            d["addresses"] += _cdp_addrs(v)
        off += ln
    return d


def _cdp_addrs(v: bytes) -> list[str]:
    out, off = [], 4
    for _ in range(struct.unpack("!I", v[:4])[0]):
        if off + 2 > len(v):
            break
        plen = v[off + 1]
        proto = v[off + 2:off + 2 + plen]
        off += 2 + plen
        alen = struct.unpack("!H", v[off:off + 2])[0]
        a = v[off + 2:off + 2 + alen]
        off += 2 + alen
        if proto == b"\xcc" and alen == 4:
            out.append(str(ipaddress.IPv4Address(a)))
        elif alen == 16:
            out.append(str(ipaddress.IPv6Address(a)))
    return out


def cdp_info(d: dict) -> str:
    s = f"CDP Device ID: {d.get('device_id', '?')}  Port ID: {d.get('port_id', '?')}"
    if "native_vlan" in d:
        s += f"  Native VLAN: {d['native_vlan']}"
    return s


def parse_dtp(buf: bytes) -> dict | None:
    if len(buf) < 1 or buf[0] != 1:
        return None
    d: dict = {}
    off = 1
    while off + 4 <= len(buf):
        t, ln = struct.unpack("!HH", buf[off:off + 4])
        if ln < 4:
            break
        v = buf[off + 4:off + ln]
        if t == 1:
            d["domain"] = v.rstrip(b"\x00").decode("latin-1", "replace")
        elif t == 2 and v:
            d["operational"] = "trunk" if v[0] & 0x80 else "access"
            d["admin"] = DTP_TAS.get(v[0] & 0x07, f"0x{v[0] & 0x07:x}")
        elif t == 3 and v:
            d["encapsulation"] = DTP_TRUNK_TYPE.get(v[0] >> 5, f"negotiating (0x{v[0]:02x})")
        elif t == 4 and len(v) >= 6:
            d["neighbor"] = mac(v[:6])
        off += ln
    return d


def dtp_info(d: dict) -> str:
    return f"DTP mode {d.get('admin', '?')}, port is {d.get('operational', '?')}, encapsulation {d.get('encapsulation', '?')}"


def pvst_vlan(bpdu: bytes) -> int | None:
    """PVST+ appends a PVID TLV (type 0, length 2) after the BPDU."""
    if len(bpdu) >= 6 and bpdu[-6:-2] == b"\x00\x00\x00\x02":
        return struct.unpack("!H", bpdu[-2:])[0]
    return None


def parse_lldp(buf: bytes) -> dict | None:
    d: dict = {}
    off = 0
    while off + 2 <= len(buf):
        hdr = struct.unpack("!H", buf[off:off + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = buf[off + 2:off + 2 + ln]
        if t == 0:
            break
        if t == 1 and v:
            d["chassis_id"] = mac(v[1:7]) if v[0] == 4 and len(v) == 7 else v[1:].decode("latin-1", "replace")
        elif t == 2 and v:
            d["port_id"] = mac(v[1:7]) if v[0] == 3 and len(v) == 7 else v[1:].decode("latin-1", "replace")
        elif t == 3 and len(v) == 2:
            d["ttl"] = struct.unpack("!H", v)[0]
        elif t == 5:
            d["system_name"] = v.decode("latin-1", "replace")
        elif t == 6:
            d["system_description"] = v.decode("latin-1", "replace")[:160]
        elif t == 7 and len(v) == 4:
            d["capabilities"] = _caps(struct.unpack("!H", v[2:4])[0], LLDP_CAPS)
        off += 2 + ln
    return d or None


def lldp_info(d: dict) -> str:
    return f"LLDP {d.get('system_name') or d.get('chassis_id', '?')} port {d.get('port_id', '?')}"
