"""Packet simulator with fault injection.

A small discrete-event model of a routed path::

    client ── [switch] ── R1 ── R2 … Rn ── server

Every packet is walked hop by hop: routers decrement TTL and rewrite MAC addresses, a
switch forwards transparently, and injected faults act on the device or link where they
are placed (loss, extra latency, silent firewall drop, firewall reject, missing route,
MTU black hole / ICMP fragmentation-needed, routing loop …). Endpoint behaviour models
TCP (handshake with SYN retries, windowed transfer, delayed and duplicate ACKs, fast
retransmit, RTO back-off, zero-window probing, black-hole MSS fallback), ICMP echo,
traceroute, DNS, DHCP and TLS.

The result is what a capture on the chosen link would contain (a real pcapng the
analyzer can diagnose) plus the *true journey* of every packet across every hop, so a
UI can show both what happened and what the capture point could see.
"""
from __future__ import annotations

import heapq
import random
import struct

from . import synth
from .reader import write_pcapng

T0 = 1_700_000_000.0
MSS = 1460
MAX_JOURNEY = 4000

TRAFFIC = {
    "http": "HTTP download over TCP",
    "tls": "HTTPS (TLS handshake + encrypted download)",
    "ping": "ICMP echo (ping)",
    "traceroute": "UDP traceroute",
    "dns": "DNS lookup",
    "dhcp": "DHCP address request",
}
# fault id -> (label, where it can be placed: "router" | "link" | "server" | "client" | None, applicable traffic)
FAULTS = {
    "none": ("No fault (healthy)", None, set(TRAFFIC)),
    "loss": ("Packet loss", "router", {"http", "tls", "ping", "dns"}),
    "latency": ("Extra latency", "router", {"http", "tls", "ping", "dns", "traceroute"}),
    "firewall_drop": ("Firewall silently drops", "router", {"http", "tls", "ping", "dns"}),
    "firewall_reject": ("Firewall rejects (RST / ICMP prohibited)", "router", {"http", "tls", "ping", "dns"}),
    "no_route": ("Missing route (ICMP unreachable)", "router", {"http", "tls", "ping", "dns", "traceroute"}),
    "mtu_blackhole": ("MTU black hole (ICMP filtered)", "link", {"http", "tls"}),
    "mtu_icmp": ("Smaller MTU with ICMP frag-needed", "link", {"http", "tls"}),
    "routing_loop": ("Routing loop", "router", {"http", "tls", "ping", "traceroute", "dns"}),
    "port_closed": ("Service not listening (RST)", "server", {"http", "tls"}),
    "slow_server": ("Slow server (think time)", "server", {"http", "tls"}),
    "zero_window": ("Receiver stops reading (zero window)", "client", {"http", "tls"}),
    "dns_servfail": ("Resolver SERVFAIL", "server", {"dns"}),
    "dns_timeout": ("Resolver not answering", "server", {"dns"}),
    "dhcp_no_offer": ("DHCP server not answering", "router", {"dhcp"}),
    "dhcp_rogue": ("Rogue DHCP server", "client", {"dhcp"}),
    "tls_alert": ("TLS handshake failure alert", "server", {"tls"}),
}
# what the analyzer should report for each fault (per traffic where it differs)
# detection counts when ANY of the listed findings appears (the same fault shows differently depending on what was hit)
EXPECTED = {
    "loss": {"http": ["tcp_retransmissions"], "tls": ["tcp_retransmissions"], "dns": ["dns_no_response", "dns_slow"], "ping": []},
    "latency": {"http": ["tcp_high_irtt"], "tls": ["tcp_high_irtt"], "dns": ["dns_slow"], "*": []},
    "firewall_drop": {"http": ["tcp_syn_no_response"], "tls": ["tcp_syn_no_response"], "dns": ["dns_no_response"], "ping": []},
    "firewall_reject": {"http": ["tcp_conn_refused"], "tls": ["tcp_conn_refused"], "*": ["icmp_admin_prohibited"]},
    "no_route": {"*": ["icmp_unreachable"]},
    "mtu_blackhole": {"*": ["tcp_retransmissions"]},
    # the ICMP goes to the server: a client-side capture only sees the resulting gap and retransmission
    "mtu_icmp": {"*": ["icmp_frag_needed", "tcp_retransmissions", "tcp_lost_segment"]},
    "routing_loop": {"*": ["icmp_ttl_exceeded"]},
    "port_closed": {"*": ["tcp_conn_refused"]},
    "slow_server": {"*": ["tcp_slow_response"]},
    "zero_window": {"*": ["tcp_zero_window"]},
    "dns_servfail": {"*": ["dns_servfail"]},
    "dns_timeout": {"*": ["dns_no_response"]},
    "dhcp_no_offer": {"*": ["dhcp_no_offer"]},
    "dhcp_rogue": {"*": ["dhcp_multiple_servers"]},
    "tls_alert": {"*": ["tls_alert"]},
}


def expected_findings(fault: str, traffic: str) -> list[str]:
    e = EXPECTED.get(fault, {})
    return e.get(traffic, e.get("*", []))


# ------------------------------------------------------------------ frames --
def _eth(src, dst, etype, payload):
    return synth._mac(dst) + synth._mac(src) + struct.pack("!H", etype) + payload


def _ip4(src, dst, proto, payload, ttl, ident, df=True, dscp=0):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(payload), ident & 0xFFFF, 0x4000 if df else 0, ttl,
                    proto, 0, synth._ip(src), synth._ip(dst))
    return h[:10] + struct.pack("!H", synth._cks(h)) + h[12:] + payload


def _tcp(sport, dport, seq, ack, flags, win, payload=b"", opts=b""):
    opts += b"\x00" * ((4 - len(opts) % 4) % 4)
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, ((20 + len(opts)) // 4) << 4,
                       flags, win, 0, 0) + opts + payload


def _udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _icmp(typ, code, rest=b"\x00" * 4, body=b""):
    m = struct.pack("!BBH", typ, code, 0) + rest + body
    return m[:2] + struct.pack("!H", synth._cks(m)) + m[4:]


class Pkt:
    """A packet in flight: IP header fields + transport bytes (built lazily per TTL)."""
    __slots__ = ("src", "dst", "proto", "l4", "ttl", "ident", "df", "label", "kind", "size", "id")

    def __init__(self, src, dst, proto, l4, ttl, ident, label, kind, df=True):
        self.src, self.dst, self.proto, self.l4, self.ttl, self.ident = src, dst, proto, l4, ttl, ident
        self.df, self.label, self.kind = df, label, kind
        self.size = 20 + len(l4)
        self.id = 0


# ---------------------------------------------------------------- network --
class Net:
    def __init__(self, routers=3, switch=True, capture=1, link_ms=4.0, seed=7):
        self.rng = random.Random(seed)
        self.link_s = link_ms / 1000
        self.nodes = []
        self.nodes.append({"id": "client", "name": "Client", "kind": "host", "ip": "192.168.10.50",
                           "mac": "02:00:00:00:00:10", "ttl": 128})
        if switch:
            self.nodes.append({"id": "sw1", "name": "SW1", "kind": "switch", "mac": "02:00:00:0a:00:01"})
        for i in range(routers):
            left = "192.168.10.1" if i == 0 else f"10.0.{i}.2"
            right = "172.16.20.1" if i == routers - 1 else f"10.0.{i + 1}.1"
            self.nodes.append({"id": f"r{i + 1}", "name": f"R{i + 1}", "kind": "router", "ip_left": left, "ip_right": right,
                               "ip": left, "mac_left": f"02:00:00:01:{i + 1:02x}:01", "mac_right": f"02:00:00:01:{i + 1:02x}:02",
                               "ttl": 255})
        self.nodes.append({"id": "server", "name": "Server", "kind": "server", "ip": "172.16.20.10",
                           "mac": "02:00:00:00:00:20", "ttl": 64})
        self.capture = max(0, min(capture, len(self.nodes) - 2))
        self.frames: list[tuple[float, bytes]] = []
        self.journey: list[dict] = []
        self.faults: dict = {}
        self.link_free: dict = {}             # (from, to) -> time the last packet left that link direction
        self.loss_hits = 0                    # packets the random-loss fault actually dropped
        self.ident ={n["id"]: 1000 * (i + 1) for i, n in enumerate(self.nodes)}
        self.pid = 0

    # ---- addressing
    def idx(self, nid):
        return next(i for i, n in enumerate(self.nodes) if n["id"] == nid)

    def ip_of(self, i, toward_client=True):
        n = self.nodes[i]
        if n["kind"] == "router":
            return n["ip_left"] if toward_client else n["ip_right"]
        return n.get("ip")

    def mac_of(self, i, side):
        """MAC of node i's interface facing ``side`` (-1 = toward client, +1 = toward server)."""
        n = self.nodes[i]
        if n["kind"] == "router":
            return n["mac_left"] if side < 0 else n["mac_right"]
        return n["mac"]

    def next_ident(self, nid):
        self.ident[nid] += 1
        return self.ident[nid]

    # ---- the core: walk a packet hop by hop
    def deliver(self, t: float, p: Pkt, a: int, b: int, *, visit_ttl=True) -> tuple[float | None, list]:
        """Send ``p`` from node a to node b. Returns (arrival time or None, [(t, response Pkt, from idx, to idx)])."""
        self.pid += 1
        p.id = self.pid
        step = 1 if b > a else -1
        i, last_l3, reply = a, a, []
        dst = self.index_of_ip(p.dst)
        while i != b:
            j = i + step
            f_link = self.faults.get(("link", min(i, j)))
            size = p.size
            # link MTU faults act before the packet enters the link
            if f_link and f_link["kind"] in ("mtu_blackhole", "mtu_icmp") and size > f_link["mtu"] and p.df:
                self._event(t, p, i, j, "drop", f"{size} B > MTU {f_link['mtu']} on link {self.nodes[i]['name']}→{self.nodes[j]['name']}")
                if f_link["kind"] == "mtu_icmp" and self.nodes[i]["kind"] == "router":
                    reply.append((t + 0.0002, self._icmp_error(i, p, 3, 4, struct.pack("!HH", 0, f_link["mtu"]), step), i, a))
                return None, reply
            # links are FIFO: jitter never lets a packet overtake the previous one; 1 Gbps serialization
            t = max(t + self.link_s + self.rng.uniform(0, self.link_s * 0.05),
                    self.link_free.get((i, j), 0.0) + size * 8 / 1e9)
            self.link_free[(i, j)] = t
            self._on_link(t, p, i, j, last_l3, step)
            self._event(t, p, i, j, "ok", p.label)
            n = self.nodes[j]
            f = self.faults.get(("node", j))
            if j == b:
                return t, reply
            if n["kind"] != "router":
                i = j
                continue
            # ---- router ingress: faults, then TTL / forwarding
            if f:
                k = f["kind"]
                if k == "latency":
                    t += f["ms"] / 1000
                elif k == "loss" and self.rng.random() < f["rate"]:
                    self.loss_hits += 1
                    self._event(t, p, j, j, "drop", f"lost at {n['name']}")
                    return None, reply
                elif k in ("firewall_drop", "firewall_reject") and self._matches(f, p):
                    if k == "firewall_drop":
                        self._event(t, p, j, j, "drop", f"dropped by firewall on {n['name']}")
                        return None, reply
                    self._event(t, p, j, j, "reject", f"rejected by firewall on {n['name']}")
                    reply.append((t + 0.0003, self._reject(j, p, -step), j, a))
                    return None, reply
                elif k == "no_route" and dst is not None and dst > j:
                    self._event(t, p, j, j, "reject", f"{n['name']}: no route to {p.dst}")
                    reply.append((t + 0.0003, self._icmp_error(j, p, 3, 0, b"\x00" * 4, step), j, a))
                    return None, reply
            p.ttl -= 1
            if p.ttl <= 0:
                self._event(t, p, j, j, "drop", f"TTL expired at {n['name']}")
                reply.append((t + 0.0002, self._icmp_error(j, p, 11, 0, b"\x00" * 4, step), j, a))
                return None, reply
            t += 0.0001
            last_l3 = j
            # routing: forward toward the destination; a looping router sends server-bound traffic back
            if dst is not None:
                step = 1 if dst > j else -1
                if f and f["kind"] == "routing_loop" and dst > j:
                    step = -1
            i = j
        return t, reply

    def index_of_ip(self, ip):
        return next((k for k, n in enumerate(self.nodes)
                     if ip in (n.get("ip"), n.get("ip_left"), n.get("ip_right"))), None)

    def _matches(self, f, p):
        return f.get("proto") in (None, p.proto)

    def _on_link(self, t, p, i, j, last_l3, step):
        """Write the frame if this link is the capture link."""
        if min(i, j) != self.capture:
            return
        # MACs belong to layer-3 devices: the switch forwards the frame unchanged
        k = j
        while self.nodes[k]["kind"] == "switch":
            k += step
        src_mac = self.mac_of(last_l3, step)
        dst_mac = self.mac_of(k, -step)
        if p.dst == "255.255.255.255":
            dst_mac = synth.BCAST
        frame = _eth(src_mac, dst_mac, 0x0800, _ip4(p.src, p.dst, p.proto, p.l4, p.ttl, p.ident, p.df))
        self.frames.append((T0 + t, frame))

    def _event(self, t, p, i, j, status, label):
        if len(self.journey) < MAX_JOURNEY:
            self.journey.append({"t": round(t, 6), "pkt": p.id, "from": self.nodes[i]["id"], "to": self.nodes[j]["id"],
                                 "status": status, "label": label[:90], "kind": p.kind, "size": p.size,
                                 "captured": min(i, j) == self.capture and i != j})

    def _icmp_error(self, j, p, typ, code, rest, step):
        orig = _ip4(p.src, p.dst, p.proto, p.l4, p.ttl, p.ident, p.df)[:28]
        src = self.ip_of(j, toward_client=step > 0)
        q = Pkt(src, p.src, 1, _icmp(typ, code, rest, orig), 255, self.next_ident(self.nodes[j]["id"]),
                f"ICMP {'time exceeded' if typ == 11 else 'unreachable'} from {self.nodes[j]['name']}", "icmp-error", df=False)
        return q

    def _reject(self, j, p, back):
        if p.proto == 6:
            sport, dport, seq, ack, _o, flags = struct.unpack("!HHIIBB", p.l4[:14])
            l4 = _tcp(dport, sport, ack if flags & 0x10 else 0, seq + 1, 0x14, 0)
            # the firewall spoofs the destination's address but its own TTL gives it away
            return Pkt(p.dst, p.src, 6, l4, 255, self.next_ident(self.nodes[j]["id"]), f"RST from firewall on {self.nodes[j]['name']}",
                       "rst")
        return self._icmp_error(j, p, 3, 13, b"\x00" * 4, -back)

    # ---- CDP so the analyzer can name the devices on the capture link
    def cdp(self, t):
        for i in (self.capture, self.capture + 1):
            n = self.nodes[i]
            if n["kind"] not in ("router", "switch"):
                continue
            side = 1 if i == self.capture else -1
            caps = 0x01 if n["kind"] == "router" else 0x08
            body = b"\x02\xb4\x00\x00" + _tlv(1, n["name"].encode()) + _tlv(3, f"Gi0/{0 if side < 0 else 1}".encode()) \
                + _tlv(4, struct.pack("!I", caps)) + _tlv(6, b"PacketLens simulator")
            if n["kind"] == "router":
                ip = self.ip_of(i, toward_client=side < 0)
                body += _tlv(2, struct.pack("!I", 1) + b"\x01\x01\xcc" + struct.pack("!H", 4) + synth._ip(ip))
            llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00" + body
            mac = self.mac_of(i, side)
            self.frames.append((T0 + t, synth._mac("01:00:0c:cc:cc:cc") + synth._mac(mac) + struct.pack("!H", len(llc)) + llc))


def _tlv(t, v):
    return struct.pack("!HH", t, len(v) + 4) + v


# ------------------------------------------------------------- endpoints --
class Sim:
    def __init__(self, net: Net):
        self.net = net
        self.q: list = []
        self.seq = 0
        self.notes: list[str] = []

    def at(self, t, fn, *args):
        self.seq += 1
        heapq.heappush(self.q, (t, self.seq, fn, args))

    def run(self, until=120.0):
        while self.q:
            t, _, fn, args = heapq.heappop(self.q)
            if t > until:
                break
            fn(t, *args)

    def send(self, t, p: Pkt, a: int, b: int, on_arrive=None):
        arr, replies = self.net.deliver(t, p, a, b)
        for rt, rp, ri, rto in replies:
            self.at(rt, self._send_reply, rp, ri, rto)
        if arr is not None and on_arrive:
            self.at(arr, on_arrive, p)
        return arr

    def _send_reply(self, t, p, a, b):
        arr, replies = self.net.deliver(t, p, a, b)
        if arr is not None and getattr(self, "on_error", None):
            self.at(arr, self.on_error, p)


class TCPFlow:
    """Client (index a) downloads ``data`` from the server (index b)."""

    def __init__(self, sim: Sim, request: bytes, data: bytes, sport=51000, dport=80, zero_window=None, think=0.02,
                 hello=None):
        self.s, self.net = sim, sim.net
        self.a, self.b = 0, len(self.net.nodes) - 1
        self.cip, self.sip = self.net.nodes[self.a]["ip"], self.net.nodes[self.b]["ip"]
        self.sport, self.dport = sport, dport
        self.req, self.data, self.think = request, data, think
        self.hello = hello                                  # (client hello, server hello or alert) for TLS
        self.cisn, self.sisn = 1_000_000, 5_000_000
        self.mss = MSS
        self.cwnd, self.una, self.nxt, self.dup, self.rto = 10, 0, 0, 0, 0.3
        self.rto_gen, self.rto_count, self.last_ack = 0, 0, -1
        self.rcv_nxt, self.ooo, self.unacked = 0, {}, 0
        self.rbuf = 16384 if zero_window else 65535      # receive buffer (small when the app will stall)
        self.rwnd, self.buf, self.zero = self.rbuf, 0, zero_window
        self.syn_tries, self.state = 0, "syn"
        self.done_at = None
        sim.on_error = self.on_icmp

    # ---- helpers
    def pkt(self, from_client, seq, ack, flags, payload=b"", opts=b"", label="", kind="tcp", win=None):
        src, dst = (self.cip, self.sip) if from_client else (self.sip, self.cip)
        sp, dp = (self.sport, self.dport) if from_client else (self.dport, self.sport)
        w = min(65535, self.rwnd if win is None else win) if from_client else 65535
        n = self.net.nodes[self.a if from_client else self.b]
        return Pkt(src, dst, 6, _tcp(sp, dp, seq, ack, flags, w, payload, opts), n["ttl"], self.net.next_ident(n["id"]),
                   label, kind)

    def c2s(self, t, p, cb=None):
        return self.s.send(t, p, self.a, self.b, cb)

    def s2c(self, t, p, cb=None):
        return self.s.send(t, p, self.b, self.a, cb)

    # ---- handshake
    def start(self, t):
        self.syn_tries += 1
        opts = synth.tcp_opts(self.mss, 7, True)
        self.c2s(t, self.pkt(True, self.cisn, 0, 0x02, opts=opts, label=f"SYN (try {self.syn_tries})", kind="syn"), self.srv_syn)
        if self.syn_tries < 4:
            self.s.at(t + 2 ** (self.syn_tries - 1), self._syn_timeout, self.syn_tries)

    def _syn_timeout(self, t, tries):
        if self.state == "syn" and self.syn_tries == tries:
            self.start(t)
        elif self.state == "syn":
            self.s.notes.append("Connection attempt timed out")

    def srv_syn(self, t, p):
        if self.net.faults.get(("server",)) == "port_closed":
            self.s2c(t + 0.0002, self.pkt(False, 0, self.cisn + 1, 0x14, label="RST (port closed)", kind="rst"), self.cli_rst)
            return
        opts = synth.tcp_opts(MSS, 7, True)
        self.s2c(t + 0.0003, self.pkt(False, self.sisn, self.cisn + 1, 0x12, opts=opts, label="SYN-ACK", kind="syn"), self.cli_synack)

    def cli_rst(self, t, p):
        self.state = "reset"
        self.s.notes.append("Connection reset")

    def cli_synack(self, t, p):
        if self.state != "syn":
            return
        self.state = "est"
        self.c2s(t + 0.0001, self.pkt(True, self.cisn + 1, self.sisn + 1, 0x10, label="ACK", kind="ack-only"))
        if self.hello:
            self.cseq = self.cisn + 1 + len(self.hello[0])
            self.send_hello(t + 0.001, 1)
        else:
            self.send_request(t + 0.001)

    def send_hello(self, t, tries):
        if getattr(self, "hello_done", False) or tries > 6:
            return
        self.c2s(t, self.pkt(True, self.cisn + 1, self.sisn + 1, 0x18, self.hello[0],
                             label="TLS ClientHello" + (" (retransmission)" if tries > 1 else ""),
                             kind="data" if tries == 1 else "retrans"), self.srv_hello)
        self.s.at(t + 0.3 * 2 ** (tries - 1), lambda tt, n=tries + 1: self.send_hello(tt, n))

    def srv_hello(self, t, p):
        sh = self.hello[1]
        alert = sh[0] == 21
        first = not getattr(self, "sh_sent", False)
        self.sh_sent = True
        base = self.sisn if first else self.sisn - len(sh)     # a repeat ServerHello reuses its sequence number
        self.s2c(t + 0.004, self.pkt(False, base + 1, self.cseq, 0x18, sh, label="TLS alert" if alert else "TLS ServerHello"),
                 self.cli_alert if alert else self.cli_sh)
        if first:
            self.sisn += len(sh)

    def cli_sh(self, t, p):
        if not getattr(self, "hello_done", False):
            self.hello_done = True
            self.send_request(t + 0.02, self.cseq)

    def cli_alert(self, t, p):
        self.hello_done = True
        self.c2s(t + 0.001, self.pkt(True, self.cseq, self.sisn + 1, 0x14, label="RST after alert", kind="rst"))
        self.state = "closed"

    # ---- request / response
    def send_request(self, t, seq=None, tries=1):
        seq = seq if seq is not None else self.cisn + 1
        self.req_seq = seq
        self.cseq = seq + len(self.req)
        self.c2s(t, self.pkt(True, seq, self.sisn + 1, 0x18, self.req, label="Request" if tries == 1 else "Request retransmission",
                             kind="data" if tries == 1 else "retrans"), self.srv_request)
        if tries < 6:                                           # client RTO: resend until the server acknowledges
            self.s.at(t + 0.3 * 2 ** (tries - 1), self._request_timeout, tries)

    def _request_timeout(self, t, tries):
        if not getattr(self, "req_acked", False) and self.state == "est":
            self.send_request(t, self.req_seq, tries + 1)

    def srv_request(self, t, p):
        self.s2c(t + 0.0002, self.pkt(False, self.sisn + 1, self.cseq, 0x10, label="ACK", kind="ack-only"), self._req_acked)
        if not getattr(self, "served", False):              # a retransmitted request is only acknowledged again
            self.served = True
            self.s.at(t + self.think, self.pump)

    def _req_acked(self, t, p):
        self.req_acked = True

    def seg_len(self, off):
        return min(self.mss, len(self.data) - off)

    def pump(self, t):
        """Server sends as much as the congestion and receive windows allow."""
        limit = min(self.cwnd * self.mss, self.rwnd)
        sent = False
        while self.nxt < len(self.data) and self.nxt - self.una < limit:
            n = self.seg_len(self.nxt)
            if self.nxt - self.una + n > limit:
                break
            self.tx(t, self.nxt, n, retrans=False)
            self.nxt += n
            t += 0.00005
            sent = True
        if self.rwnd == 0 and self.una == self.nxt < len(self.data):
            self.persist(t)
        elif sent or self.una < self.nxt:
            self.arm(t)

    def persist(self, t):
        """Start the single persist timer that probes a zero window (one chain, not one per ACK)."""
        if not getattr(self, "probing", False):
            self.probing = True
            self.s.at(t + 0.2, self.probe, 0)

    def tx(self, t, off, n, retrans):
        p = self.pkt(False, self.sisn + 1 + off, self.cseq, 0x18 if off + n >= len(self.data) else 0x10,
                     self.data[off:off + n], label=("Retransmission " if retrans else "Data ") + f"seq {off}+{n}",
                     kind="retrans" if retrans else "data")
        self.s2c(t, p, lambda tt, pp, o=off, l=n: self.cli_data(tt, o, l))

    def arm(self, t):
        self.rto_gen += 1
        self.s.at(t + self.rto, self.timeout, self.rto_gen)

    def timeout(self, t, gen):
        if gen != self.rto_gen or self.una >= len(self.data) or self.state != "est":
            return
        self.rto_count += 1
        if self.rto_count >= 3 and self.mss > 536:        # OS black-hole detection: shrink segments
            self.mss = 536
            self.s.notes.append("Sender fell back to 536-byte segments (black-hole detection)")
        self.cwnd = 1
        self.tx(t, self.una, self.seg_len(self.una), retrans=True)
        self.nxt = max(self.nxt, self.una + self.seg_len(self.una))
        self.rto = min(self.rto * 2, 8.0)
        self.arm(t)

    def probe(self, t, n):
        if self.rwnd > 0 or self.una >= len(self.data):
            self.probing = False
            return
        p = self.pkt(False, self.sisn + self.una, self.cseq, 0x10, label="Zero-window probe", kind="probe")
        self.s2c(t, p, self.cli_probe)
        self.s.at(t + min(0.2 * 2 ** (n + 1), 5), self.probe, n + 1)

    def cli_probe(self, t, p):
        self.send_ack(t, force=True)

    # ---- receiver (client)
    def cli_data(self, t, off, n):
        self.req_acked = True                                   # response data implies the request arrived
        if off == self.rcv_nxt:
            self.rcv_nxt += n
            while self.rcv_nxt in self.ooo:
                self.rcv_nxt += self.ooo.pop(self.rcv_nxt)
            self.buf += n
            self.unacked += 1
            if self.zero and self.zero["after"] <= self.rcv_nxt and not self.zero.get("fired"):
                self.zero["fired"] = True
                self.s.at(t + self.zero["pause"], self.app_read)
            if not self.zero or not self.zero.get("fired") or self.zero.get("resumed"):
                self.buf = 0                                    # the application reads immediately
            free = self.rbuf - self.buf
            self.rwnd = free if free >= self.mss else 0         # silly-window avoidance: < 1 segment free = 0
            if self.ooo or self.unacked >= 2 or self.rcv_nxt >= len(self.data) or self.rwnd < self.mss:
                self.send_ack(t)
            else:
                self.s.at(t + 0.04, self.delayed_ack, self.rcv_nxt)
        elif off > self.rcv_nxt:
            self.ooo[off] = n
            self.send_ack(t, force=True)                        # duplicate ACK
        else:
            self.send_ack(t, force=True)

    def delayed_ack(self, t, upto):
        if self.rcv_nxt == upto and self.unacked:
            self.send_ack(t)

    def app_read(self, t):
        self.zero["resumed"] = True
        self.buf = 0
        self.rwnd = self.rbuf
        self.send_ack(t, force=True, label="Window update")

    def send_ack(self, t, force=False, label="ACK"):
        self.unacked = 0
        win = self.rwnd >> 7                                   # window scale 7
        p = self.pkt(True, self.cseq, self.sisn + 1 + self.rcv_nxt, 0x10, label=f"{label} {self.rcv_nxt}" +
                     (" (window 0)" if self.rwnd == 0 else ""), kind="ack-only", win=win)
        self.c2s(t + 0.0001, p, lambda tt, pp, a=self.rcv_nxt, w=self.rwnd: self.srv_ack(tt, a, w))

    # ---- sender reacts to ACKs
    def srv_ack(self, t, ack, win):
        self.rwnd = win
        if ack > self.una:
            self.una, self.dup, self.rto_count = ack, 0, 0
            self.rto = 0.3
            self.cwnd += 1
            if self.una >= len(self.data):
                self.finish(t)
                return
            self.pump(t)
        elif ack == self.una and self.una < self.nxt:
            self.dup += 1
            if self.dup == 3:                                   # fast retransmit
                self.cwnd = max(2, self.cwnd // 2)
                self.tx(t, self.una, self.seg_len(self.una), retrans=True)
                self.arm(t)
        if win == 0:
            self.persist(t)
        elif self.una < len(self.data):
            self.pump(t)

    def finish(self, t):
        if self.state != "est":
            return
        self.state = "fin"
        end = self.sisn + 1 + len(self.data)
        self.s2c(t + 0.001, self.pkt(False, end, self.cseq, 0x11, label="FIN", kind="fin"),
                 lambda tt, p: self.c2s(tt + 0.001, self.pkt(True, self.cseq, end + 1, 0x11, label="FIN-ACK", kind="fin"),
                                        lambda t2, p2: self.s2c(t2 + 0.0005, self.pkt(False, end + 1, self.cseq + 1, 0x10,
                                                                                      label="ACK", kind="ack-only"))))
        self.done_at = t

    def on_icmp(self, t, p):
        """ICMP fragmentation-needed reaches the server: it lowers its segment size and resends at once."""
        if p.proto == 1 and p.l4[0] == 3 and p.l4[1] == 4:
            mtu = struct.unpack("!H", p.l4[6:8])[0]
            if mtu - 40 < self.mss:
                self.mss = mtu - 40
                self.s.notes.append(f"Path MTU discovery: server lowered segment size to {self.mss}")
                self.nxt = self.una
                self.pump(t)


# ---------------------------------------------------------------- traffic --
def _ping(sim: Sim, count=5):
    net = sim.net
    a, b = 0, len(net.nodes) - 1
    c = net.nodes[a]
    for i in range(count):
        t = 0.05 + i * 0.4
        l4 = _icmp(8, 0, struct.pack("!HH", 0x1234, i + 1), b"abcdefghijklmnopqrstuvwabcdefghi")
        p = Pkt(c["ip"], net.nodes[b]["ip"], 1, l4, c["ttl"], net.next_ident("client"), f"Echo request seq {i + 1}", "ping")

        def reply(tt, pp, seq=i + 1):
            s = net.nodes[b]
            r = Pkt(s["ip"], c["ip"], 1, _icmp(0, 0, struct.pack("!HH", 0x1234, seq), b"abcdefghijklmnopqrstuvwabcdefghi"),
                    s["ttl"], net.next_ident("server"), f"Echo reply seq {seq}", "ping")
            sim.send(tt + 0.0002, r, b, a)
        sim.at(t, lambda tt, pp=p, cb=reply: sim.send(tt, pp, a, b, cb))


def _traceroute(sim: Sim):
    net = sim.net
    a, b = 0, len(net.nodes) - 1
    routers = sum(1 for n in net.nodes if n["kind"] == "router")
    c = net.nodes[a]
    t = 0.05
    for ttl in range(1, routers + 2):
        for k in range(3):
            port = 33434 + (ttl - 1) * 3 + k
            p = Pkt(c["ip"], net.nodes[b]["ip"], 17, _udp(40000 + ttl, port, b"\x00" * 32), ttl, net.next_ident("client"),
                    f"Probe TTL {ttl}", "probe")

            def unreach(tt, pp):
                s = net.nodes[b]
                orig = _ip4(pp.src, pp.dst, pp.proto, pp.l4, pp.ttl, pp.ident)[:28]
                r = Pkt(s["ip"], c["ip"], 1, _icmp(3, 3, b"\x00" * 4, orig), s["ttl"], net.next_ident("server"),
                        "ICMP port unreachable (destination reached)", "icmp-error")
                sim.send(tt + 0.0002, r, b, a)
            sim.at(t, lambda tt, pp=p, cb=unreach: sim.send(tt, pp, a, b, cb))
            t += 0.05


def _dns(sim: Sim, fault):
    net = sim.net
    a, b = 0, len(net.nodes) - 1
    c, s = net.nodes[a], net.nodes[b]
    name = "app.example.com"
    answered = {}

    def query(t, tries):
        if answered.get("done") or tries > 3:
            return
        q = Pkt(c["ip"], s["ip"], 17, _udp(53000, 53, synth.dns_msg(0x4242, name)), c["ttl"], net.next_ident("client"),
                f"DNS query {name}" + (f" (retry {tries - 1})" if tries > 1 else ""), "dns")

        def resp(tt, pp):
            if fault == "dns_timeout":
                return
            rc = 2 if fault == "dns_servfail" else 0
            r = Pkt(s["ip"], c["ip"], 17, _udp(53, 53000, synth.dns_msg(0x4242, name, response=True, rcode=rc,
                                                                         answers=() if rc else ("172.16.20.80",))),
                    s["ttl"], net.next_ident("server"), "DNS SERVFAIL" if rc else "DNS answer 172.16.20.80", "dns")

            def got(t2, p2):
                answered["done"] = True
            sim.send(tt + 0.015, r, b, a, got)
        sim.send(t, q, a, b, resp)
        sim.at(t + 1.0 * tries, query, tries + 1)
    sim.at(0.05, query, 1)


def _dhcp(sim: Sim, fault):
    """DHCP happens on the client's LAN: R1 is the DHCP server (plus a rogue host when injected)."""
    net = sim.net
    gw = next(i for i, n in enumerate(net.nodes) if n["kind"] == "router")
    cmac = net.nodes[0]["mac"]
    xid = 0x5A5A0001

    def bc(t, src_i, dst_i, payload, sport, dport, label, src_ip="0.0.0.0", dst_ip="255.255.255.255", ttl=64):
        p = Pkt(src_ip, dst_ip, 17, _udp(sport, dport, payload), ttl, net.next_ident(net.nodes[src_i]["id"]), label, "dhcp", df=False)
        return p
    state = {"offered": False}

    def discover(t, n):
        if state["offered"] or n > 3:
            return
        sim.send(t, bc(t, 0, gw, synth.dhcp_msg(1, xid, cmac, 1), 68, 67, "DHCP DISCOVER"), 0, gw, offer)
        sim.at(t + 2 ** n, discover, n + 1)

    def offer(t, p):
        if fault == "dhcp_no_offer":
            return
        g = net.nodes[gw]
        o = bc(t, gw, 0, synth.dhcp_msg(2, xid, cmac, 2, "192.168.10.50", g["ip_left"], g["ip_left"], "8.8.8.8"), 67, 68,
               "DHCP OFFER", g["ip_left"], ttl=255)
        sim.send(t + 0.002, o, gw, 0, request)
        if fault == "dhcp_rogue":
            r = Pkt("192.168.10.66", "255.255.255.255", 17,
                    _udp(67, 68, synth.dhcp_msg(2, xid, cmac, 2, "192.168.10.150", "192.168.10.66", "192.168.10.66", "192.168.10.66")),
                    64, 1, "Rogue DHCP OFFER", "dhcp", df=False)
            on_lan = net.capture < gw                          # the rogue host sits on the client LAN
            if on_lan:
                net.frames.append((T0 + t + 0.001, _eth("02:00:00:00:00:66", synth.BCAST, 0x0800,
                                                        _ip4(r.src, r.dst, 17, r.l4, 64, 7, False))))
            net.journey.append({"t": round(t + 0.001, 6), "pkt": -1, "from": "rogue", "to": "client", "status": "reject",
                                "label": "Rogue DHCP OFFER (wrong gateway)", "kind": "dhcp", "size": r.size, "captured": on_lan})

    def request(t, p):
        if state["offered"]:
            return
        state["offered"] = True
        sim.send(t + 0.01, bc(t, 0, gw, synth.dhcp_msg(1, xid, cmac, 3, server=net.nodes[gw]["ip_left"]), 68, 67,
                              "DHCP REQUEST"), 0, gw, ack)

    def ack(t, p):
        g = net.nodes[gw]
        sim.send(t + 0.002, bc(t, gw, 0, synth.dhcp_msg(2, xid, cmac, 5, "192.168.10.50", g["ip_left"], g["ip_left"], "8.8.8.8"),
                               67, 68, "DHCP ACK", g["ip_left"], ttl=255), gw, 0)
    sim.at(0.05, discover, 1)


def simulate(traffic="http", fault="none", where=None, routers=3, switch=True, capture=1, link_ms=4.0, size_kb=64,
             loss_rate=0.2, latency_ms=250, mtu=1400, think_s=3.0, seed=7) -> dict:
    if traffic not in TRAFFIC:
        raise ValueError(f"unknown traffic {traffic!r}")
    if fault not in FAULTS:
        raise ValueError(f"unknown fault {fault!r}")
    routers = max(1, min(6, int(routers)))
    net = Net(routers, switch, int(capture), float(link_ms), seed)
    sim = Sim(net)
    kind = FAULTS[fault][1]
    router_idx = [i for i, n in enumerate(net.nodes) if n["kind"] == "router"]
    if kind == "router":
        w = where if where in [n["id"] for n in net.nodes if n["kind"] == "router"] else net.nodes[router_idx[len(router_idx) // 2]]["id"]
        f = {"kind": fault, "rate": float(loss_rate), "ms": float(latency_ms), "proto": None}
        if fault == "dhcp_no_offer":
            w = net.nodes[router_idx[0]]["id"]
        net.faults[("node", net.idx(w))] = f
        where = w
    elif kind == "link":
        li = int(where) if str(where).isdigit() and 0 <= int(where) < len(net.nodes) - 1 else router_idx[len(router_idx) // 2]
        net.faults[("link", li)] = {"kind": fault, "mtu": int(mtu)}
        where = li
    elif kind == "server":
        net.faults[("server",)] = fault
        where = "server"
    elif kind == "client":
        where = "client"
    net.cdp(0.0)
    body = bytes((i * 7 + 13) & 0x7F | 0x20 for i in range(int(size_kb * 1024)))
    if traffic in ("http", "tls"):
        zero = {"after": 4096, "pause": 2.5} if fault == "zero_window" else None   # app stalls after 4 KB
        think = float(think_s) if fault == "slow_server" else 0.02
        if traffic == "http":
            flow = TCPFlow(sim, synth.http_req("GET", "app.example.com", "/reports/q3.pdf"),
                           synth.http_resp(200, "OK", body, "application/octet-stream"), zero_window=zero, think=think)
        else:
            sh = synth.tls_alert(40) if fault == "tls_alert" else synth.server_hello(0x0303, 0xC02F)
            records = b"".join(struct.pack("!BHH", 23, 0x0303, len(body[i:i + 16000])) + body[i:i + 16000]
                               for i in range(0, len(body), 16000))
            flow = TCPFlow(sim, struct.pack("!BHH", 23, 0x0303, 64) + b"\x00" * 64, records, dport=443, zero_window=zero,
                           think=think, hello=(synth.client_hello("app.example.com"), sh))
        sim.at(0.05, flow.start)
    elif traffic == "ping":
        _ping(sim)
    elif traffic == "traceroute":
        _traceroute(sim)
    elif traffic == "dns":
        _dns(sim, fault)
    elif traffic == "dhcp":
        _dhcp(sim, fault)
    sim.run()
    net.frames.sort(key=lambda f: f[0])
    exp = expected_findings(fault, traffic)
    if fault == "loss" and not net.loss_hits:
        exp = []
        sim.notes.append(f"At {float(loss_rate):.0%} loss no packet of this short exchange happened to be dropped "
                         "(try another seed or a higher rate)")
    if fault in ("latency", "loss") and traffic == "dns" and _fault_side(net, kind, where) == "before":
        exp = []      # query→answer time measured here only covers the server side of the capture point
        sim.notes.append("The fault sits between the client and the capture point: DNS timing seen here only covers the "
                         "server side, so it looks healthy from this vantage point")
    if fault == "mtu_icmp" and net.capture <= where:
        # the oversize packet dies before reaching this capture and the ICMP goes to the server: PMTUD works
        # invisibly from here, so a clean capture is the correct result
        exp = []
        sim.notes.append("Path MTU discovery happened entirely on the server side of the capture point")
    visible = sum(1 for _, f in net.frames if f[12:14] == b"\x08\x00")   # IP frames (not just CDP) at the capture link
    if not visible and exp:
        exp = []
        sim.notes.append("None of this traffic crossed the capture link: the fault stops it before the capture point "
                         "(or it never leaves another segment). Move the capture closer to the client to see it.")
    return {"frames": net.frames, "journey": net.journey, "notes": sim.notes, "expected": exp,
            "topology": {"nodes": [{k: v for k, v in n.items()} for n in net.nodes], "capture_link": net.capture,
                         "rogue": fault == "dhcp_rogue"},
            "config": {"traffic": traffic, "fault": fault, "where": where, "routers": routers, "switch": switch,
                       "capture": net.capture, "link_ms": link_ms, "size_kb": size_kb, "loss_rate": loss_rate,
                       "latency_ms": latency_ms, "mtu": mtu, "think_s": think_s, "seed": seed},
            "fault_side": _fault_side(net, kind, where), "visible_frames": visible}


def _fault_side(net: Net, kind, where) -> str | None:
    """Is the fault between the client and the capture point, or beyond it?"""
    if kind in (None, "client"):
        return None if kind is None else "client"
    if kind == "server":
        return "beyond"
    pos = net.idx(where) if kind == "router" else int(where) + 0.5
    return "before" if pos <= net.capture else "beyond"


def write(result: dict, path: str) -> str:
    write_pcapng(path, result["frames"])
    return path
