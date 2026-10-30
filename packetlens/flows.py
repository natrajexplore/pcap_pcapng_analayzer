"""Conversation tracking and TCP stream analysis.

The TCP engine reproduces the most useful Wireshark ``tcp.analysis.*`` expert
flags (the "Bad TCP" colouring rule in Chris Greer's TCP profile):
retransmission, fast/spurious retransmission, out-of-order, lost segment,
duplicate ACK, ACKed unseen segment, zero window, zero-window probe,
window full, window update and keep-alive. It also measures handshake iRTT,
splits it into client-side and server-side latency (to locate the capture
point), tracks conversation completeness, bytes-in-flight, TCP delta gaps and
application response time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .packet import Packet

M32 = 0xFFFFFFFF


def seq_gt(a: int, b: int) -> bool:
    return 0 < ((a - b) & M32) < 0x80000000


def seq_lt(a: int, b: int) -> bool:
    return seq_gt(b, a)


def seq_le(a: int, b: int) -> bool:
    return a == b or seq_lt(a, b)


@dataclass
class Direction:
    isn: Optional[int] = None
    next_seq: Optional[int] = None
    last_ack: Optional[int] = None
    last_ack_ts: float = 0.0
    last_win: int = -1           # calculated (scaled) window
    last_win_raw: int = -1
    wscale: int = -1
    mss: Optional[int] = None
    sack_perm: bool = False
    timestamps: bool = False
    dupacks: int = 0
    last_ts: float = 0.0
    last_data_ts: float = 0.0
    bytes: int = 0
    payload_bytes: int = 0
    packets: int = 0
    last_was_keepalive: bool = False
    max_bif: int = 0
    min_win: Optional[int] = None


@dataclass
class TCPStream:
    id: int
    client: str
    cport: int
    server: str
    sport: int
    first_ts: float
    last_ts: float = 0.0
    first_no: int = 0
    c: Direction = field(default_factory=Direction)
    s: Direction = field(default_factory=Direction)
    syn_ts: Optional[float] = None
    first_syn_ts: Optional[float] = None
    synack_ts: Optional[float] = None
    ack_ts: Optional[float] = None
    syn_count: int = 0
    synack_count: int = 0
    completeness: int = 0
    flags: dict = field(default_factory=dict)       # analysis flag -> count
    events: list = field(default_factory=list)      # (no, flag, dir)
    rst: Optional[dict] = None
    fin_from: list = field(default_factory=list)
    max_delta: float = 0.0
    max_delta_no: int = 0
    gaps: list = field(default_factory=list)       # large idle gaps with attribution
    response_times: list = field(default_factory=list)   # (request no, response no, seconds)
    ladder: list = field(default_factory=list)
    app: str = "TCP"
    _awaiting_response_from: Optional[int] = None
    _last_req_ts: float = 0.0
    _last_req_no: int = 0
    _zero_window_active: dict = field(default_factory=dict)

    @property
    def irtt(self) -> Optional[float]:
        if self.syn_ts is not None and self.ack_ts is not None:
            return self.ack_ts - self.syn_ts
        return None

    @property
    def server_side_rtt(self) -> Optional[float]:
        if self.syn_ts is not None and self.synack_ts is not None:
            return self.synack_ts - self.syn_ts
        return None

    @property
    def client_side_rtt(self) -> Optional[float]:
        if self.synack_ts is not None and self.ack_ts is not None:
            return self.ack_ts - self.synack_ts
        return None

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    def count(self, flag: str) -> int:
        return self.flags.get(flag, 0)

    def completeness_str(self) -> str:
        bits = [(1, "SYN"), (2, "SYN-ACK"), (4, "ACK"), (8, "DATA"), (16, "FIN"), (32, "RST")]
        return "·".join(n for b, n in bits if self.completeness & b) or "none"

    def to_dict(self) -> dict:
        r = lambda v: None if v is None else round(v * 1000, 3)  # noqa: E731  (ms)
        dur = max(self.duration, 1e-6)
        return {
            "id": self.id, "client": f"{self.client}:{self.cport}", "server": f"{self.server}:{self.sport}",
            "app": self.app, "start": round(self.first_ts, 6), "duration": round(self.duration, 6),
            "packets": self.c.packets + self.s.packets,
            "bytes_c2s": self.c.bytes, "bytes_s2c": self.s.bytes,
            "payload_c2s": self.c.payload_bytes, "payload_s2c": self.s.payload_bytes,
            "throughput_bps_s2c": round(self.s.payload_bytes * 8 / dur),
            "throughput_bps_c2s": round(self.c.payload_bytes * 8 / dur),
            "irtt_ms": r(self.irtt), "server_side_ms": r(self.server_side_rtt),
            "client_side_ms": r(self.client_side_rtt),
            "mss": [self.c.mss, self.s.mss], "wscale": [self.c.wscale, self.s.wscale],
            "sack": [self.c.sack_perm, self.s.sack_perm],
            "completeness": self.completeness, "completeness_str": self.completeness_str(),
            "flags": self.flags, "rst": self.rst, "max_delta_ms": r(self.max_delta),
            "max_delta_no": self.max_delta_no, "gaps": self.gaps[:20],
            "response_times_ms": [(a, b, round(t * 1000, 3)) for a, b, t in self.response_times[:50]],
            "max_bif": [self.c.max_bif, self.s.max_bif],
            "min_win": [self.c.min_win, self.s.min_win],
            "ladder": self.ladder,
        }


@dataclass
class Conversation:
    proto: str
    a: str
    b: str
    first_ts: float
    last_ts: float = 0.0
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    apps: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"proto": self.proto, "a": self.a, "b": self.b, "start": round(self.first_ts, 6),
                "duration": round(self.last_ts - self.first_ts, 6), "packets_ab": self.packets_ab,
                "packets_ba": self.packets_ba, "bytes_ab": self.bytes_ab, "bytes_ba": self.bytes_ba,
                "apps": sorted(self.apps)}


class FlowTracker:
    LADDER_MAX = 400
    GAP_THRESHOLD = 1.0   # Chris Greer "Slow Stuff // TCP Delta" button: tcp.time_delta > 1

    def __init__(self) -> None:
        self.streams: list[TCPStream] = []
        self._tcp: dict[tuple, TCPStream] = {}
        self.conversations: dict[tuple, Conversation] = {}
        self.ip_conversations: dict[tuple, Conversation] = {}

    # ------------------------------------------------------------ public ----
    def add(self, p: Packet) -> None:
        if p.src is None:
            return
        self._conv(p)
        if p.tcp is not None:
            self._tcp_packet(p)

    # ------------------------------------------------------- conversations --
    def _conv(self, p: Packet) -> None:
        key_ip = tuple(sorted((p.src, p.dst)))
        ipc = self.ip_conversations.get(key_ip)
        if ipc is None:
            ipc = self.ip_conversations[key_ip] = Conversation(f"IPv{p.ip_version}", key_ip[0], key_ip[1], p.ts)
        self._bump(ipc, p, p.src == ipc.a)
        if p.sport is None:
            return
        proto = "TCP" if p.tcp else "UDP"
        e1, e2 = f"{p.src}:{p.sport}", f"{p.dst}:{p.dport}"
        key = (proto,) + tuple(sorted((e1, e2)))
        c = self.conversations.get(key)
        if c is None:
            c = self.conversations[key] = Conversation(proto, key[1], key[2], p.ts)
        self._bump(c, p, e1 == c.a)

    @staticmethod
    def _bump(c: Conversation, p: Packet, forward: bool) -> None:
        c.last_ts = p.ts
        if forward:
            c.packets_ab += 1
            c.bytes_ab += p.wirelen
        else:
            c.packets_ba += 1
            c.bytes_ba += p.wirelen
        if p.protocol not in ("TCP", "UDP", "IPv4", "IPv6"):
            c.apps.add(p.protocol)

    # ------------------------------------------------------------- tcp ------
    def _tcp_packet(self, p: Packet) -> None:
        t = p.tcp
        k1 = (p.src, p.sport, p.dst, p.dport)
        k2 = (p.dst, p.dport, p.src, p.sport)
        st = self._tcp.get(k1) or self._tcp.get(k2)
        # a new SYN on a closed/reset tuple starts a new stream (port reuse)
        if st is not None and t.syn and not t.ackf and (st.rst or len(st.fin_from) >= 2) \
                and st.c.isn is not None and t.seq != st.c.isn:
            st = None
        if st is None:
            if t.syn and t.ackf:   # capture started mid-handshake: SYN-ACK sender is the server
                st = TCPStream(len(self.streams), p.dst, p.dport, p.src, p.sport, p.ts, first_no=p.no)
            else:
                st = TCPStream(len(self.streams), p.src, p.sport, p.dst, p.dport, p.ts, first_no=p.no)
            self.streams.append(st)
            self._tcp[k1] = st
            self._tcp.pop(k2, None)
        t.stream = st.id
        from_client = p.src == st.client and p.sport == st.cport
        d, o = (st.c, st.s) if from_client else (st.s, st.c)

        # ---- time delta (Wireshark tcp.time_delta) & idle-gap attribution
        if st.last_ts:
            t.time_delta = p.ts - st.last_ts
            if t.time_delta > st.max_delta:
                st.max_delta, st.max_delta_no = t.time_delta, p.no
        st.last_ts = p.ts

        seglen = t.payload_len + (1 if t.syn else 0) + (1 if t.fin else 0)
        flags: list[str] = []

        # ---- handshake & options
        if t.syn:
            if "mss" in t.options:
                d.mss = t.options["mss"]
            d.wscale = t.options.get("wscale", -1)
            d.sack_perm = bool(t.options.get("sack_perm"))
            d.timestamps = "ts" in t.options
            if not t.ackf:
                st.syn_count += 1
                st.completeness |= 1
                if st.first_syn_ts is None:
                    st.first_syn_ts = p.ts
                if d.isn == t.seq and st.syn_count > 1:
                    flags.append("retransmission")
                    flags.append("syn_retransmission")
                d.isn = t.seq
                st.syn_ts = p.ts
            else:
                st.synack_count += 1
                st.completeness |= 2
                if st.synack_count > 1 and d.isn == t.seq:
                    flags.append("retransmission")
                    flags.append("synack_retransmission")
                d.isn = t.seq
                if st.synack_ts is None or st.synack_count > 1:
                    st.synack_ts = p.ts
        elif from_client and st.synack_ts is not None and st.ack_ts is None and t.ackf \
                and st.s.isn is not None and t.ack == (st.s.isn + 1) & M32:
            st.ack_ts = p.ts
            st.completeness |= 4
        if t.payload_len:
            st.completeness |= 8
        if t.fin:
            st.completeness |= 16
            st.fin_from.append("client" if from_client else "server")
        if t.rst:
            st.completeness |= 32

        scaled = d.wscale >= 0 and o.wscale >= 0
        t.calc_window = t.window << d.wscale if (scaled and not t.syn) else t.window
        if not t.syn and not t.rst:
            d.min_win = t.calc_window if d.min_win is None else min(d.min_win, t.calc_window)

        plain = not (t.syn or t.fin or t.rst)
        # ---- zero window & probes
        if t.window == 0 and plain:
            flags.append("zero_window")
            st._zero_window_active[from_client] = True
        elif t.window and st._zero_window_active.get(from_client):
            st._zero_window_active[from_client] = False
        keepalive = (plain and seglen <= 1 and d.next_seq is not None
                     and t.seq == (d.next_seq - 1) & M32)
        if keepalive:
            flags.append("keep_alive")
        elif t.payload_len == 1 and o.last_win == 0 and d.next_seq is not None and \
                t.seq in (d.next_seq, (d.next_seq - 1) & M32):
            flags.append("zero_window_probe")
        if plain and t.payload_len == 0 and d.last_ack == t.ack and o.last_was_keepalive:
            flags.append("keep_alive_ack")

        # ---- sequence analysis
        if d.next_seq is not None and not t.rst and not keepalive and seglen > 0 and not t.syn:
            if seq_gt(t.seq, d.next_seq):
                flags.append("lost_segment")          # previous segment not captured
            elif seq_lt(t.seq, d.next_seq):
                if o.last_ack is not None and seq_le((t.seq + seglen) & M32, o.last_ack):
                    flags.append("spurious_retransmission")
                elif o.dupacks >= 2 and o.last_ack == t.seq and p.ts - o.last_ack_ts < 0.05:
                    flags.append("fast_retransmission")
                elif d.last_ts and p.ts - d.last_ts < min(0.003, st.irtt or 0.003) \
                        and "zero_window_probe" not in flags:
                    flags.append("out_of_order")
                elif "zero_window_probe" not in flags:
                    flags.append("retransmission")

        # ---- ack analysis
        if t.ackf and not t.rst:
            if o.next_seq is not None and seq_gt(t.ack, o.next_seq) and not t.syn:
                flags.append("ack_unseen")
            if plain and t.payload_len == 0 and d.last_ack is not None and "keep_alive_ack" not in flags:
                if t.ack == d.last_ack and t.window == d.last_win_raw and \
                        o.next_seq is not None and seq_gt(o.next_seq, t.ack):
                    d.dupacks += 1
                    flags.append("duplicate_ack")
                elif t.ack == d.last_ack and t.window != d.last_win_raw and d.last_win_raw >= 0:
                    flags.append("window_update")
            if d.last_ack is None or seq_gt(t.ack, d.last_ack):
                d.last_ack = t.ack
                d.dupacks = 0
            d.last_ack_ts = p.ts

        # ---- window full
        if t.payload_len and o.last_ack is not None and o.last_win > 0 and \
                (t.seq + t.payload_len) & M32 == (o.last_ack + o.last_win) & M32:
            flags.append("window_full")

        # ---- update state
        end = (t.seq + seglen) & M32
        if "zero_window_probe" in flags:
            pass  # probe byte is not accepted by a zero window; do not advance next_seq
        elif d.next_seq is None or seq_gt(end, d.next_seq):
            d.next_seq = end
        if not t.syn:
            d.last_win, d.last_win_raw = t.calc_window, t.window
        elif t.syn:
            d.last_win, d.last_win_raw = t.window, t.window
        d.packets += 1
        d.last_ts = p.ts
        d.bytes += p.wirelen
        d.payload_bytes += t.payload_len
        d.last_was_keepalive = keepalive
        if t.payload_len and o.last_ack is not None and d.next_seq is not None:
            t.bytes_in_flight = (d.next_seq - o.last_ack) & M32
            if t.bytes_in_flight < 0x7FFFFFFF:
                d.max_bif = max(d.max_bif, t.bytes_in_flight)

        # ---- RST classification
        if t.rst and st.rst is None:
            who = "client" if from_client else "server"
            if not (st.completeness & 8) and (st.completeness & 1) and not (st.completeness & 2):
                kind = "refused"        # SYN answered by RST: nothing listening / firewall reject
            elif st.fin_from:
                kind = "after_fin"
            elif st.completeness & 8:
                kind = "abort"          # reset in the middle of a data transfer
            else:
                kind = "early"
            st.rst = {"no": p.no, "from": who, "kind": kind, "ts": p.ts}

        # ---- idle-gap attribution (before the response tracking below clears the pending request)
        if t.time_delta > self.GAP_THRESHOLD and st.c.packets + st.s.packets > 1:
            st.gaps.append({"no": p.no, "seconds": round(t.time_delta, 3),
                            "cause": self._gap_cause(t, flags, from_client, st)})
        # ---- application response time
        if t.payload_len and "retransmission" not in flags and "keep_alive" not in flags:
            if from_client:
                st._awaiting_response_from, st._last_req_ts, st._last_req_no = 1, p.ts, p.no
            elif st._awaiting_response_from == 1:
                st.response_times.append((st._last_req_no, p.no, p.ts - st._last_req_ts))
                st._awaiting_response_from = None

        # ---- record
        t.analysis = flags
        for f in flags:
            st.flags[f] = st.flags.get(f, 0) + 1
            if len(st.events) < 2000:
                st.events.append((p.no, f, "c2s" if from_client else "s2c"))
        if len(st.ladder) < self.LADDER_MAX:
            st.ladder.append({"no": p.no, "t": round(p.ts - st.first_ts, 6),
                              "dir": "c2s" if from_client else "s2c", "flags": t.flag_str(),
                              "len": t.payload_len, "seq": (t.seq - (d.isn or 0)) & M32,
                              "ack": (t.ack - (o.isn or 0)) & M32 if t.ackf else 0,
                              "win": t.calc_window, "analysis": flags, "app": p.protocol})
        if p.protocol not in ("TCP",):
            st.app = p.protocol if st.app == "TCP" else st.app
        # ---- per-packet signatures (Chris Greer ThreatHunt profile)
        self._signatures(p, t)

    @staticmethod
    def _gap_cause(t, flags, from_client, st) -> str:
        if any(f in flags for f in ("retransmission", "fast_retransmission", "spurious_retransmission")):
            return "network: sender waited for retransmission timeout (RTO) — packet loss"
        if "zero_window_probe" in flags or any(st._zero_window_active.values()):
            return "receiver: advertised zero window — application not reading data"
        if "keep_alive" in flags:
            return "idle: connection idle, keep-alive sent"
        if t.payload_len and not from_client and st._awaiting_response_from == 1:
            return "server: application think time (request received, response delayed)"
        if t.payload_len and from_client:
            return "client: client/user think time before next request"
        if t.fin or t.rst:
            return "teardown: idle before close"
        return "idle: no data outstanding"

    @staticmethod
    def _signatures(p: Packet, t) -> None:
        if t.syn and not t.ackf:
            if t.hdr_len == 20:
                p.tags.append("syn_no_options")
            elif "mss" not in t.options:
                p.tags.append("syn_no_mss")
            if t.window == 1024:
                p.tags.append("nmap_syn_lowwin")
            if t.window == 0:
                p.tags.append("invalid_syn_zero_window")
        if (t.flags & 0x3F) == 0:
            p.tags.append("null_scan")
        elif (t.flags & 0x3F) == 0x29:
            p.tags.append("xmas_scan")
        if t.options.get("nops", 0) >= 4:
            p.tags.append("four_nop")
