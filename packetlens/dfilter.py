"""Wireshark-style display filters.

    ip.addr == 10.0.0.0/8 && tcp.port in {80 443} && !tcp.analysis.retransmission
    dns.qry.name contains "example" || http.request.method == "POST"
    frame contains "jndi" or tcp.flags.reset == 1

Grammar: ``or`` (``||``) of ``and`` (``&&``) of optional ``!``/``not`` of either a parenthesised
expression or a test ``field [op value]``. Operators: ``== eq != ne > gt < lt >= ge <= le contains
matches ~ in {…}``. A bare field is true when present. Multi-valued fields (``ip.addr``) match when any
value matches; ``!=`` means "no value equals" (Wireshark 3.6+ semantics). ``matches`` is a
case-insensitive regular expression.
"""
from __future__ import annotations

import ipaddress
import re

TOKEN = re.compile(r"""\s*(?:
    (?P<str>"(?:[^"\\]|\\.)*")|
    (?P<op>==|!=|>=|<=|&&|\|\||[()!<>{}~,])|
    (?P<word>[A-Za-z0-9_.:/\-]+)
)""", re.X)
WORD_OPS = {"eq": "==", "ne": "!=", "gt": ">", "lt": "<", "ge": ">=", "le": "<=", "and": "&&", "or": "||", "not": "!",
            "contains": "contains", "matches": "matches", "in": "in"}
CMP = {"==", "!=", ">", "<", ">=", "<=", "contains", "matches", "~", "in"}


class FilterError(ValueError):
    pass


# ------------------------------------------------------------------ fields --
def _ip_list(*vals):
    return [v for v in vals if v]


def _tcp(p, attr):
    return [getattr(p.tcp, attr)] if p.tcp is not None else []


def _flag(bit):
    return lambda p, raw: [1 if p.tcp.flags & bit else 0] if p.tcp is not None else []


def _layer(name, key):
    def get(p, raw):
        d = p.layers.get(name)
        if not d:
            return []
        v = d.get(key)
        if v is None:
            return []
        return v if isinstance(v, list) else [v]
    return get


def _v4(p):
    return p.ip_version == 4


def _v6(p):
    return p.ip_version == 6


FIELDS = {
    "frame.number": lambda p, raw: [p.no],
    "frame.len": lambda p, raw: [p.wirelen],
    "frame.cap_len": lambda p, raw: [p.caplen],
    "frame.time_relative": lambda p, raw: [p.rel_ts],
    "frame.protocols": lambda p, raw: [protocol_stack(p)],
    "frame.marked": lambda p, raw: [],                                     # resolved by the caller (marked set)
    "eth.src": lambda p, raw: _ip_list(p.eth_src),
    "eth.dst": lambda p, raw: _ip_list(p.eth_dst),
    "eth.addr": lambda p, raw: _ip_list(p.eth_src, p.eth_dst),
    "eth.type": lambda p, raw: [p.ethertype] if p.ethertype is not None else [],
    "vlan.id": lambda p, raw: [p.vlan] if p.vlan is not None else [],
    "ip.src": lambda p, raw: _ip_list(p.src) if _v4(p) else [],
    "ip.dst": lambda p, raw: _ip_list(p.dst) if _v4(p) else [],
    "ip.addr": lambda p, raw: _ip_list(p.src, p.dst) if _v4(p) else [],
    "ip.ttl": lambda p, raw: [p.ttl] if _v4(p) else [],
    "ip.proto": lambda p, raw: [p.ip_proto] if _v4(p) else [],
    "ip.len": lambda p, raw: [p.ip_len] if _v4(p) else [],
    "ip.id": lambda p, raw: [p.ip_id] if _v4(p) and p.ip_id is not None else [],
    "ip.flags.df": lambda p, raw: [int(p.ip_df)] if _v4(p) else [],
    "ip.flags.mf": lambda p, raw: [int(p.ip_mf)] if _v4(p) else [],
    "ip.frag_offset": lambda p, raw: [p.ip_frag_offset] if _v4(p) else [],
    "ip.dsfield.dscp": lambda p, raw: [p.dscp] if p.ip_version else [],
    "ip.checksum.status": lambda p, raw: [{True: "good", False: "bad", None: "unverified"}[p.ip_checksum_ok]] if _v4(p) else [],
    "ipv6.src": lambda p, raw: _ip_list(p.src) if _v6(p) else [],
    "ipv6.dst": lambda p, raw: _ip_list(p.dst) if _v6(p) else [],
    "ipv6.addr": lambda p, raw: _ip_list(p.src, p.dst) if _v6(p) else [],
    "ipv6.hlim": lambda p, raw: [p.ttl] if _v6(p) else [],
    "ipv6.nxt": lambda p, raw: [p.ip_proto] if _v6(p) else [],
    "tcp.srcport": lambda p, raw: _tcp(p, "sport"),
    "tcp.dstport": lambda p, raw: _tcp(p, "dport"),
    "tcp.port": lambda p, raw: [p.tcp.sport, p.tcp.dport] if p.tcp is not None else [],
    "tcp.stream": lambda p, raw: _tcp(p, "stream"),
    "tcp.seq": lambda p, raw: _tcp(p, "seq"),
    "tcp.ack": lambda p, raw: _tcp(p, "ack"),
    "tcp.len": lambda p, raw: _tcp(p, "payload_len"),
    "tcp.hdr_len": lambda p, raw: _tcp(p, "hdr_len"),
    "tcp.window_size_value": lambda p, raw: _tcp(p, "window"),
    "tcp.window_size": lambda p, raw: _tcp(p, "calc_window"),
    "tcp.flags": lambda p, raw: _tcp(p, "flags"),
    "tcp.flags.syn": _flag(0x02), "tcp.flags.ack": _flag(0x10), "tcp.flags.fin": _flag(0x01),
    "tcp.flags.reset": _flag(0x04), "tcp.flags.push": _flag(0x08), "tcp.flags.urg": _flag(0x20),
    "tcp.options.mss_val": lambda p, raw: [p.tcp.options["mss"]] if p.tcp is not None and "mss" in p.tcp.options else [],
    "tcp.time_delta": lambda p, raw: _tcp(p, "time_delta"),
    "tcp.analysis.bytes_in_flight": lambda p, raw: [p.tcp.bytes_in_flight] if p.tcp is not None and p.tcp.bytes_in_flight else [],
    "tcp.analysis.flags": lambda p, raw: [1] if p.tcp is not None and set(p.tcp.analysis) - {"window_update", "keep_alive_ack"} else [],
    "udp.srcport": lambda p, raw: [p.sport] if p.ip_proto == 17 and p.sport is not None else [],
    "udp.dstport": lambda p, raw: [p.dport] if p.ip_proto == 17 and p.dport is not None else [],
    "udp.port": lambda p, raw: [p.sport, p.dport] if p.ip_proto == 17 and p.sport is not None else [],
    "icmp.type": lambda p, raw: [p.layers["icmp"]["type"]] if "icmp" in p.layers and not p.layers["icmp"]["v6"] else [],
    "icmp.code": lambda p, raw: [p.layers["icmp"]["code"]] if "icmp" in p.layers and not p.layers["icmp"]["v6"] else [],
    "icmpv6.type": lambda p, raw: [p.layers["icmp"]["type"]] if "icmp" in p.layers and p.layers["icmp"]["v6"] else [],
    "icmpv6.code": lambda p, raw: [p.layers["icmp"]["code"]] if "icmp" in p.layers and p.layers["icmp"]["v6"] else [],
    "arp.opcode": lambda p, raw: [1 if p.layers["arp"]["op"] == "request" else 2] if "arp" in p.layers else [],
    "arp.src.proto_ipv4": _layer("arp", "sender_ip"), "arp.dst.proto_ipv4": _layer("arp", "target_ip"),
    "arp.src.hw_mac": _layer("arp", "sender_mac"), "arp.dst.hw_mac": _layer("arp", "target_mac"),
    "dns.qry.name": _layer("dns", "qname"), "dns.qry.type": _layer("dns", "qtype"),
    "dns.id": _layer("dns", "id"), "dns.flags.rcode": _layer("dns", "rcode"),
    "dns.flags.response": lambda p, raw: [int(p.layers["dns"]["qr"])] if "dns" in p.layers else [],
    "dns.a": lambda p, raw: [a["data"] for a in p.layers["dns"]["answers"] if a["type"] == "A"] if "dns" in p.layers else [],
    "http.request": lambda p, raw: [1] if p.layers.get("http", {}).get("type") == "request" else [],
    "http.response": lambda p, raw: [1] if p.layers.get("http", {}).get("type") == "response" else [],
    "http.request.method": _layer("http", "method"), "http.request.uri": _layer("http", "uri"),
    "http.request.full_uri": _layer("http", "url"), "http.host": _layer("http", "host"),
    "http.user_agent": _layer("http", "user_agent"), "http.response.code": _layer("http", "status"),
    "http.content_type": _layer("http", "content_type"),
    "tls.handshake.type": lambda p, raw: p.layers["tls"].get("handshakes", []) if "tls" in p.layers else [],
    "tls.handshake.extensions_server_name": lambda p, raw: _ip_list((p.layers.get("tls", {}).get("client_hello") or {}).get("sni")),
    "tls.handshake.ja3": lambda p, raw: _ip_list((p.layers.get("tls", {}).get("client_hello") or {}).get("ja3")),
    "tls.record.content_type": lambda p, raw: [r["type"] for r in p.layers["tls"]["records"]] if "tls" in p.layers else [],
    "dhcp.option.dhcp": _layer("dhcp", "msg_type"), "dhcp.hw.mac_addr": _layer("dhcp", "chaddr"),
    "bgp.type": lambda p, raw: [m["type"] for m in p.layers["bgp"]["messages"]] if "bgp" in p.layers else [],
    "ospf.msg": _layer("ospf", "type"), "ospf.srcrouter": _layer("ospf", "router_id"), "ospf.area_id": _layer("ospf", "area"),
    "pim.type": _layer("pim", "type_num"), "igmp.type": _layer("igmp", "type_num"),
    "cdp.deviceid": _layer("cdp", "device_id"), "cdp.native_vlan": _layer("cdp", "native_vlan"),
    "eap.code": lambda p, raw: [{"Request": 1, "Response": 2, "Success": 3, "Failure": 4}.get((p.layers["eapol"].get("eap") or {}).get("code"))]
                               if (p.layers.get("eapol") or {}).get("eap") else [],
    "radius.code": _layer("radius", "code_num"), "radius.User_Name": _layer("radius", "user"),
    "vxlan.vni": _layer("vxlan", "vni"), "gre.proto": _layer("gre", "proto"),
    "stp.flags.tc": lambda p, raw: [int(p.layers["stp"]["tc"])] if "stp" in p.layers else [],
}
# Wireshark tcp.analysis.* expert fields map onto the analyzer's per-packet flags
ANALYSIS = {"retransmission": "retransmission", "fast_retransmission": "fast_retransmission",
            "spurious_retransmission": "spurious_retransmission", "out_of_order": "out_of_order",
            "lost_segment": "lost_segment", "ack_lost_segment": "ack_unseen", "duplicate_ack": "duplicate_ack",
            "zero_window": "zero_window", "zero_window_probe": "zero_window_probe", "window_full": "window_full",
            "window_update": "window_update", "keep_alive": "keep_alive", "keep_alive_ack": "keep_alive_ack"}
for _name, _flagname in ANALYSIS.items():
    FIELDS[f"tcp.analysis.{_name}"] = (lambda fl: lambda p, raw: [1] if p.tcp is not None and fl in p.tcp.analysis else [])(_flagname)

# protocol names as bare tests (Wireshark's "dns", "!arp", …)
PROTOCOLS = {
    "eth": lambda p: p.eth_src is not None and "wlan" not in p.layers, "vlan": lambda p: p.vlan is not None,
    "ip": _v4, "ipv6": _v6, "tcp": lambda p: p.tcp is not None, "udp": lambda p: p.ip_proto == 17 and p.sport is not None,
    "icmp": lambda p: "icmp" in p.layers and not p.layers["icmp"]["v6"],
    "icmpv6": lambda p: "icmp" in p.layers and p.layers["icmp"]["v6"],
    "http2": lambda p: "http2" in p.layers, "quic": lambda p: p.protocol == "QUIC", "wlan": lambda p: "wlan" in p.layers,
    "llc": lambda p: p.protocol == "LLC", "loop": lambda p: p.protocol == "LOOP",
}
for _l in ("arp", "dns", "http", "tls", "dhcp", "bgp", "ospf", "eigrp", "rip", "stp", "isis", "pim", "igmp", "gre", "vxlan",
           "cdp", "dtp", "lldp", "eapol", "radius"):
    PROTOCOLS[_l] = (lambda n: lambda p: n in p.layers)(_l)
PROTOCOLS["hsrp"] = lambda p: p.protocol == "HSRP"
PROTOCOLS["vrrp"] = lambda p: p.protocol == "VRRP"
PROTOCOLS["ssl"] = PROTOCOLS["tls"]
PROTOCOLS["bootp"] = PROTOCOLS["dhcp"]


def protocol_stack(p) -> str:
    """Wireshark ``frame.protocols``-style stack, e.g. ``eth:ethertype:ip:tcp:tls``."""
    out = []
    if "wlan" in p.layers:
        out.append("wlan")
    elif p.eth_src:
        out += ["eth", "ethertype"] if p.ethertype is not None else ["eth", "llc"]
    if p.vlan is not None and "isl" not in p.layers:
        out.insert(min(2, len(out)), "vlan")
    for t in ("gre", "vxlan"):
        if t in p.layers:
            out += ["ip", t]
    if p.ip_version:
        out.append("ip" if p.ip_version == 4 else "ipv6")
    if p.tcp is not None:
        out.append("tcp")
    elif p.ip_proto == 17 and p.sport is not None:
        out.append("udp")
    app = p.protocol.lower()
    for name in p.layers:
        if name not in ("wlan", "isl", "gre", "vxlan") and name not in out:
            out.append(name)
    if app not in out and app not in ("tcp", "udp", "ipv4", "ipv6", "eth", "llc"):
        out.append(app)
    return ":".join(out)


# ------------------------------------------------------------------ parser --
def _tokens(text: str) -> list:
    pos, out = 0, []
    text = text.strip()
    while pos < len(text):
        m = TOKEN.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"unexpected character at {pos + 1}: {text[pos:pos + 10]!r}")
        pos = m.end()
        if m.group("str") is not None:
            # only \" and \\ are escapes; other backslashes stay literal so regexes like "1\.1" work as typed
            out.append(("str", re.sub(r'\\(["\\])', r"\1", m.group("str")[1:-1])))
        elif m.group("op") is not None:
            out.append(("op", m.group("op")))
        else:
            w = m.group("word")
            out.append(("op", WORD_OPS[w.lower()]) if w.lower() in WORD_OPS else ("word", w))
    return out


class _P:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, kind=None, val=None):
        k, v = self.peek()
        if k is None or (kind and k != kind) or (val and v != val):
            raise FilterError(f"expected {val or kind}, found {v or 'end of filter'}")
        self.i += 1
        return v

    def expr(self):
        left = self.andexpr()
        while self.peek() == ("op", "||"):
            self.i += 1
            right = self.andexpr()
            left = (lambda a, b: lambda c: a(c) or b(c))(left, right)
        return left

    def andexpr(self):
        left = self.notexpr()
        while self.peek() == ("op", "&&"):
            self.i += 1
            right = self.notexpr()
            left = (lambda a, b: lambda c: a(c) and b(c))(left, right)
        return left

    def notexpr(self):
        if self.peek() == ("op", "!"):
            self.i += 1
            inner = self.notexpr()
            return lambda c: not inner(c)
        if self.peek() == ("op", "("):
            self.i += 1
            e = self.expr()
            self.take("op", ")")
            return e
        return self.test()

    def value(self):
        k, v = self.peek()
        if k in ("str", "word"):
            self.i += 1
            return v
        raise FilterError(f"expected a value, found {v or 'end of filter'}")

    def test(self):
        if self.peek()[0] != "word":
            raise FilterError(f"expected a field or protocol, found {self.peek()[1] or 'end of filter'}")
        name = self.take("word")
        k, op = self.peek()
        if name == "frame" and op in ("contains", "matches"):
            self.i += 1
            needle = self.value()
            if op == "contains":
                b = _as_bytes(needle)
                return lambda c: b in c.raw()
            rx = _regex(needle)
            return lambda c: bool(rx.search(c.raw().decode("latin-1")))
        if name in PROTOCOLS and not (k == "op" and op in CMP):
            test = PROTOCOLS[name]
            return lambda c: test(c.p)
        if name == "frame.marked":
            return lambda c: c.marked
        if name not in FIELDS:
            raise FilterError(f'"{name}" is not a known field or protocol')
        get = FIELDS[name]
        if not (k == "op" and op in CMP):
            return lambda c: bool(get(c.p, c.raw))              # bare field: true when present (Wireshark)
        self.i += 1
        if op == "in":
            self.take("op", "{")
            vals = []
            while self.peek() != ("op", "}"):
                vals.append(self.value())
                if self.peek() == ("op", ","):
                    self.i += 1
            self.take("op", "}")
            preds = [_cmp("==", v) for v in vals]
            return lambda c: any(any(pr(x) for pr in preds) for x in get(c.p, c.raw))
        pred = _cmp(op, self.value())
        if op == "!=":
            return lambda c: bool(get(c.p, c.raw)) and all(pred(x) for x in get(c.p, c.raw))
        return lambda c: any(pred(x) for x in get(c.p, c.raw))


def _as_bytes(s: str) -> bytes:
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}[:\-.]){1,}[0-9a-fA-F]{2}", s):     # 4a:4e:44 byte sequences
        return bytes.fromhex(re.sub(r"[:\-.]", "", s))
    return s.encode("utf-8")


def _regex(s: str):
    try:
        return re.compile(s, re.I)
    except re.error as exc:
        raise FilterError(f"invalid regular expression: {exc}") from None


def _num(v):
    try:
        return int(v, 0) if isinstance(v, str) else v
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return None


def _cmp(op, raw_value):
    """Predicate comparing one field value against the filter literal (typed by the field value at runtime)."""
    if op in ("contains",):
        needle = str(raw_value)
        return lambda x: needle in str(x)
    if op in ("matches", "~"):
        rx = _regex(str(raw_value))
        return lambda x: bool(rx.search(str(x)))
    net = None
    if "/" in str(raw_value):
        try:
            net = ipaddress.ip_network(raw_value, strict=False)
        except ValueError:
            net = None
    num = _num(raw_value)
    low = str(raw_value).lower()

    def eq(x):
        if net is not None:
            try:
                return ipaddress.ip_address(x) in net
            except (ValueError, TypeError):
                return False
        if isinstance(x, bool):
            return int(x) == num
        if isinstance(x, (int, float)):
            return num is not None and x == num
        try:
            return ipaddress.ip_address(x) == ipaddress.ip_address(raw_value)
        except (ValueError, TypeError):
            return str(x).lower() == low if ":" in str(x) and len(str(x)) == 17 else str(x) == str(raw_value)

    def order(x):
        if isinstance(x, (int, float)) and num is not None:
            return x, num
        return str(x), str(raw_value)
    return {"==": eq, "!=": lambda x: not eq(x),
            ">": lambda x: (lambda a, b: a > b)(*order(x)), "<": lambda x: (lambda a, b: a < b)(*order(x)),
            ">=": lambda x: (lambda a, b: a >= b)(*order(x)), "<=": lambda x: (lambda a, b: a <= b)(*order(x))}[op]


class Ctx:
    """What a filter sees for one packet: the decoded packet, its raw bytes (lazily) and whether it is marked."""
    __slots__ = ("p", "_raw", "_get_raw", "marked")

    def __init__(self, p, get_raw, marked=False):
        self.p, self._raw, self._get_raw, self.marked = p, None, get_raw, marked

    def raw(self) -> bytes:
        if self._raw is None:
            self._raw = self._get_raw() or b""
        return self._raw


def compile_filter(text: str):
    """Compile a display filter to a predicate over :class:`Ctx`; an empty filter matches everything."""
    if not text or not text.strip():
        return lambda c: True
    p = _P(_tokens(text))
    fn = p.expr()
    if p.i != len(p.t):
        raise FilterError(f"unexpected {p.t[p.i][1]!r} after a complete expression")
    return fn


def field_names() -> list[str]:
    return sorted(set(FIELDS) | set(PROTOCOLS) | {"frame"})
