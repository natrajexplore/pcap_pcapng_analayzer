"""TCP stream reassembly and application-message framing.

Each TCP direction is rebuilt in sequence order (retransmissions and overlaps
removed, out-of-order segments buffered) and cut into application messages:
TLS records, HTTP/1.x headers (+ bodies by Content-Length / chunked), HTTP/2
frames, BGP messages and DNS-over-TCP. Every message is attached to the packet
in which it *completes*, like Wireshark's "reassembled PDU" handling.

TLS records are handed to a :class:`~packetlens.tlsdecrypt.TLSSession`; decrypted
application data is framed again (HTTP/1.x or HTTP/2) so HTTPS traffic gets the
same HTTP analysis as cleartext traffic when a key log is supplied.

Packets are processed in a single pass, so payload bytes can be dropped as soon
as they are consumed (low memory use on large captures).
"""
from __future__ import annotations

import re

from .protocols import bgp, dns, http, http2, tls
from .tlsdecrypt import TLSSession

M32 = 0xFFFFFFFF
MAX_HEADER = 64 * 1024
MAX_OOO = 64
APP_KEYS = ("http", "tls", "bgp", "dns", "http2")
_CL = re.compile(rb"\r\ncontent-length:\s*(\d+)", re.I)
_TE = re.compile(rb"\r\ntransfer-encoding:[^\r\n]*chunked", re.I)
_STATUS = re.compile(rb"^HTTP/\d\.\d (\d{3})")


class Framer:
    """Turns a byte stream into application messages (kind, bytes, start_pkt, end_pkt)."""

    def __init__(self, ports=(), proto: str | None = None):
        self.ports = ports
        self.proto = proto
        self.buf = bytearray()
        self.marks: list = []        # [end offset in buf, packet]
        self.body = None             # int bytes remaining | "chunked" | "close"
        self.preface_done = False
        self.desync = False
        self.h2dec = None

    # ------------------------------------------------------------------ io --
    def feed(self, data: bytes, pkt) -> list:
        if not data or self.proto == "raw":
            return []
        if self.desync:                      # resume only at a segment that starts a recognisable message
            det = self._detect(data)
            if det is None:
                return []
            self.desync, self.proto = False, det
        self.buf += data
        self.marks.append([len(self.buf), pkt])
        if self.proto is None:
            det = self._detect(bytes(self.buf[:64]))
            if det is None:
                if len(self.buf) >= 24:      # enough bytes and still unknown: stop buffering
                    self.proto = "raw"
                    self.buf.clear()
                    self.marks.clear()
                return []
            self.proto = det
        return self._parse()

    def _detect(self, d: bytes) -> str | None:
        if 179 in self.ports and d[:16] == b"\xff" * 16:
            return "bgp"
        if d.startswith(http2.PREFACE[:len(d)]) and len(d) >= 3 and d[:3] == b"PRI":
            return "h2"
        if http.looks_like_http(d):
            return "http"
        if tls.looks_like_tls(d):
            return "tls"
        if 53 in self.ports and len(d) >= 14:
            return "dns"
        return None

    def _pkt_at(self, off: int):
        for end, p in self.marks:
            if end > off:
                return p
        return self.marks[-1][1] if self.marks else None

    def _take(self, n: int):
        msg = bytes(self.buf[:n])
        start, end = self._pkt_at(0), self._pkt_at(n - 1)
        del self.buf[:n]
        self.marks = [[e - n, p] for e, p in self.marks if e - n > 0]
        return msg, start, end

    def _lose_sync(self):
        self.desync = True
        self.buf.clear()
        self.marks.clear()
        self.body = None

    # --------------------------------------------------------------- parse --
    def _parse(self) -> list:
        out = []
        while self.buf:
            if self.body is not None:
                if not self._consume_body():
                    break
                continue
            n = self._msg_len()
            if n is None:
                break
            if n < 0:
                self._lose_sync()
                break
            msg, s, e = self._take(n)
            out.append((self.proto if self.proto != "h2" or self.preface_done or not msg.startswith(b"PRI") else "h2-preface",
                        msg, s, e))
            if self.proto == "h2" and msg.startswith(b"PRI"):
                self.preface_done = True
            if self.proto == "http":
                self._after_http_header(msg)
        return out

    def _msg_len(self) -> int | None:
        b = self.buf
        if self.proto == "tls":
            if len(b) < 5:
                return None
            if b[0] not in (20, 21, 22, 23) or b[1] != 3:
                return -1
            n = 5 + int.from_bytes(b[3:5], "big")
            return n if len(b) >= n else None
        if self.proto == "bgp":
            if len(b) < 19:
                return None
            if b[:16] != b"\xff" * 16:
                return -1
            n = int.from_bytes(b[16:18], "big")
            if n < 19:
                return -1
            return n if len(b) >= n else None
        if self.proto == "dns":
            if len(b) < 2:
                return None
            n = 2 + int.from_bytes(b[:2], "big")
            return n if len(b) >= n else None
        if self.proto == "h2":
            if not self.preface_done and b[:3] == b"PRI":
                return 24 if len(b) >= 24 else None
            if len(b) < 9:
                return None
            n = 9 + int.from_bytes(b[:3], "big")
            return n if len(b) >= n else None
        if self.proto == "http":
            i = b.find(b"\r\n\r\n", 0, MAX_HEADER)
            if i < 0:
                return -1 if len(b) > MAX_HEADER else None
            if not http.looks_like_http(bytes(b[:16])):
                return -1
            return i + 4
        return -1

    def _after_http_header(self, hdr: bytes) -> None:
        m = _STATUS.match(hdr)
        if m and (m.group(1).startswith(b"1") or m.group(1) in (b"204", b"304")):
            return
        if _TE.search(hdr):
            self.body = "chunked"
            return
        cl = _CL.search(hdr)
        if cl:
            n = int(cl.group(1))
            self.body = n or None
        elif m:                                    # response without length: body until close
            self.body = "close"

    def _consume_body(self) -> bool:
        if self.body == "close":
            self._take(len(self.buf))
            return False
        if isinstance(self.body, int):
            take = min(self.body, len(self.buf))
            self._take(take)
            self.body -= take
            if self.body == 0:
                self.body = None
            return self.body is None
        # chunked
        i = self.buf.find(b"\r\n")
        if i < 0:
            return False
        try:
            size = int(bytes(self.buf[:i]).split(b";")[0].strip() or b"0", 16)
        except ValueError:
            self._lose_sync()
            return False
        if size == 0:
            j = self.buf.find(b"\r\n\r\n", i - 2 if i >= 2 else 0)
            if j < 0:
                return False
            self._take(j + 4)
            self.body = None
            return True
        need = i + 2 + size + 2
        if len(self.buf) < need:
            return False
        self._take(need)
        return True


class _Dir:
    def __init__(self, ports):
        self.next_seq = None
        self.ooo: dict = {}
        self.framer = Framer(ports)
        self.broken = False          # sliced capture: fall back to per-packet decoding
        self.plain = None            # Framer for decrypted TLS application data


class Reassembler:
    def __init__(self, keylog=None):
        self.keylog = keylog
        self.dirs: dict = {}
        self.tls: dict[int, TLSSession] = {}
        self.stats = {"messages": 0, "decrypted_records": 0}

    # ------------------------------------------------------------------------
    def feed(self, p, from_client: bool) -> None:
        t = p.tcp
        key = (t.stream, from_client)
        d = self.dirs.get(key)
        if d is None:
            d = self.dirs[key] = _Dir((p.sport, p.dport))
        if t.syn:
            d.next_seq = (t.seq + 1) & M32
            return
        if not t.payload_len or d.broken:
            return
        if "sliced" in p.tags or len(p.payload) < t.payload_len:
            d.broken = True            # keep the per-packet decode done by the dissector
            return
        # reassembly is authoritative for this packet: drop per-packet app decode
        _reset_app(p)
        data, seq = p.payload, t.seq
        if d.next_seq is None:
            d.next_seq = seq
        delta = (seq - d.next_seq) & M32
        if delta >= 0x80000000:                          # starts before next_seq: overlap / retransmission
            skip = (d.next_seq - seq) & M32
            if skip >= len(data):
                return
            data, seq = data[skip:], d.next_seq
        elif delta > 0:                                  # gap: buffer until it is filled
            d.ooo[seq] = (data, p)
            if len(d.ooo) > MAX_OOO:                     # segment never captured: resynchronise
                first = min(d.ooo, key=lambda s: (s - d.next_seq) & M32)
                d.framer._lose_sync()
                d.next_seq = first
                self._drain(d, from_client, t.stream)
            return
        self._push(d, data, p, from_client, t.stream)
        self._drain(d, from_client, t.stream)

    def _drain(self, d, from_client, sid):
        while d.next_seq in d.ooo:
            data, p = d.ooo.pop(d.next_seq)
            self._push(d, data, p, from_client, sid)
        # discard segments that are now entirely old
        for s in [s for s in d.ooo if ((s - d.next_seq) & M32) >= 0x80000000]:
            data, p = d.ooo.pop(s)
            skip = (d.next_seq - s) & M32
            if skip < len(data):
                self._push(d, data[skip:], p, from_client, sid)

    def _push(self, d, data, p, from_client, sid):
        d.next_seq = (d.next_seq + len(data)) & M32
        if d.framer.proto is None:
            other = self.dirs.get((sid, not from_client))
            if other is not None and other.framer.proto == "h2":   # server side of h2c has no preface
                d.framer.proto, d.framer.preface_done = "h2", True
        for kind, msg, start, end in d.framer.feed(data, p):
            self.stats["messages"] += 1
            self._emit(kind, msg, start, end, from_client, sid, d)
        if d.framer.buf and d.framer.proto not in (None, "raw") and p.protocol == "TCP":
            p.info += " [TCP segment of a reassembled PDU]"

    # ------------------------------------------------------------------------
    def _emit(self, kind, msg, start, end, from_client, sid, d):
        if end is None:
            return
        if kind == "tls":
            sess = self.tls.get(sid)
            if sess is None:
                sess = self.tls[sid] = TLSSession(self.keylog)
            if msg[0] == 22 and sess.dirs[from_client].after_ccs:
                # encrypted handshake (Finished): record only, never parse as a plaintext hello
                rec = {"records": [{"type": 22, "version": tls.VERSIONS.get(int.from_bytes(msg[1:3], "big"), "?")}],
                       "handshakes": []}
            else:
                rec = tls.parse(msg)
            if rec:
                _merge_tls(end, rec)
                sess.observe(rec)
                for inner, body in sess.record(msg[0], int.from_bytes(msg[1:3], "big"), msg[5:], from_client):
                    self.stats["decrypted_records"] += 1
                    self._decrypted(inner, body, end, from_client, sid, d, sess)
        elif kind == "bgp":
            m = bgp.parse(msg)
            if m:
                cur = end.layers.setdefault("bgp", {"messages": []})
                cur["messages"] += m["messages"]
                _label(end, "BGP", bgp.info(cur))
        elif kind == "dns":
            m = dns.parse(msg[2:])
            if m:
                end.layers["dns"] = m
                _label(end, "DNS", dns.info(m))
        elif kind == "http":
            hdr_pkt = end
            m = http.parse(msg + bytes(d.framer.buf[:200]) if d.framer.body else msg)
            if m:
                hdr_pkt.layers["http"] = m
                _label(hdr_pkt, "HTTP", http.info(m))
        elif kind in ("h2", "h2-preface"):
            self._h2(msg, end, d.framer, kind)

    def _decrypted(self, inner, body, pkt, from_client, sid, d, sess):
        pkt.tags.append("decrypted") if "decrypted" not in pkt.tags else None
        if inner == 21 and len(body) >= 2:
            cur = pkt.layers.setdefault("tls", {"records": [], "handshakes": []})
            cur["alert"] = {"level": "fatal" if body[0] == 2 else "warning",
                            "description": tls.ALERTS.get(body[1], str(body[1])), "code": body[1], "encrypted": True}
            _label(pkt, "TLS", tls.info(cur))
            return
        if inner != 23:
            return
        if d.plain is None:
            proto = "h2" if sess.alpn == "h2" else None
            d.plain = Framer((), proto)
        for kind, msg, start, end in d.plain.feed(body, pkt):
            if kind == "http":
                m = http.parse(msg + bytes(d.plain.buf[:200]) if d.plain.body else msg)
                if m:
                    m["tls"] = True
                    if m.get("url", "").startswith("http://"):
                        m["url"] = "https://" + m["url"][7:]
                    end.layers["http"] = m
                    _label(end, "HTTP", http.info(m) + " [decrypted TLS]")
            elif kind in ("h2", "h2-preface"):
                self._h2(msg, end, d.plain, kind, tls_=True)

    def _h2(self, msg, pkt, framer, kind, tls_=False):
        cur = pkt.layers.setdefault("http2", {"frames": [], "tls": tls_})
        if kind == "h2-preface":
            cur["preface"] = True
        else:
            if framer.h2dec is None:
                framer.h2dec = http2.HeaderDecoder()
            cur["frames"].append(http2.parse_frame(msg, framer.h2dec))
        _label(pkt, "HTTP2", http2.info(cur["frames"]) if cur["frames"] else "HTTP/2 connection preface")

    def sessions_summary(self) -> dict:
        return {sid: {"status": s.status, "records": s.decrypted_records, "alpn": s.alpn,
                      "cipher": s.cipher} for sid, s in self.tls.items()}


def _reset_app(p) -> None:
    had = False
    for k in APP_KEYS:
        if p.layers.pop(k, None) is not None:
            had = True
    if had or p.protocol != "TCP":
        t = p.tcp
        p.protocol = "TCP"
        p.info = f"{p.sport} → {p.dport} [{t.flag_str()}] Seq={t.seq} Ack={t.ack} Win={t.window} Len={t.payload_len}"


def _label(p, proto: str, info: str) -> None:
    p.protocol = proto
    p.info = info


def _merge_tls(p, rec: dict) -> None:
    cur = p.layers.get("tls")
    if cur is None:
        p.layers["tls"] = rec
    else:
        cur["records"] += rec["records"]
        cur["handshakes"] += rec["handshakes"]
        for k in ("client_hello", "server_hello", "alert"):
            if k in rec:
                cur[k] = rec[k]
    if "http" not in p.layers and "http2" not in p.layers:   # decrypted application layer wins the label
        _label(p, "TLS", tls.info(p.layers["tls"]))
