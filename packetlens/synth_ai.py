"""Synthetic AI-era traffic for the demo capture and the test-suite.

AI / LLM services over TLS (streaming responses, slow first token, mid-stream stall, large upload), consumer
assistants, self-hosted Ollama and an OpenAI-compatible server over cleartext HTTP, MCP JSON-RPC, QUIC (real
encrypted Initials when ``cryptography`` is installed, blocked QUIC with TCP fallback, version negotiation),
WireGuard (healthy and unanswered), RoCEv2 with PSN gaps / NAK / CNP / ECN, PFC pause storm and gRPC inference
errors (needs ``hpack``). Payload bytes are filler: only structure, sizes and timing are real.
"""
from __future__ import annotations

import json
import struct

from .protocols import quic
from .synth import Conv, dns_msg
from .synth_crypto import _send, client_hello, server_hello13

GW = "00:00:5e:00:53:01"
DNS = "10.72.0.53"
APPDATA = lambda n, fill=b"\x96": struct.pack("!BHH", 23, 0x0303, n) + fill * n  # noqa: E731


def _dns(g, t, client, name, ip, tid):
    g.udp(t, "00:50:56:0b:00:01", GW, client, DNS, 40000 + tid % 1000, 53, dns_msg(tid, name))
    g.udp(t + 0.008, GW, "00:50:56:0b:00:01", DNS, client, 53, 40000 + tid % 1000, dns_msg(tid, name, response=True, answers=[ip]))


def _llm_session(g, t, client, cport, server, sni, ttft, chunks=40, gap=0.05, stall_at=None, stall=0.0, upload=900, mss=1448):
    """TLS 1.3 with a streamed response: request -> wait ttft -> chunks small records (stall once if asked)."""
    c = Conv(g, "00:50:56:0b:00:10", GW, client, server, cport, 443, ttl_s=54)
    t = c.handshake(t, rtt_s=0.012)
    t = _send(c, "c", t + 0.001, client_hello(sni, [0x11EC, 0x1D], [(0x11EC, 1216), (0x1D, 32)]))
    c.s(t + 0.012, 0x10)
    t = _send(c, "s", t + 0.013, server_hello13(0x11EC, 1120)) + 0.001
    req = APPDATA(min(upload, 16000))
    body = req * max(1, upload // len(req))
    t = _send(c, "c", t, body, mss=mss)
    c.s(t + 0.010, 0x10)
    t += ttft
    for i in range(chunks):
        if stall_at is not None and i == stall_at:
            t += stall
        c.s(t, 0x18, APPDATA(60 + i % 7 * 10, b"\x95"))
        if i % 4 == 3:
            c.c(t + 0.0005, 0x10)
        t += gap
    c.close(t + 0.1)
    return t


def _http_stream(g, t, client, cport, server, sport, request: bytes, head: bytes, events, gap=0.04):
    c = Conv(g, "00:50:56:0b:00:20", "00:50:56:0b:00:21", client, server, cport, sport, ttl_s=64)
    t = c.handshake(t, rtt_s=0.0008)
    c.c(t + 0.001, 0x18, request)
    c.s(t + 0.002, 0x10)
    t += 0.35
    c.s(t, 0x18, head)
    for e in events:
        t += gap
        c.s(t, 0x18, e)
    c.c(t + 0.001, 0x10)
    c.close(t + 0.05)


def _chunk(b: bytes) -> bytes:
    return f"{len(b):x}\r\n".encode() + b + b"\r\n"


def build_ai(g, t0=500.0):
    for i, (cl, name, ip) in enumerate((("10.72.0.10", "api.openai.com", "162.159.140.245"),
                                        ("10.72.0.10", "api.anthropic.com", "160.79.104.10"),
                                        ("10.72.0.20", "claude.ai", "160.79.104.20"),
                                        ("10.72.0.21", "chatgpt.com", "104.18.32.47"),
                                        ("10.72.0.22", "api.githubcopilot.com", "140.82.113.22"))):
        _dns(g, t0 + i * 0.1, cl, name, ip, 0x5000 + i)
    _llm_session(g, t0 + 1, "10.72.0.10", 53001, "162.159.140.245", "api.openai.com", ttft=0.6)
    _llm_session(g, t0 + 4, "10.72.0.10", 53002, "160.79.104.10", "api.anthropic.com", ttft=7.5, stall_at=20, stall=6.0)
    _llm_session(g, t0 + 25, "10.72.0.20", 53003, "160.79.104.20", "claude.ai", ttft=1.2, upload=2_400_000, mss=16000)
    _llm_session(g, t0 + 30, "10.72.0.21", 53004, "104.18.32.47", "chatgpt.com", ttft=0.9, chunks=20)
    _llm_session(g, t0 + 33, "10.72.0.22", 53005, "140.82.113.22", "api.githubcopilot.com", ttft=0.4, chunks=12)
    # self-hosted Ollama, no authentication, two clients; NDJSON streaming
    for k, cl in enumerate(("10.72.0.30", "10.72.0.31")):
        body = json.dumps({"model": "llama3.1", "messages": [{"role": "user", "content": "summarise the incident"}], "stream": True}).encode()
        req = (b"POST /api/chat HTTP/1.1\r\nHost: 10.72.5.5:11434\r\nContent-Type: application/json\r\nContent-Length: "
               + str(len(body)).encode() + b"\r\n\r\n" + body)
        head = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\n\r\n"
        ev = [_chunk(json.dumps({"message": {"content": "tok%d" % i}, "done": False}).encode() + b"\n") for i in range(12)] + [b"0\r\n\r\n"]
        _http_stream(g, t0 + 36 + k, cl, 53010 + k, "10.72.5.5", 11434, req, head, ev)
    # OpenAI-compatible vLLM server over plain HTTP with a bearer key (SSE)
    body = json.dumps({"model": "mistral-7b", "stream": True, "messages": [{"role": "user", "content": "hi"}]}).encode()
    req = (b"POST /v1/chat/completions HTTP/1.1\r\nHost: llm.lab.internal:8000\r\nAuthorization: Bearer sk-lab-0123456789abcdef\r\n"
           b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
    ev = [_chunk(b'data: {"choices":[{"delta":{"content":"w%d"}}]}\n\n' % i) for i in range(15)] + [_chunk(b"data: [DONE]\n\n"), b"0\r\n\r\n"]
    _http_stream(g, t0 + 39, "10.72.0.32", 53020, "10.72.5.6", 8000, req, head, ev)
    # LLM gateway answering 429 (rate limited)
    req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: gateway.lab.internal:4000\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
    _http_stream(g, t0 + 40, "10.72.0.32", 53021, "10.72.5.8", 4000, req,
                 b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 20\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", [])
    # MCP over plain HTTP: initialize, tools/list, tools/call
    c = Conv(g, "00:50:56:0b:00:30", "00:50:56:0b:00:31", "10.72.0.33", "10.72.5.7", 53030, 8931)
    t = c.handshake(t0 + 41, rtt_s=0.0006)
    for i, (method, params) in enumerate((("initialize", {"protocolVersion": "2025-06-18"}), ("tools/list", {}),
                                          ("tools/call", {"name": "query_database", "arguments": {"sql": "select 1"}}))):
        body = json.dumps({"jsonrpc": "2.0", "id": i + 1, "method": method, "params": params}).encode()
        c.c(t + 0.001, 0x18, b"POST /mcp HTTP/1.1\r\nHost: tools.lab.internal:8931\r\nContent-Type: application/json\r\n"
                             b"Accept: application/json, text/event-stream\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        rb = json.dumps({"jsonrpc": "2.0", "id": i + 1, "result": {}}).encode()
        c.s(t + 0.02, 0x18, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(rb)).encode() + b"\r\n\r\n" + rb)
        t += 0.05
    c.close(t + 0.05)


# ---------------------------------------------------------------- QUIC ----
def _varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack("!H", 0x4000 | v)
    return struct.pack("!I", 0x80000000 | v)


def quic_initial(odcid: bytes, dcid: bytes, scid: bytes, pn: int, frames: bytes, server: bool, version=quic.V1, pad_to=1200) -> bytes:
    """Encrypted Initial packet (RFC 9001 5); without ``cryptography`` the payload is left as filler."""
    ptype = 0 if version == quic.V1 else 1
    pn_len = 2
    if not server:                                       # clients pad Initials to >= 1200 bytes (PADDING frames)
        overhead = 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1 + 2 + pn_len + 16
        frames += b"\x00" * max(0, pad_to - overhead - len(frames))
    length = pn_len + len(frames) + 16
    first = 0xC0 | (ptype << 4) | (pn_len - 1)
    header = bytes([first]) + struct.pack("!I", version) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + \
        _varint(0) + _varint(length)                    # empty token, then the Length field
    pn_bytes = pn.to_bytes(pn_len, "big")
    if not quic.HAVE_CRYPTO:
        return header + pn_bytes + b"\x5a" * (len(frames) + 16)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key, iv, hp = quic._keys(version, odcid, server)
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct = AESGCM(key).encrypt(nonce, frames, header + pn_bytes)
    sample = ct[4 - pn_len:4 - pn_len + 16]
    enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
    mask = enc.update(sample) + enc.finalize()
    first_p = bytes([header[0] ^ (mask[0] & 0x0F)])
    pn_p = bytes(b ^ m for b, m in zip(pn_bytes, mask[1:1 + pn_len]))
    return first_p + header[1:] + pn_p + ct


def _crypto_frame(off: int, data: bytes) -> bytes:
    return b"\x06" + _varint(off) + _varint(len(data)) + data


def build_quic(g, t0=545.0):
    cm, sm = "00:50:56:0b:01:01", GW
    odcid, scid, srv_cid = bytes.fromhex("8394c8f03e515708"), bytes.fromhex("c1c2c3c4"), bytes.fromhex("5e5e5e5e5e5e5e5e")
    ch = client_hello("gemini.google.com", [0x11EC, 0x1D, 0x17], [(0x11EC, 1216), (0x1D, 32)])[5:]   # handshake msg, no record header
    sh = server_hello13(0x11EC, 1120, hrr=False)
    sh = sh[5:5 + int.from_bytes(sh[3:5], "big")]
    cl, sv = "10.72.0.40", "142.250.180.14"
    half = 1100
    g.udp(t0, cm, sm, cl, sv, 54001, 443, quic_initial(odcid, odcid, scid, 0, _crypto_frame(0, ch[:half]), False))
    g.udp(t0 + 0.0002, cm, sm, cl, sv, 54001, 443, quic_initial(odcid, odcid, scid, 1, _crypto_frame(half, ch[half:]), False))
    g.udp(t0 + 0.018, sm, cm, sv, cl, 443, 54001, quic_initial(odcid, scid, srv_cid, 0, b"\x02\x01\x00\x00\x00" + _crypto_frame(0, sh), True))
    for k in range(6):                                  # 1-RTT short-header packets
        g.udp(t0 + 0.04 + k * 0.01, sm if k % 2 else cm, cm if k % 2 else sm, sv if k % 2 else cl, cl if k % 2 else sv,
              443 if k % 2 else 54001, 54001 if k % 2 else 443, b"\x41" + (scid if k % 2 else srv_cid) + b"\x77" * 200)
    # UDP/443 blocked: three Initials, nothing back, then TCP/TLS to the same server
    od2 = bytes.fromhex("0102030405060708")
    for k, dt in enumerate((0.0, 0.3, 0.9)):
        g.udp(t0 + 2 + dt, cm, sm, cl, "203.0.113.99", 54002, 443, quic_initial(od2, od2, scid, k, _crypto_frame(0, ch[:half]), False))
    c = Conv(g, cm, sm, cl, "203.0.113.99", 54003, 443, ttl_s=50)
    t = c.handshake(t0 + 3.2, rtt_s=0.02)
    _send(c, "c", t + 0.001, client_hello("intranet-apps.example.net", [0x1D], [(0x1D, 32)]))
    c.s(t + 0.03, 0x18, server_hello13(0x1D, 32))
    c.close(t + 0.2)
    # version negotiation: draft-29 Initial, server lists v1 and v2
    od3 = bytes.fromhex("1112131415161718")
    g.udp(t0 + 4, cm, sm, cl, "198.51.100.44", 54004, 443, b"\xc0" + struct.pack("!I", 0xFF00001D) + b"\x08" + od3 + b"\x04" + scid +
          b"\x00" + _varint(1200) + b"\x00" * 1200)
    g.udp(t0 + 4.02, sm, cm, "198.51.100.44", cl, 443, 54004, b"\x80" + b"\x00\x00\x00\x00" + b"\x04" + scid + b"\x08" + od3 +
          struct.pack("!II", quic.V1, quic.V2))


# ----------------------------------------------------------- WireGuard ----
def build_wireguard(g, t0=552.0):
    a, b = "00:50:56:0b:02:01", "00:50:56:0b:02:02"
    init = lambda s: b"\x01\x00\x00\x00" + struct.pack("<I", s) + b"\x11" * 140  # noqa: E731
    g.udp(t0, a, b, "10.73.0.1", "10.73.0.2", 51820, 51820, init(0x1111))
    g.udp(t0 + 0.004, b, a, "10.73.0.2", "10.73.0.1", 51820, 51820, b"\x02\x00\x00\x00" + struct.pack("<II", 0x2222, 0x1111) + b"\x22" * 80)
    for k in range(10):
        src, dst, rcv = (("10.73.0.1", "10.73.0.2", 0x2222), ("10.73.0.2", "10.73.0.1", 0x1111))[k % 2]
        g.udp(t0 + 0.01 + k * 0.01, a if k % 2 == 0 else b, b if k % 2 == 0 else a, src, dst, 51820, 51820,
              b"\x04\x00\x00\x00" + struct.pack("<IQ", rcv, k // 2) + b"\x33" * 96)
    for k in range(4):                                  # wrong peer key: initiations every 5 s, never answered
        g.udp(t0 + 1 + k * 5, a, GW, "10.73.0.5", "198.51.100.7", 51820, 51820, init(0x5000 + k))


# --------------------------------------------------------- RoCE / PFC -----
def _bth(op, qp, psn, ack_req=False, pkey=0xFFFF):
    return struct.pack("!BBHB", op, 0x40, pkey, 0) + qp.to_bytes(3, "big") + bytes([0x80 if ack_req else 0]) + psn.to_bytes(3, "big")


def build_fabric(g, t0=575.0):
    m1, m2, sw = "b8:3f:d2:00:00:11", "b8:3f:d2:00:00:12", "00:1c:73:aa:bb:01"
    t = t0
    psns = [p for p in range(100, 140) if p not in (105, 106, 107)]
    for i, psn in enumerate(psns):                      # RDMA WRITE stream, three PSNs lost, then go-back-N from 105
        op = 0x06 if i == 0 else 0x08 if psn == 139 else 0x07
        ecn = 3 if 120 <= psn < 126 else 2               # switch marks CE under congestion, ECT(0) otherwise
        g.udp(t, m1, m2, "10.100.0.11", "10.100.0.12", 49152, 4791, _bth(op, 0x00012A, psn) + b"\x5d" * 1024 + b"\x00" * 4, tos=0x68 | ecn)
        t += 0.00001
        if psn == 108:
            g.udp(t, m2, m1, "10.100.0.12", "10.100.0.11", 49152, 4791,
                  _bth(0x11, 0x00034B, 105) + bytes([0x60]) + (7).to_bytes(3, "big") + b"\x00" * 4, tos=0x68 | 2)
            t += 0.00001
    for psn in range(105, 112):
        g.udp(t, m1, m2, "10.100.0.11", "10.100.0.12", 49152, 4791, _bth(0x07, 0x00012A, psn) + b"\x5d" * 1024 + b"\x00" * 4, tos=0x68 | 2)
        t += 0.00001
    for k in range(6):                                  # CNPs back to the sender (DCQCN)
        g.udp(t + k * 0.00005, m2, m1, "10.100.0.12", "10.100.0.11", 49152, 4791, _bth(0x81, 0x00012A, 0) + b"\x00" * 16 + b"\x00" * 4,
              tos=0x68 | 2)
    for psn in [p for p in range(10, 30) if p != 17]:   # second pair: not ECN-capable, one PSN lost
        g.udp(t0 + 0.5 + psn * 0.00001, "b8:3f:d2:00:00:13", "b8:3f:d2:00:00:14", "10.100.0.13", "10.100.0.14", 49153, 4791,
              _bth(0x04, 0x000777, psn) + b"\x5d" * 512 + b"\x00" * 4)
    for k in range(200):                                # PFC pause storm on priority 3 from a stuck NIC port
        g.eth(t0 + 1 + k * 0.004, sw, "01:80:c2:00:00:01", 0x8808, struct.pack("!HH", 0x0101, 0x0008) + struct.pack("!8H", 0, 0, 0, 0xFFFF, 0, 0, 0, 0)
              + b"\x00" * 26)


# ---------------------------------------------------------------- gRPC ----
def build_grpc(g, t0=580.0):
    try:
        import hpack
    except ImportError:
        return
    enc_c, enc_s = hpack.Encoder(), hpack.Encoder()
    fr = lambda t, fl, sid, body: len(body).to_bytes(3, "big") + bytes([t, fl]) + struct.pack("!I", sid) + body  # noqa: E731
    settings = fr(4, 0, 0, b"")
    req_h = enc_c.encode([(":method", "POST"), (":scheme", "http"), (":path", "/inference.GRPCInferenceService/ModelInfer"),
                          (":authority", "triton.lab.internal:8001"), ("content-type", "application/grpc"), ("te", "trailers")])
    msg = b"\x00" + struct.pack("!I", 64) + b"\x0a" * 64
    c2s = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + settings + fr(1, 0x04, 1, req_h) + fr(0, 0x01, 1, msg)
    resp_h = enc_s.encode([(":status", "200"), ("content-type", "application/grpc")])
    trailers = enc_s.encode([("grpc-status", "14"), ("grpc-message", "model llama3 is not ready")])
    s2c = settings + fr(4, 0x01, 0, b"") + fr(1, 0x04, 1, resp_h) + fr(1, 0x05, 1, trailers)
    c = Conv(g, "00:50:56:0b:03:01", "00:50:56:0b:03:02", "10.72.0.50", "10.72.5.9", 53050, 8001)
    t = c.handshake(t0, rtt_s=0.0005)
    c.c(t + 0.001, 0x18, c2s)
    c.s(t + 0.05, 0x18, s2c)
    c.c(t + 0.051, 0x10)
    c.close(t + 0.1)


def build_all(g) -> None:
    build_ai(g)
    build_quic(g)
    build_wireguard(g)
    build_fabric(g)
    build_grpc(g)
