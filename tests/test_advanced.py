"""Tests for reassembly, TLS decryption, HTTP/2, FHRP, IS-IS, multi-point comparison and live capture."""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from packetlens import synth
from packetlens.analyzer import analyze_file
from packetlens.compare import annotate, compare
from packetlens.protocols import http2
from packetlens.tlsdecrypt import HAVE_CRYPTO, hkdf_expand_label, prf12

TMP = tempfile.mkdtemp(prefix="packetlens-adv-")
DEMO = os.path.join(TMP, "demo.pcapng")
synth.write_demo(DEMO)
A = analyze_file(DEMO)
IDS = {f.id for f in A.findings}
RC = {r.id for r in A.root_causes}


def _conv(g, sip="10.9.0.1", dip="10.9.0.2", sport=41000, dport=80):
    return synth.Conv(g, "00:00:00:00:00:01", "00:00:00:00:00:02", sip, dip, sport, dport)


class KnownAnswerTests(unittest.TestCase):
    def test_tls13_hkdf_expand_label_rfc8448(self):
        sec = bytes.fromhex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
        self.assertEqual(hkdf_expand_label("sha256", sec, "key", b"", 16).hex(), "3fce516009c21727d0f2e4e86ee403bc")
        self.assertEqual(hkdf_expand_label("sha256", sec, "iv", b"", 12).hex(), "5d313eb2671276ee13000b30")

    def test_tls12_prf_vector(self):
        out = prf12("sha256", bytes.fromhex("9bbe436ba940f017b17652849a71db35"), b"test label",
                    bytes.fromhex("a0ba9f936cda311827a6f796ffd5198c"), 16)
        self.assertEqual(out.hex(), "e3f229ba727be17b8d122620557cd453")


class ReassemblyTests(unittest.TestCase):
    def test_http_header_split_and_out_of_order(self):
        g = synth.Gen()
        c = _conv(g)
        t = c.handshake(0.0)
        req = synth.http_req("GET", "split.example", "/a/very/long/path?x=1")
        c.c(t + 0.001, 0x18, req[:15])
        c.c(t + 0.002, 0x18, req[15:])
        resp = synth.http_resp(404, "Not Found", b"n" * 3000)
        s0 = c.sseq
        c.s(t + 0.010, 0x10, resp[:1400])
        c.s(t + 0.011, 0x18, resp[2800:], seq=s0 + 2800)     # arrives before the middle segment
        c.s(t + 0.012, 0x10, resp[1400:2800], seq=s0 + 1400)
        c.sseq = s0 + len(resp)
        c.c(t + 0.02, 0x10)
        p = os.path.join(TMP, "split.pcapng")
        g.save(p)
        a = analyze_file(p)
        (tx,) = a.http_transactions
        self.assertEqual((tx["method"], tx["url"], tx["status"]), ("GET", "http://split.example/a/very/long/path?x=1", 404))

    def test_bgp_message_split_across_segments(self):
        g = synth.Gen()
        c = _conv(g, "192.0.2.2", "192.0.2.1", 51000, 179)
        t = c.handshake(0.0)
        upd = synth.bgp_update(["172.20.0.0/16", "172.21.0.0/16"], as_path=[65001], next_hop="192.0.2.1")
        msg = synth.bgp_open(65002, 90, "2.2.2.2") + upd
        c.c(t + 0.001, 0x18, msg[:25])
        c.c(t + 0.002, 0x18, msg[25:])
        p = os.path.join(TMP, "bgp.pcapng")
        g.save(p)
        a = analyze_file(p)
        types = [m["type"] for q in a.packets for m in q.layers.get("bgp", {}).get("messages", [])]
        self.assertEqual(types, ["OPEN", "UPDATE"])

    def test_payload_dropped_by_default(self):
        self.assertTrue(all(not p.payload for p in A.packets))

    def test_sliced_capture_falls_back_to_per_packet(self):
        g = synth.Gen()
        c = _conv(g)
        t = c.handshake(0.0)
        c.c(t + 0.001, 0x18, synth.http_req("GET", "x.example", "/"))
        c.s(t + 0.01, 0x18, synth.http_resp(200, "OK", b"y" * 1000))
        frames = [(ts, data[:96]) for ts, data in sorted(g.frames)]
        p = os.path.join(TMP, "sliced.pcap")
        from packetlens.reader import write_pcap
        write_pcap(p, frames)
        a = analyze_file(p)
        self.assertTrue(any("sliced" in w for w in a.warnings))
        self.assertEqual(len(a.http_transactions), 1)


class FragmentTests(unittest.TestCase):
    @staticmethod
    def _v4_frags(g, t, src, dst, ident, l4, sizes, drop=()):
        import struct as st
        from packetlens.synth import _cks, _ip
        off = 0
        for i, n in enumerate(sizes):
            chunk = l4[off:off + n]
            more = off + n < len(l4)
            hdr = st.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), ident, (0x2000 if more else 0) | (off // 8), 64, 17, 0,
                          _ip(src), _ip(dst))
            hdr = hdr[:10] + st.pack("!H", _cks(hdr)) + hdr[12:]
            if i not in drop:
                g.eth(t + (0.001 * (len(sizes) - i)), "00:00:00:00:00:02", "00:00:00:00:00:01", 0x0800, hdr + chunk)
            off += n

    def test_ipv4_and_ipv6_reassembly(self):
        import struct as st
        names = ["10.9.%d.%d" % (i // 250, i % 250) for i in range(120)]
        dns = synth.dns_msg(0x4242, "big.example", response=True, answers=names)
        l4 = st.pack("!HHHH", 53, 40000, 8 + len(dns), 0) + dns
        g = synth.Gen()
        g.udp(0.0, "00:00:00:00:00:01", "00:00:00:00:00:02", "10.9.0.1", "10.9.0.53", 40000, 53, synth.dns_msg(0x4242, "big.example"))
        sizes = [800, 800, len(l4) - 1600]
        self._v4_frags(g, 0.01, "10.9.0.53", "10.9.0.1", 77, l4, sizes)                 # delivered in reverse order
        self._v4_frags(g, 0.5, "10.9.0.53", "10.9.0.1", 78, l4, sizes, drop=(1,))       # middle fragment lost
        # IPv6: two fragments of a UDP datagram
        src6, dst6 = socket.inet_pton(socket.AF_INET6, "2001:db8::53"), socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        u6 = st.pack("!HHHH", 53, 40001, 8 + len(dns), 0) + dns
        for i, (o, chunk) in enumerate(((0, u6[:1232]), (1232, u6[1232:]))):
            fh = st.pack("!BBHI", 17, 0, o | (1 if o == 0 else 0), 0x99)
            ip6 = st.pack("!IHBB", 0x60000000, 8 + len(chunk), 44, 64) + src6 + dst6 + fh + chunk
            g.eth(1.0 + i * 0.001, "00:00:00:00:00:02", "00:00:00:00:00:01", 0x86DD, ip6)
        p = os.path.join(TMP, "frag.pcapng")
        g.save(p)
        a = analyze_file(p)
        answers = [q for q in a.packets if q.layers.get("dns", {}).get("qr")]
        self.assertEqual(len(answers), 2)                       # one IPv4 + one IPv6 reassembled response
        self.assertTrue(all(len(q.layers["dns"]["answers"]) == 120 for q in answers))
        self.assertEqual(a.frag_stats, {"reassembled": 2, "incomplete": 1})
        f = next(f for f in a.findings if f.id == "ip_fragmentation")
        self.assertIn("INCOMPLETE", f.summary)
        tx = a.dns_transactions[0]
        self.assertEqual(tx["rcode"], "NOERROR")


class HTTP2Tests(unittest.TestCase):
    @unittest.skipUnless(http2.HAVE_HPACK, "hpack not installed")
    def test_h2_transactions_and_goaway(self):
        tx = [t for t in A.http_transactions if t["version"] == "HTTP/2"]
        self.assertEqual({(t["uri"], t["status"]) for t in tx}, {("/api/items", 200), ("/api/checkout", 503)})
        self.assertIn("http2_goaway", IDS)

    def test_frame_parser(self):
        goaway = (8).to_bytes(3, "big") + bytes([7, 0]) + b"\x00\x00\x00\x00" + (5).to_bytes(4, "big") + (11).to_bytes(4, "big")
        f = http2.parse_frame(goaway)
        self.assertEqual((f["type"], f["last_stream"], f["error"]), ("GOAWAY", 5, "ENHANCE_YOUR_CALM"))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class TLSDecryptionTests(unittest.TestCase):
    def test_embedded_keys_decrypt_tls12_and_tls13(self):
        https = {(t["url"], t["status"]) for t in A.http_transactions if t["url"].startswith("https://")}
        self.assertIn(("https://api.secure.example/v2/orders?id=42", 502), https)
        self.assertIn(("https://shop.secure.example/cart/checkout", 200), https)
        self.assertEqual(sum(1 for s in A.tls_decrypt.values() if s["records"]), 2)

    def test_tls_credentials_not_reported_as_cleartext(self):
        f = [f for f in A.findings if f.id == "http_cleartext_credentials"]
        self.assertFalse(any("secure.example" in e for x in f for e in x.entities))

    def test_wrong_keys_warn(self):
        p = os.path.join(TMP, "tls-nokeys.pcapng")
        g = synth.Gen()
        synth.build_tls_decryptable(g)
        g.save(p)
        kl = os.path.join(TMP, "wrong.keys")
        with open(kl, "w") as fh:
            fh.write("CLIENT_RANDOM " + "00" * 32 + " " + "11" * 48 + "\n")
        a = analyze_file(p, keylog_path=kl)
        self.assertTrue(any("no TLS session could be decrypted" in w for w in a.warnings))
        self.assertFalse([t for t in a.http_transactions if t["url"].startswith("https://")])

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("openssl")
                         and hasattr(socket, "AF_PACKET"), "needs root, openssl and AF_PACKET")
    def test_real_openssl_traffic_on_loopback(self):
        """Capture genuine TLS 1.2 + 1.3 HTTPS from Python/OpenSSL and decrypt it with SSLKEYLOGFILE."""
        import http.server
        import ssl
        import urllib.request
        from packetlens import live
        cert, key, kl = (os.path.join(TMP, n) for n in ("c.pem", "k.pem", "keys.log"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                body = b"x" * (20000 if self.path == "/big" else 10)
                self.send_response(503 if self.path == "/fail" else 200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        frames = []
        cap = threading.Thread(target=lambda: frames.extend(live.capture("lo", duration=3.0)))
        cap.start()
        time.sleep(0.4)
        ports = []
        for maxv in (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2):
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(cert, key)
            sctx.maximum_version = maxv
            srv = http.server.HTTPServer(("127.0.0.1", 0), H)
            srv.socket = sctx.wrap_socket(srv.socket, server_side=True)
            port = srv.server_address[1]
            ports.append(port)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            cctx = ssl.create_default_context()
            cctx.check_hostname, cctx.verify_mode, cctx.keylog_filename = False, ssl.CERT_NONE, kl
            for path in ("/", "/big", "/fail"):
                try:
                    urllib.request.urlopen(f"https://127.0.0.1:{port}{path}", context=cctx).read()
                except Exception:
                    pass
            srv.shutdown()
            srv.server_close()
        cap.join()
        p = os.path.join(TMP, "real-tls.pcapng")
        live.save(frames, p)
        a = analyze_file(p, keylog_path=kl)
        got = {(t["url"], t["status"]) for t in a.http_transactions}
        for port in ports:
            self.assertIn((f"https://127.0.0.1:{port}/big", 200), got)
            self.assertIn((f"https://127.0.0.1:{port}/fail", 503), got)
        self.assertIn("http_server_errors", {f.id for f in a.findings})


class FHRPandISISTests(unittest.TestCase):
    def test_fhrp(self):
        for fid in ("fhrp_split_brain", "fhrp_auth_mismatch", "fhrp_flap", "fhrp_weak_auth"):
            self.assertIn(fid, IDS)
        self.assertIn("fhrp_split_brain", RC)

    def test_isis(self):
        for fid in ("isis_mtu_mismatch", "isis_circuit_mismatch", "isis_one_way"):
            self.assertIn(fid, IDS)
        self.assertIn("isis_adjacency", RC)
        # routers on different VLANs are never compared
        self.assertFalse([f for f in A.findings if f.id.startswith("isis_") and "0000.0000.0001" in f.summary
                          and "0000.0000.0003" in f.summary])


class CompareTests(unittest.TestCase):
    def _pair(self, drop=(), offset=100.0, owd=0.010):
        """Server-side capture sees everything; client-side capture misses ``drop`` data segments."""
        gs, gc = synth.Gen(), synth.Gen()
        cs, cc = _conv(gs, dport=80), _conv(gc, dport=80)
        # SYN leaves the client at t=0: seen at the client capture at 0 (+offset), at the server capture at owd
        cc.handshake(0.0 + offset, rtt_s=2 * owd, rtt_c=0.0)
        cs.handshake(owd, rtt_s=0.0, rtt_c=2 * owd)
        # data from server: seen at server capture at t, at client capture at t+owd (+offset)
        for i in range(10):
            ts = 1.0 + i * 0.01
            cs.s(ts, 0x10, b"d" * 1000)
            cc.s(ts + owd + offset, 0x10, b"d" * 1000, capture=i not in drop)
            cc.c(ts + owd + offset + 0.0001, 0x10)
            cs.c(ts + 2 * owd + 0.0001, 0x10)
        ps, pc = os.path.join(TMP, "srv.pcapng"), os.path.join(TMP, "cli.pcapng")
        gs.save(ps)
        gc.save(pc)
        return analyze_file(pc), analyze_file(ps)

    def test_loss_between_points_and_clock_offset(self):
        a, b = self._pair(drop=(3, 7))
        r = compare(a, b)
        self.assertEqual(r["lost_between"], 2)
        self.assertAlmostEqual(r["clock_offset_s"], -100.0, places=2)
        self.assertAlmostEqual(r["one_way_delay_s"], 0.010, places=3)
        annotate(a, r)
        self.assertEqual(a.root_causes[0].id, "loss_between_points")

    def test_no_loss(self):
        a, b = self._pair(drop=())
        r = compare(a, b)
        self.assertEqual(r["lost_between"], 0)


@unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and hasattr(socket, "AF_PACKET"), "needs root")
class LiveCaptureTests(unittest.TestCase):
    def test_capture_loopback_udp(self):
        from packetlens import live
        frames = []
        th = threading.Thread(target=lambda: frames.extend(live.capture("lo", duration=1.5, port=45999)))
        th.start()
        time.sleep(0.3)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(5):
            s.sendto(b"ping", ("127.0.0.1", 45999))
        s.close()
        th.join()
        self.assertEqual(len(frames), 5)          # loopback duplicates suppressed, port filter applied
        p = os.path.join(TMP, "live.pcapng")
        live.save(frames, p)
        a = analyze_file(p)
        self.assertEqual({(q.dport, q.protocol) for q in a.packets}, {(45999, "UDP")})


if __name__ == "__main__":
    sys.exit(unittest.main())
