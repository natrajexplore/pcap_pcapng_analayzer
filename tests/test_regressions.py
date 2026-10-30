"""Regression tests for the bugs found in the 1.1.0 code review."""
import os
import tempfile
import unittest

try:
    import tomllib               # Python 3.11+
except ImportError:              # pragma: no cover
    tomllib = None

from packetlens import synth
from packetlens.analyzer import analyze_file
from packetlens.reader import write_pcap

TMP = tempfile.mkdtemp(prefix="packetlens-reg-")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _conv(g, sport=42000, **kw):
    return synth.Conv(g, "00:00:00:00:00:01", "00:00:00:00:00:02", "10.8.0.1", "10.8.0.2", sport, 80, **kw)


def _analyze(g, name, unsorted=False):
    p = os.path.join(TMP, name)
    if unsorted:
        write_pcap(p, g.frames)          # Gen.save sorts by time; keep capture order as built
    else:
        g.save(p)
    return analyze_file(p)


class RegressionTests(unittest.TestCase):
    @unittest.skipIf(tomllib is None, "tomllib needs Python 3.11+")
    def test_pyproject_metadata_not_in_extras(self):
        with open(os.path.join(ROOT, "pyproject.toml"), "rb") as fh:
            proj = tomllib.load(fh)["project"]
        self.assertIn("keywords", proj)
        self.assertIn("classifiers", proj)
        self.assertEqual(set(proj["optional-dependencies"]), {"full", "dev"})

    def test_truncated_ipv4_header_is_malformed_not_fatal(self):
        g = synth.Gen()
        _conv(g).handshake(0.0)
        ts, frame = g.frames[0]
        g.frames.append((ts + 1, frame[:14 + 14]))       # snaplen cut inside the IPv4 addresses
        a = _analyze(g, "trunc.pcap", unsorted=True)
        self.assertIn("malformed", a.packets[-1].tags)

    def test_reordered_segments_flag_out_of_order(self):
        g = synth.Gen()
        c = _conv(g)
        t = c.handshake(0.0)
        s0 = c.cseq
        c.c(t + 0.010, 0x18, b"B" * 100, seq=s0 + 100)
        c.c(t + 0.011, 0x18, b"A" * 100, seq=s0)          # 1 ms later: reordering, not an RTO retransmission
        c.cseq = s0 + 200
        a = _analyze(g, "ooo.pcapng")
        self.assertEqual(a.packets[-1].tcp.analysis, ["out_of_order"])
        self.assertNotIn("tcp_retransmissions", {f.id for f in a.findings})

    def test_timeline_survives_backwards_timestamps(self):
        g = synth.Gen()
        for t in (100.0, 88.0, 110.0):
            g.udp(t, "00:00:00:00:00:01", "00:00:00:00:00:02", "10.8.0.1", "10.8.0.2", 1, 2, b"x")
        a = _analyze(g, "backwards.pcap", unsorted=True)
        st = a.stats()
        self.assertEqual(sum(b["pkts"] for b in st["timeline"]), 3)
        self.assertAlmostEqual(st["duration"], 22.0)

    def test_handshake_without_mss_does_not_abort_tcp_expert(self):
        g = synth.Gen()
        c = _conv(g)
        c.c(0.0, 0x02, win=64240)                          # no options at all on either side
        c.s(0.02, 0x12, win=65160)
        c.c(0.0205, 0x10)
        a = _analyze(g, "nomss.pcapng")
        self.assertFalse([w for w in a.warnings if "tcp failed" in w], a.warnings)
        self.assertIn("tcp_capture_point", {f.id for f in a.findings})

    def test_head_response_does_not_swallow_next_response(self):
        g = synth.Gen()
        c = _conv(g)
        t = c.handshake(0.0)
        c.c(t + 0.01, 0x18, synth.http_req("HEAD", "h.example", "/a"))
        c.s(t + 0.02, 0x18, b"HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n")
        c.c(t + 0.03, 0x18, synth.http_req("GET", "h.example", "/b"))
        c.s(t + 0.04, 0x18, synth.http_resp(503, "Service Unavailable"))
        a = _analyze(g, "head.pcapng")
        self.assertEqual([(x["method"], x["status"]) for x in a.http_transactions], [("HEAD", 200), ("GET", 503)])
        self.assertIn("http_server_errors", {f.id for f in a.findings})

    def test_server_think_time_gap_attribution(self):
        g = synth.Gen()
        c = _conv(g)
        t = c.handshake(0.0)
        c.c(t + 0.01, 0x18, synth.http_req("GET", "slow.example", "/"))
        c.s(t + 0.02, 0x10)
        c.s(t + 3.02, 0x18, synth.http_resp(200, "OK"))
        a = _analyze(g, "think.pcapng")
        (gap,) = a.flows.streams[0].gaps
        self.assertTrue(gap["cause"].startswith("server:"), gap["cause"])

    def test_no_decryption_status_without_keylog(self):
        g = synth.Gen()
        c = _conv(g, sport=42001)
        c.sport = 443
        t = c.handshake(0.0)
        c.c(t + 0.01, 0x18, synth.client_hello("x.example"))
        c.s(t + 0.02, 0x18, synth.server_hello())
        a = _analyze(g, "nokeys.pcapng")
        self.assertTrue(a.tls_sessions)
        self.assertIsNone(a.tls_sessions[0]["decryption"])


if __name__ == "__main__":
    unittest.main()
