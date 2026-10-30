import io
import json
import os
import re
import struct
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer

from packetlens import cli, synth
from packetlens.analyzer import Analysis, analyze_file
from packetlens.decode import dissect
from packetlens.flows import seq_gt, seq_lt
from packetlens.reader import CaptureFormatError, RawFrame, open_capture, write_pcap
from packetlens.report import html
from packetlens.web import make_handler

TMP = tempfile.mkdtemp(prefix="packetlens-test-")
DEMO = os.path.join(TMP, "demo.pcapng")
synth.write_demo(DEMO)
A = analyze_file(DEMO)
IDS = {f.id for f in A.findings}
RC = {r.id for r in A.root_causes}


class ReaderTests(unittest.TestCase):
    def test_pcapng_and_pcap_roundtrip(self):
        g = synth.build_demo()
        p1, p2 = os.path.join(TMP, "a.pcapng"), os.path.join(TMP, "a.pcap")
        n = g.save(p1, "pcapng")
        g.save(p2, "pcap")
        f1, f2 = list(open_capture(p1)), list(open_capture(p2))
        self.assertEqual(len(f1), n)
        self.assertEqual(len(f2), n)
        self.assertEqual(f1[10].data, f2[10].data)
        self.assertAlmostEqual(f1[10].ts, f2[10].ts, places=5)

    def test_nanosecond_pcap(self):
        buf = io.BytesIO()
        buf.write(struct.pack("<IHHiIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1))
        buf.write(struct.pack("<IIII", 10, 500_000_000, 4, 4) + b"abcd")
        buf.seek(0)
        (fr,) = list(open_capture(buf))
        self.assertAlmostEqual(fr.ts, 10.5)

    def test_rejects_garbage(self):
        with self.assertRaises(CaptureFormatError):
            list(open_capture(io.BytesIO(b"not a capture at all")))

    def test_truncated_file_is_tolerated(self):
        p = os.path.join(TMP, "trunc.pcap")
        write_pcap(p, [(1.0, b"\x00" * 60), (2.0, b"\x00" * 60)])
        with open(p, "rb") as fh:
            data = fh.read()[:-10]
        self.assertEqual(len(list(open_capture(io.BytesIO(data)))), 1)


class DecodeTests(unittest.TestCase):
    def test_protocols_decoded(self):
        protos = {p.protocol for p in A.packets}
        for name in ("TCP", "HTTP", "TLS", "DNS", "DHCP", "BGP", "OSPF", "EIGRP", "RIP", "ICMP", "ARP", "STP"):
            self.assertIn(name, protos)

    def test_linux_sll_and_raw_ip(self):
        eth = synth.build_demo().frames[0][1]   # Ethernet + IPv4 DNS query
        ip = eth[14:]
        raw = dissect(1, RawFrame(0.0, 101, ip, len(ip)))
        sll = dissect(2, RawFrame(0.0, 113, b"\x00" * 14 + b"\x08\x00" + ip, len(ip) + 16))
        for p in (raw, sll):
            self.assertEqual(p.protocol, "DNS")
            self.assertEqual(p.layers["dns"]["qname"], "www.example.com")

    def test_malformed_packet_does_not_raise(self):
        p = dissect(1, RawFrame(0.0, 1, b"\x00" * 13, 13))
        self.assertIn("malformed", p.tags)

    def test_seq_wraparound(self):
        self.assertTrue(seq_gt(5, 0xFFFFFFF0))
        self.assertTrue(seq_lt(0xFFFFFFF0, 5))

    def test_url_extraction(self):
        urls = {u["url"] for u in A.urls}
        self.assertIn("http://www.example.com/index.html", urls)
        self.assertIn("https://legacy.example.com/", urls)


class ExpertTests(unittest.TestCase):
    def test_tcp_analysis_flags(self):
        flags = {f for s in A.flows.streams for f in s.flags}
        for f in ("retransmission", "fast_retransmission", "duplicate_ack", "lost_segment", "zero_window",
                  "zero_window_probe", "window_update", "syn_retransmission"):
            self.assertIn(f, flags)

    def test_expected_findings(self):
        expected = {
            "tcp_retransmissions", "tcp_zero_window", "tcp_syn_no_response", "tcp_conn_refused", "tcp_slow_response",
            "icmp_admin_prohibited", "icmp_frag_needed", "icmp_ttl_exceeded", "icmp_unreachable",
            "dns_servfail", "dns_no_response", "dns_nxdomain", "dns_slow", "dns_suspicious_names", "dns_non_local_resolver",
            "dhcp_no_offer", "dhcp_multiple_servers", "dhcp_nak", "dhcp_apipa",
            "http_server_errors", "http_slow_response", "http_suspicious_user_agent", "http_cleartext_credentials",
            "tls_old_version", "tls_weak_cipher", "tls_alert", "tls_handshake_failure",
            "bgp_notification", "bgp_withdrawals", "ospf_mtu_mismatch", "ospf_hello_mismatch", "ospf_exstart_stuck",
            "eigrp_k_mismatch", "eigrp_sia", "eigrp_goodbye", "eigrp_retrans", "rip_version_mismatch",
            "rip_unreachable_routes", "arp_duplicate_ip", "stp_topology_change", "sec_port_scan",
            "sec_nmap_signature", "sec_log4j", "tcp_capture_point"}
        self.assertEqual(expected - IDS, set())

    def test_every_finding_has_explanations(self):
        for f in A.findings:
            self.assertTrue(f.causes and f.remediation and f.recommendations and f.perspectives, f.id)

    def test_no_false_positive_low_ttl_for_bgp(self):
        self.assertFalse(any("TTL < 5" in f.summary for f in A.findings if f.id == "ip_ttl_anomaly"))

    def test_bgp_details(self):
        n = [f for f in A.findings if f.id == "bgp_notification"]
        errors = {f.details["code"] for f in n}
        self.assertEqual(errors, {2, 4})
        hold = next(f for f in n if f.details["code"] == 4)
        self.assertGreaterEqual(hold.details["tcp_retrans"], 1)

    def test_capture_point(self):
        self.assertIn("CLIENT", A.capture_point)


class CorrelationTests(unittest.TestCase):
    def test_root_causes(self):
        expected = {"firewall_block", "middlebox_reset", "pmtud", "ospf_mtu", "ospf_adjacency", "bgp_hold_loss",
                    "routing_impact", "eigrp_adjacency", "dns_failure", "dns_latency", "dhcp_failure", "rogue_dhcp",
                    "arp_conflict", "receiver_bottleneck", "server_think_time", "attack_chain"}
        self.assertEqual(expected - RC, set())

    def test_slow_app_blames_server_not_network(self):
        r = next(r for r in A.root_causes if r.id == "server_think_time")
        self.assertEqual(r.fault_domain, "server")
        self.assertNotIn("slow_due_to_loss", RC)

    def test_receiver_bottleneck_names_the_server(self):
        r = next(r for r in A.root_causes if r.id == "receiver_bottleneck")
        self.assertIn("10.0.2.40", r.title)

    def test_chains_are_time_ordered(self):
        for r in A.root_causes:
            ts = [s["t"] for s in r.chain if s["t"] is not None]
            self.assertEqual(ts, sorted(ts), r.id)

    def test_pmtud_blackhole_with_mss_fallback(self):
        g = synth.Gen()
        c = synth.Conv(g, "00:00:00:00:00:01", "00:00:00:00:00:02", "10.0.0.1", "10.0.0.2", 40000, 80)
        t = c.handshake(0.0)
        c.c(t + 0.001, 0x18, synth.http_req("GET", "files.example", "/big"))
        s0 = c.sseq
        for dt in (0.01, 3.0, 9.0, 21.0):                      # full-size segment never gets through
            c.s(t + dt, 0x10, b"x" * 1460, seq=s0)
        c.sseq = s0
        for i in range(6):                                     # black-hole detection: 536-byte segments
            c.s(t + 21.1 + i * 0.001, 0x10, b"y" * 536)
        c.c(t + 21.2, 0x10)
        p = os.path.join(TMP, "blackhole.pcapng")
        g.save(p)
        a = analyze_file(p)
        r = next(r for r in a.root_causes if r.id == "pmtud_blackhole")
        self.assertGreaterEqual(r.confidence, 0.9)
        self.assertEqual(r.fault_domain, "network")

    def test_healthy_capture_has_no_root_causes(self):
        g = synth.Gen()
        c = synth.Conv(g, "00:00:00:00:00:01", "00:00:00:00:00:02", "10.0.0.1", "10.0.0.2", 40000, 80)
        t = c.handshake(0.0)
        c.c(t + 0.001, 0x18, synth.http_req("GET", "ok.example", "/"))
        c.s(t + 0.010, 0x18, synth.http_resp(200, "OK", b"hi"))
        c.c(t + 0.011, 0x10)
        c.close(t + 0.1)
        p = os.path.join(TMP, "healthy.pcapng")
        g.save(p)
        a = analyze_file(p)
        self.assertEqual(a.root_causes, [])
        self.assertFalse([f for f in a.findings if f.severity in ("critical", "high", "medium")])
        self.assertEqual(a.stats()["health"]["overall"], 100)


class ReportTests(unittest.TestCase):
    def test_html_is_self_contained_and_json_parses(self):
        out = html.render(A.to_dict())
        m = re.search(r'<script id="pl-data" type="application/json">(.*?)</script>', out, re.S)
        data = json.loads(m.group(1))
        self.assertEqual(data["stats"]["packets"], len(A.packets))
        # no external assets: the only script source is the bundled three.min.js placed next to the report
        self.assertEqual(re.findall(r'<script[^>]+src="([^"]*)"', out), ["three.min.js"])
        self.assertNotRegex(out, r"<link[^>]+href=")

    def test_to_dict_is_json_serialisable(self):
        json.dumps(A.to_dict())

    def test_cli_json_and_fail_on(self):
        out = os.path.join(TMP, "out.json")
        rc = cli.main(["analyze", DEMO, "--json", out, "-q", "--fail-on", "critical"])
        self.assertEqual(rc, 2)
        with open(out) as fh:
            self.assertIn("root_causes", json.load(fh))
        self.assertEqual(cli.main(["analyze", os.path.join(TMP, "missing.pcap"), "-q"]), 1)

    def test_text_report(self):
        txt = cli.text_report(A, color=False, verbose=True)
        self.assertIn("ROOT CAUSES", txt)
        self.assertIn("Wireshark filter:", txt)


class WebTests(unittest.TestCase):
    def test_upload_and_analyze(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(50))
        th = threading.Thread(target=srv.serve_forever, daemon=True)
        th.start()
        try:
            base = f"http://127.0.0.1:{srv.server_address[1]}"
            self.assertIn(b"PacketLens", urllib.request.urlopen(base + "/").read())
            with open(DEMO, "rb") as fh:
                req = urllib.request.Request(base + "/analyze?name=demo.pcapng", data=fh.read(), method="POST")
            body = urllib.request.urlopen(req).read().decode()
            self.assertIn('id="pl-data"', body)
            bad = urllib.request.Request(base + "/analyze", data=b"garbage-bytes", method="POST")
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(bad)
            self.assertEqual(cm.exception.code, 400)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
