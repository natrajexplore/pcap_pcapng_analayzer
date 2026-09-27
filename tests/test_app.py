"""Tests for the packet simulator and the Studio app API."""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from packetlens import sim, synth
from packetlens.analyzer import analyze_file
from packetlens.app.server import State, make_handler

TMP = tempfile.mkdtemp(prefix="packetlens-app-")


def _run(**kw):
    r = sim.simulate(**kw)
    p = os.path.join(TMP, "sim.pcapng")
    sim.write(r, p)
    return r, {f.id: f for f in analyze_file(p).findings}


class SimulatorTests(unittest.TestCase):
    def test_every_fault_is_detected_from_the_default_capture_point(self):
        for fault, (_label, _where, traffics) in sim.FAULTS.items():
            for traffic in sorted(traffics):
                with self.subTest(fault=fault, traffic=traffic):
                    r, found = _run(traffic=traffic, fault=fault)
                    if r["expected"]:
                        self.assertTrue(set(r["expected"]) & set(found), (r["expected"], sorted(found)))

    def test_healthy_runs_are_clean(self):
        for traffic in sim.TRAFFIC:
            with self.subTest(traffic=traffic):
                _r, found = _run(traffic=traffic, fault="none")
                self.assertFalse([f for f in found.values() if f.severity in ("critical", "high", "medium")], sorted(found))

    def test_fault_upstream_of_capture_is_reported_as_invisible(self):
        # firewall on R1 while capturing between R3 and the server: the SYN never reaches the capture link
        r, found = _run(traffic="http", fault="firewall_drop", where="r1", capture=4)
        self.assertEqual((r["expected"], r["visible_frames"], r["fault_side"]), ([], 0, "before"))
        self.assertTrue(any("capture" in n for n in r["notes"]))

    def test_frames_carry_router_ttl_and_macs(self):
        r, _ = _run(traffic="ping", fault="none", routers=3, capture=4)      # R3 ↔ server
        ttls = {f[1][22] for f in r["frames"] if f[1][12:14] == b"\x08\x00" and f[1][26:30] == bytes([192, 168, 10, 50])}
        self.assertEqual(ttls, {128 - 3})                                     # client TTL 128 after three routers
        self.assertTrue(r["journey"] and all(e["status"] == "ok" for e in r["journey"]))


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib = os.path.join(TMP, "lib", "TCP")
        os.makedirs(lib)
        synth.write_demo(os.path.join(lib, "demo.pcapng"))
        os.environ["PACKETLENS_QUIET"] = "1"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(State(os.path.join(TMP, "lib"))))
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def test_library_capture_and_report(self):
        st, body = self.req("GET", "/api/library?analyze=1")
        lib = json.loads(body)
        self.assertEqual(st, 200)
        cap = lib["folders"][0]["captures"][0]
        self.assertEqual((cap["id"], cap["packets"] > 100), ("TCP/demo.pcapng", True))
        st, body = self.req("GET", "/api/capture?id=TCP/demo.pcapng")
        d = json.loads(body)
        self.assertEqual(st, 200)
        self.assertEqual(len(d["replay"]["rows"]), d["stats"]["packets"])
        st, body = self.req("GET", "/api/report?id=TCP/demo.pcapng")
        self.assertIn(b'src="/static/three.min.js"', body)

    def test_simulation_round_trip(self):
        st, body = self.req("POST", "/api/sim", json.dumps({"traffic": "http", "fault": "port_closed"}),
                            {"X-PacketLens": "1", "Content-Type": "application/json"})
        r = json.loads(body)
        self.assertEqual((st, r["verdict"], r["detected"]), (200, "detected", ["tcp_conn_refused"]))
        st, pcap = self.req("GET", f"/api/sim/pcap?id={r['id']}")
        self.assertEqual((st, pcap[:4]), (200, b"\x0a\x0d\x0d\x0a"))            # pcapng section header
        st, body = self.req("GET", "/api/capture?id=" + r["key"])
        self.assertEqual(st, 200)

    def test_local_only_protections(self):
        self.assertEqual(self.req("POST", "/api/sim", "{}")[0], 403)                          # no X-PacketLens header
        self.assertEqual(self.req("GET", "/api/meta", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("GET", "/api/capture?id=../../pyproject.toml")[0], 404)
        self.assertEqual(self.req("GET", "/static/../server.py")[0], 404)
        st, body = self.req("POST", "/api/sim", json.dumps({"traffic": "nope"}), {"X-PacketLens": "1"})
        self.assertEqual(st, 400)


if __name__ == "__main__":
    unittest.main()
