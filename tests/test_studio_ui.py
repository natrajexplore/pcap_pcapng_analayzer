"""Tests for the Studio front end: assets, script syntax, served pages, and filters the UI offers to apply."""
import http.client
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from packetlens import synth
from packetlens.app.server import State, make_handler
from packetlens.dfilter import compile_filter
from packetlens.findings import filter_supported
from packetlens.knowledge import KB

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packetlens", "app", "static")
NEW_PROTOCOLS = {"PQC", "SSH", "IKE", "ESP", "MACsec", "MKA", "X.509", "AI", "gRPC", "QUIC", "WireGuard", "RoCE", "PFC"}


class AssetTests(unittest.TestCase):
    def test_index_wires_new_views(self):
        html = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
        for needle in ('/static/insights.js', 'data-view="insights"', 'id="pal"', 'id="btn-theme"', 'class="skip"', 'id="drop-ov"'):
            self.assertIn(needle, html)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_scripts_parse(self):
        for name in ("app.js", "analyze.js", "insights.js", "scene.js"):
            r = subprocess.run(["node", "--check", os.path.join(STATIC, name)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr}")

    def test_light_and_dark_tokens(self):
        css = open(os.path.join(STATIC, "app.css"), encoding="utf-8").read()
        self.assertIn('[data-theme="light"]', css)
        self.assertIn("prefers-reduced-motion", css)


class FilterTests(unittest.TestCase):
    def test_new_knowledge_filters_run_in_the_builtin_engine(self):
        for fid, kb in KB.items():
            if kb["protocol"] in NEW_PROTOCOLS and kb["filter"]:
                compile_filter(kb["filter"])            # raises on an unsupported field

    def test_filter_supported_flag(self):
        self.assertTrue(filter_supported("tls.pqc && tcp"))
        self.assertFalse(filter_supported("dns.time > 1"))
        self.assertFalse(filter_supported(""))


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="packetlens-ui-")
        os.makedirs(os.path.join(cls.tmp, "Demo"))
        synth.write_demo(os.path.join(cls.tmp, "Demo", "demo.pcapng"))
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(State(cls.tmp)))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1], timeout=60)
        c.request("GET", path)
        r = c.getresponse()
        return r.status, r.read()

    def test_insights_script_served(self):
        st, body = self.get("/static/insights.js")
        self.assertEqual(st, 200)
        self.assertIn(b"PL.views.insights", body)

    def test_capture_payload_feeds_insights(self):
        st, body = self.get("/api/capture?id=Demo/demo.pcapng")
        self.assertEqual(st, 200)
        d = json.loads(body)
        self.assertTrue(d["crypto"]["sessions"] and d["ai"]["flows"] and d["fabric"]["qps"])
        self.assertTrue(all("filter_ok" in f for f in d["findings"]))


if __name__ == "__main__":
    unittest.main()
