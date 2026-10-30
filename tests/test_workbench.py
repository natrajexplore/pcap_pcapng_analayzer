"""Tests for display filters, the packet details tree and the Analyze-tab API."""
import http.client
import json
import os
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

from packetlens import synth
from packetlens.analyzer import analyze_file
from packetlens.app.server import State, make_handler
from packetlens.dfilter import Ctx, FilterError, compile_filter
from packetlens.fields import tree
from packetlens.reader import open_capture

TMP = tempfile.mkdtemp(prefix="packetlens-wb-")
DEMO = os.path.join(TMP, "lib", "demo.pcapng")
os.makedirs(os.path.dirname(DEMO))
synth.write_demo(DEMO)
A = analyze_file(DEMO)
RAW = list(open_capture(DEMO))


def count(expr):
    fn = compile_filter(expr)
    return sum(1 for p in A.packets if fn(Ctx(p, lambda n=p.no: RAW[n - 1].data)))


class FilterTests(unittest.TestCase):
    def test_protocols_fields_and_operators(self):
        tcp, total = count("tcp"), len(A.packets)
        self.assertTrue(0 < tcp < total)
        self.assertEqual(count("!tcp"), total - tcp)
        self.assertEqual(count("tcp || !tcp"), total)
        self.assertEqual(count("tcp && !tcp"), 0)
        self.assertEqual(count("tcp.port == 80"), count("tcp.srcport == 80 || tcp.dstport == 80"))
        self.assertEqual(count("tcp.port in {80 443}"), count("tcp.port == 80 or tcp.port eq 443"))
        self.assertEqual(count("frame.len > 1000") + count("frame.len <= 1000"), total)
        self.assertGreater(count("dns.qry.name contains \".\""), 0)
        self.assertGreater(count("tcp.analysis.retransmission"), 0)

    def test_address_semantics(self):
        p = next(p for p in A.packets if p.ip_version == 4)
        self.assertGreater(count(f"ip.addr == {p.src}"), 0)
        self.assertEqual(count(f"ip.addr == {p.src}/32"), count(f"ip.addr == {p.src}"))
        # != means "no value equals": both addresses must differ
        self.assertEqual(count(f"ip.addr != {p.src}"), count(f"ip && !(ip.addr == {p.src})"))

    def test_frame_contains_and_matches(self):
        self.assertGreater(count('frame contains "HTTP/1.1"'), 0)
        self.assertEqual(count('frame matches "http/1\\.1"'), count('frame contains "HTTP/1.1"'))

    def test_errors_are_reported(self):
        for bad in ["tcp.prot == 80", "ip.addr ==", "tcp &&", "(tcp", "frame matches \"(\"", "== 5"]:
            with self.subTest(bad=bad), self.assertRaises(FilterError):
                compile_filter(bad)


class TreeTests(unittest.TestCase):
    def test_ranges_stay_inside_the_frame_and_fields_are_filterable(self):
        def walk(nodes, n):
            for x in nodes:
                if "range" in x:
                    self.assertTrue(0 <= x["range"][0] and x["range"][0] + x["range"][1] <= n, x["label"])
                yield x
                yield from walk(x.get("children", []), n)
        for p in A.packets:
            fr = RAW[p.no - 1]
            nodes = list(walk(tree(p, fr.data, fr.linktype), len(fr.data)))
            for x in nodes:                      # every "Apply as filter" expression must compile
                if "field" in x and x.get("value") is not None and isinstance(x["value"], int):
                    compile_filter(f"{x['field']} == {x['value']}")

    def test_tcp_header_bytes(self):
        p = next(p for p in A.packets if p.tcp is not None and p.eth_src and p.vlan is None and p.ip_version == 4)
        t = tree(p, RAW[p.no - 1].data, 1)
        tcp = next(n for n in t if n["label"].startswith("Transmission Control Protocol"))
        sport = next(c for c in tcp["children"] if c["label"].startswith("Source Port"))
        self.assertEqual(sport["range"], [34, 2])
        self.assertEqual(int(RAW[p.no - 1].data[34:36].hex(), 16), p.tcp.sport)


class WorkbenchApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["PACKETLENS_QUIET"] = "1"
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(State(os.path.dirname(DEMO))))
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def get(self, path):
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_address[1], timeout=30)
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, (json.loads(body) if r.getheader("Content-Type", "").startswith("application/json") else body)

    def test_list_filter_detail_follow_stats_export(self):
        st, d = self.get("/api/pkt/list?id=demo.pcapng&filter=tcp&limit=5")
        self.assertEqual((st, d["matched"], len(d["rows"])), (200, count("tcp"), 5))
        st, d = self.get("/api/pkt/list?id=demo.pcapng&filter=tcp.prot%3D%3D1")
        self.assertEqual((st, d.get("filter_error")), (400, True))
        no = next(p.no for p in A.packets if p.tcp is not None and p.tcp.payload_len)
        st, d = self.get(f"/api/pkt/detail?id=demo.pcapng&no={no}")
        self.assertEqual(len(d["bytes"]) // 2, len(RAW[no - 1].data))
        st, d = self.get(f"/api/pkt/follow?id=demo.pcapng&no={no}")
        self.assertTrue(d["filter"].startswith("tcp.stream eq") and d["chunks"])
        for kind in ("hierarchy", "conversations", "endpoints", "io", "expert"):
            st, d = self.get(f"/api/pkt/stats?id=demo.pcapng&kind={kind}")
            self.assertEqual(st, 200, kind)
        st, body = self.get("/api/pkt/export?id=demo.pcapng&filter=dns")
        exported = list(open_capture(__import__("io").BytesIO(body)))
        self.assertEqual(len(exported), count("dns"))


if __name__ == "__main__":
    unittest.main()
