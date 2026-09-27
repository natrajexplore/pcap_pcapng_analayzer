"""Tests for the layer-2 / multicast / tunnel / access-control decoders, their experts, path inference,
the scenario library and batch reports."""
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path

from packetlens import batch, synth
from packetlens.analyzer import analyze_file
from packetlens.knowledge import KB
from packetlens.path import stitch
from packetlens.scenarios import TOPICS

TMP = tempfile.mkdtemp(prefix="packetlens-topo-")
M1, M2, M3 = "00:00:00:00:00:01", "00:00:00:00:00:02", "00:00:00:00:00:03"
CDP_DST, PAE = "01:00:0c:cc:cc:cc", "01:80:c2:00:00:03"


def _save(g, name):
    p = os.path.join(TMP, name)
    g.save(p)
    return analyze_file(p)


def ip4(src, dst, proto, payload, ttl=64):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, ttl, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", synth._cks(h)) + h[12:] + payload


def tlv(t, v):
    return struct.pack("!HH", t, len(v) + 4) + v


def snap(g, t, src, pid, body, vlan=None):
    llc = b"\xaa\xaa\x03\x00\x00\x0c" + struct.pack("!H", pid) + body
    g.eth(t, src, CDP_DST, len(llc), llc, vlan=vlan)


def cdp(g, t, src, name, port, native=None, router=True):
    body = b"\x02\xb4\x00\x00" + tlv(1, name.encode()) + tlv(3, port.encode()) + tlv(4, struct.pack("!I", 0x01 if router else 0x08))
    if native is not None:
        body += tlv(0x0A, struct.pack("!H", native))
    snap(g, t, src, 0x2000, body)


class DecoderTests(unittest.TestCase):
    def test_cdp_dtp_native_vlan_mismatch(self):
        g = synth.Gen()
        cdp(g, 0.0, M1, "SW-1", "Gi0/1", native=1, router=False)
        cdp(g, 0.1, M2, "SW-2", "Gi0/2", native=10, router=False)
        dtp = b"\x01" + tlv(1, b"\x00") + tlv(2, b"\x04") + tlv(3, b"\xa5") + tlv(4, bytes(6))
        snap(g, 0.2, M1, 0x2004, dtp)
        a = _save(g, "l2.pcapng")
        self.assertEqual(a.packets[0].layers["cdp"]["device_id"], "SW-1")
        self.assertEqual(a.packets[2].layers["dtp"], {"domain": "", "operational": "access", "admin": "auto",
                                                      "encapsulation": "802.1Q", "neighbor": "00:00:00:00:00:00"})
        ids = {f.id for f in a.findings}
        self.assertTrue({"l2_neighbors", "cdp_native_vlan_mismatch", "dtp_negotiation_enabled"} <= ids, ids)

    def test_gre_and_vxlan_decapsulation(self):
        g = synth.Gen()
        inner = ip4("10.1.1.1", "10.2.2.2", 1, b"\x08\x00\x00\x00\x00\x01\x00\x01")
        g.ipv4(0.0, M1, M2, "1.1.1.1", "2.2.2.2", 47, b"\x00\x00\x08\x00" + inner)
        arp = synth._mac("ff:ff:ff:ff:ff:ff") + synth._mac(M3) + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) \
            + synth._mac(M3) + socket.inet_aton("192.168.1.1") + bytes(6) + socket.inet_aton("192.168.1.2")
        g.udp(0.1, M1, M2, "10.0.0.1", "239.1.1.1", 50000, 4789, b"\x08\x00\x00\x00\x00\x27\x1a\x00" + arp)
        a = _save(g, "tun.pcapng")
        gre, vx = a.packets
        self.assertEqual((gre.src, gre.dst, gre.layers["gre"]["outer_src"]), ("10.1.1.1", "10.2.2.2", "1.1.1.1"))
        self.assertEqual((vx.protocol, vx.layers["vxlan"]["vni"], vx.layers["vxlan"]["outer_eth_src"]), ("ARP", 10010, M1))
        self.assertIsNone(vx.src)                         # outer IP must not leak into the inner ARP frame
        self.assertTrue({"gre_tunnel", "vxlan_tunnel"} <= {f.id for f in a.findings})

    def test_pim_and_igmp(self):
        g = synth.Gen()
        hello = b"\x20\x00\x00\x00" + struct.pack("!HHH", 1, 2, 105) + struct.pack("!HHI", 19, 4, 5)
        g.ipv4(0.0, M1, "01:00:5e:00:00:0d", "10.0.0.1", "224.0.0.13", 103, hello, ttl=1)
        g.ipv4(0.1, M2, "01:00:5e:00:00:0d", "10.0.0.2", "224.0.0.13", 103, hello[:-1] + b"\x01", ttl=1)
        g.ipv4(0.2, M3, "01:00:5e:01:01:01", "10.0.0.9", "239.1.1.1", 2, b"\x16\x00\x00\x00" + socket.inet_aton("239.1.1.1"), ttl=1)
        a = _save(g, "mcast.pcapng")
        self.assertEqual(a.packets[0].layers["pim"]["dr_priority"], 5)
        pim = next(f for f in a.findings if f.id == "pim_neighbors")
        self.assertEqual(pim.details["dr"], "10.0.0.1")           # priority 5 beats the higher IP
        self.assertIn("igmp_no_querier", {f.id for f in a.findings})

    def test_dot1x_md5_session_and_radius_reject(self):
        g = synth.Gen()

        def eap(t, src, dst, code, ident, body=b""):
            e = struct.pack("!BBH", code, ident, 4 + len(body)) + body
            g.eth(t, src, dst, 0x888E, b"\x01\x00" + struct.pack("!H", len(e)) + e)
        eap(0.0, M1, PAE, 1, 1, b"\x01")                            # authenticator → group MAC
        eap(0.1, M2, PAE, 2, 1, b"\x01alice")                       # supplicant
        eap(0.2, M1, PAE, 1, 2, b"\x04\x10" + bytes(16))           # MD5 challenge
        eap(0.3, M2, PAE, 2, 2, b"\x04\x10" + bytes(16))
        eap(0.4, M1, PAE, 4, 2)                                     # failure
        req = struct.pack("!BBH", 1, 7, 20 + 7) + bytes(16) + b"\x01\x07alice"
        g.udp(0.15, M1, M3, "10.0.0.5", "10.0.0.9", 40000, 1812, req)
        g.udp(0.35, M3, M1, "10.0.0.9", "10.0.0.5", 1812, 40000, struct.pack("!BBH", 3, 7, 20) + bytes(16))
        a = _save(g, "dot1x.pcapng")
        sess = next(f for f in a.findings if f.id == "dot1x_sessions").details["sessions"]
        self.assertEqual([(s["supplicant"], s["identity"], s["outcome"]) for s in sess], [(M2, "alice", "Failure")])
        self.assertTrue({"dot1x_failure", "dot1x_weak_method", "radius_reject"} <= {f.id for f in a.findings})


class PathTests(unittest.TestCase):
    def _routed(self, name, router_name="R1", server_ttl=61):
        g = synth.Gen()
        cdp(g, 0.0, M2, router_name, "Gi0/0")                       # the router announces itself on the capture link
        c = synth.Conv(g, M1, M2, "192.168.1.10", "203.0.113.5", 40000, 80, ttl_s=server_ttl)
        t = c.handshake(0.01)
        c.c(t + 0.01, 0x18, synth.http_req("GET", "x.example", "/"))
        c.s(t + 0.05, 0x18, synth.http_resp(200, "OK"))
        return _save(g, name)

    def test_routed_flow_hops_and_capture_point(self):
        P = self._routed("routed.pcapng").path
        lab = {n["id"]: n for n in P["nodes"]}
        f = next(f for f in P["flows"] if f["kind"] == "data")
        # client on the link, then R1 (named by CDP, frames of the server arrive from its MAC), 2 unseen routers, server
        self.assertEqual([lab[h]["label"] for h in f["hops"]], ["192.168.1.10", "R1", "Router (hop 2)", "Router (hop 3)", "203.0.113.5"])
        self.assertEqual([lab[h]["observed"] for h in f["hops"]], [True, True, False, False, True])
        self.assertEqual(f["status"], "ok")

    def test_many_unseen_hops_collapse_to_cloud(self):
        P = self._routed("cloud.pcapng", server_ttl=50).path
        f = next(f for f in P["flows"] if f["kind"] == "data")
        kinds = [next(n for n in P["nodes"] if n["id"] == h)["kind"] for h in f["hops"]]
        self.assertEqual(kinds.count("cloud"), 1)

    def test_stitch_merges_the_same_flow(self):
        a1, a2 = self._routed("s1.pcapng"), self._routed("s2.pcapng")
        S = stitch([a1.path, a2.path])
        f = next(f for f in S["flows"] if f["kind"] == "data")
        self.assertEqual(len(f["captures"]), 2)


class LibraryTests(unittest.TestCase):
    def test_scenarios_are_consistent(self):
        for tid, t in TOPICS.items():
            n, r = len(t["normal"]), len(t["roles"])
            for f in t["failures"]:
                self.assertLess(f["at"], n, (tid, f["id"]))
                self.assertTrue(f["drop"] is None or f["drop"] < r, (tid, f["id"]))
                self.assertTrue(all(x in KB for x in f["findings"]), (tid, f["id"]))
                self.assertTrue(f["why"] and f["fix"] and f["prevent"], (tid, f["id"]))

    def test_batch_writes_reports_index_and_library(self):
        src, out = os.path.join(TMP, "lib"), os.path.join(TMP, "out")
        os.makedirs(os.path.join(src, "TCP"))
        synth.write_demo(os.path.join(src, "TCP", "demo.pcapng"))
        open(os.path.join(src, "lab.pkt"), "wb").close()
        res = batch.run(src, out, log=lambda *_: None)
        self.assertEqual((res["captures"], res["errors"], res["skipped_pkt"]), (1, 0, 1))
        page = Path(out, "TCP", "demo.pcapng.html").read_text(encoding="utf-8")
        self.assertIn('src="../_assets/three.min.js"', page)
        self.assertTrue(os.path.getsize(os.path.join(out, "_assets", "three.min.js")) > 100_000)
        self.assertIn("TCP/demo.pcapng.html", Path(res["index"]).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
