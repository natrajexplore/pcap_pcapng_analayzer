"""Tests for AI-era traffic: AI/LLM services, MCP, QUIC, WireGuard, RoCEv2 / PFC and gRPC."""
import json
import os
import struct
import tempfile
import unittest

from packetlens import synth, synth_ai
from packetlens.analyzer import analyze_file
from packetlens.cli import text_report
from packetlens.dfilter import Ctx, compile_filter
from packetlens.protocols import ai, http2, quic, roce, wireguard
from packetlens.reader import open_capture
from packetlens.report.html import render

TMP = tempfile.mkdtemp(prefix="packetlens-ai-")
DEMO = os.path.join(TMP, "demo.pcapng")
synth.write_demo(DEMO)
A = analyze_file(DEMO)
IDS = {f.id for f in A.findings}
RC = {r.id for r in A.root_causes}
FLOWS = {(f["provider"], f["client"]): f for f in A.ai["flows"]}


class ParserTests(unittest.TestCase):
    def test_quic_initial_keys_rfc9001_appendix_a(self):
        dcid = bytes.fromhex("8394c8f03e515708")
        key, iv, hp = quic._keys(quic.V1, dcid, server=False)
        self.assertEqual((key.hex(), iv.hex(), hp.hex()),
                         ("1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c", "9f50449e04a0e810283a1e9933adedd2"))
        key, iv, hp = quic._keys(quic.V1, dcid, server=True)
        self.assertEqual((key.hex(), iv.hex(), hp.hex()),
                         ("cf3a5331653c364c88f0f379b6067e37", "0ac1493ca1905853b0bba03e", "c206b8d9b9f0f37644430b490eeaa314"))

    def test_quic_headers(self):
        d = quic.parse(b"\xc0\x00\x00\x00\x01\x08" + b"\x11" * 8 + b"\x04" + b"\x22" * 4 + b"\x00\x44\xd0" + b"\x00" * 1232)
        self.assertEqual((d["type"], d["version_name"], d["dcid"], d["payload_len"]), ("Initial", "1", "11" * 8, 1232))
        self.assertEqual(quic.parse(b"\x80\x00\x00\x00\x00\x04abcd\x04efgh\x00\x00\x00\x01")["supported"], ["1"])
        self.assertEqual(quic.parse(b"\x41" + b"\x00" * 30)["form"], "short")
        self.assertEqual(quic.version_name(0xFF00001D), "draft-29")

    @unittest.skipUnless(quic.HAVE_CRYPTO, "cryptography not installed")
    def test_quic_initial_round_trip(self):
        odcid = bytes.fromhex("0011223344556677")
        pkt = synth_ai.quic_initial(odcid, odcid, b"\x01\x02", 0, synth_ai._crypto_frame(0, b"hello"), False)
        self.assertGreaterEqual(len(pkt), 1200)
        plain = quic.decrypt_initial(pkt, odcid, server=False)
        self.assertEqual(quic.crypto_frames(plain), [(0, b"hello")])
        self.assertIsNone(quic.decrypt_initial(pkt, b"\x00" * 8, server=False))       # wrong DCID: authentication fails

    def test_wireguard(self):
        self.assertEqual(wireguard.parse(b"\x01\x00\x00\x00" + struct.pack("<I", 7) + b"\x00" * 140, False)["sender"], 7)
        self.assertIsNone(wireguard.parse(b"\x01\x00\x00\x00" + b"\x00" * 100, False))                 # wrong size
        d = wireguard.parse(b"\x04\x00\x00\x00" + struct.pack("<IQ", 9, 42) + b"\x00" * 32, True)
        self.assertEqual((d["receiver"], d["counter"]), (9, 42))
        self.assertIsNone(wireguard.parse(b"\x04\x00\x00\x00" + struct.pack("<IQ", 9, 42) + b"\x00" * 32, False))

    def test_roce_and_pfc(self):
        d = roce.parse_bth(synth_ai._bth(0x11, 0x34B, 105) + bytes([0x60]) + b"\x00\x00\x07")
        self.assertEqual((d["op"], d["psn"], d["aeth"]["kind"], d["aeth"]["nak"]), ("RC Acknowledge", 105, "NAK", "PSN Sequence Error"))
        self.assertEqual(roce.parse_bth(synth_ai._bth(0x81, 1, 0) + b"\x00" * 16)["op"], "CNP")
        pfc = roce.parse_mac_control(struct.pack("!HH", 0x0101, 0x0009) + struct.pack("!8H", 100, 0, 0, 7, 0, 0, 0, 0))
        self.assertEqual(pfc["priorities"], {"0": 100, "3": 7})

    def test_ai_catalog(self):
        self.assertEqual(ai.match("api.openai.com"), ("OpenAI", "LLM API"))
        self.assertEqual(ai.match("foo.openai.azure.com")[0], "Azure OpenAI")
        self.assertEqual(ai.match("bedrock-runtime.us-east-1.amazonaws.com")[0], "AWS Bedrock")
        self.assertIsNone(ai.match("notclaude.ai.example.com"))
        self.assertIsNone(ai.match("myclaude.ai"))
        self.assertEqual(ai.api_kind("/v1/chat/completions"), "chat.completions")
        self.assertEqual(ai.api_kind("/v1beta/models/gemini-2.5:streamGenerateContent"), "gemini.generateContent")
        self.assertEqual(ai.mcp_method('{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{}}'), "tools/call")
        self.assertEqual(ai.grpc_inference("/inference.GRPCInferenceService/ModelInfer"), "Triton / KServe v2")


class AITests(unittest.TestCase):
    def test_services_and_streaming_profile(self):
        oa = FLOWS[("OpenAI", "10.72.0.10")]
        self.assertTrue(oa["streaming"])
        self.assertAlmostEqual(oa["ttft_s"], 0.6, delta=0.01)
        an = FLOWS[("Anthropic", "10.72.0.10")]
        self.assertAlmostEqual(an["ttft_s"], 7.5, delta=0.01)
        self.assertAlmostEqual(an["max_gap_s"], 6.05, delta=0.01)
        self.assertGreater(FLOWS[("Anthropic Claude", "10.72.0.20")]["up"], 2_000_000)
        for fid in ("ai_service_usage", "ai_consumer_assistant", "ai_large_upload", "ai_slow_first_token", "ai_stream_stall",
                    "ai_cleartext_api", "ai_unauth_local_inference", "ai_rate_limited", "mcp_traffic"):
            self.assertIn(fid, IDS)

    def test_self_hosted_and_mcp(self):
        self.assertEqual(FLOWS[("Self-hosted (Ollama)", "10.72.0.30")]["api"], ["ollama"])
        self.assertEqual([(m["method"], m["tool"]) for m in A.ai["mcp"]],
                         [("initialize", None), ("tools/list", None), ("tools/call", "query_database")])

    def test_http_request_body_preview_survives_reassembly(self):
        mcp_reqs = [t for t in A.http_transactions if t["uri"] == "/mcp"]
        self.assertTrue(all('"jsonrpc"' in t["body"] for t in mcp_reqs))

    @unittest.skipUnless(http2.HAVE_HPACK, "hpack not installed")
    def test_grpc_inference_errors(self):
        g = [t for t in A.http_transactions if t.get("grpc")]
        self.assertEqual([(t["grpc"], t["grpc_status"]) for t in g], [("inference.GRPCInferenceService/ModelInfer", 14)])
        self.assertIn("grpc_errors", IDS)
        self.assertIn(("Triton / KServe v2 (gRPC)", "10.72.0.50"), FLOWS)


class TransportTests(unittest.TestCase):
    def test_quic(self):
        qs = {q["server"]: q for q in A.quic_sessions}
        self.assertFalse(qs["203.0.113.99:443"]["answered"])
        self.assertIn("quic_blocked", IDS)
        self.assertIn("quic_version_negotiation", IDS)
        self.assertIn("quic_fallback", RC)
        if quic.HAVE_CRYPTO:
            self.assertEqual(qs["142.250.180.14:443"]["sni"], "gemini.google.com")
            s = next(s for s in A.crypto["sessions"] if s["proto"] == "QUIC" and s["name"] == "gemini.google.com")
            self.assertEqual((s["kex"], s["kex_status"]), ("X25519MLKEM768", "hybrid"))
            self.assertIn(("Google Gemini", "10.72.0.40"), FLOWS)
        else:
            self.assertTrue(any("cryptography" in w for w in A.warnings))

    def test_wireguard(self):
        wg = {s["server"]: s for s in A.crypto["sessions"] if s["proto"] == "WireGuard"}
        self.assertEqual(wg["10.73.0.2:51820"]["result"], "ok")
        self.assertEqual(wg["198.51.100.7:51820"]["initiations"], 4)
        self.assertIn("wireguard_handshake_failure", IDS)

    def test_fabric(self):
        qp = {q["qp"]: q for q in A.fabric["qps"]}
        self.assertEqual((qp["0x00012a"]["gaps"], qp["0x00012a"]["retx"], qp["0x00012a"]["cnps"], qp["0x00012a"]["ce"]), (3, 7, 6, 6))
        self.assertEqual(qp["0x000777"]["not_ect"], qp["0x000777"]["packets"])
        self.assertEqual(A.fabric["pfc"][0]["pausing"], 200)
        for fid in ("roce_packet_loss", "roce_congestion", "roce_not_ect", "pfc_storm"):
            self.assertIn(fid, IDS)
        self.assertIn("fabric_congestion_spreading", RC)


class SurfaceTests(unittest.TestCase):
    def test_filters(self):
        raw = list(open_capture(DEMO))
        n = lambda e: sum(1 for p in A.packets if compile_filter(e)(Ctx(p, lambda x=p.no: raw[x - 1].data)))  # noqa: E731
        self.assertEqual(n("pfc.priority == 3"), 200)
        self.assertEqual(n("infiniband.bth.opcode == 129"), 6)
        self.assertGreater(n("ip.dsfield.ecn == 3"), 0)
        self.assertEqual(n("wg.type == 1"), 5)
        self.assertGreater(n("quic.long.packet_type == \"Initial\""), 0)
        self.assertGreater(n("http.authorization"), 0)

    def test_cli_and_report(self):
        txt = text_report(A, color=False)
        self.assertIn("AI services:", txt)
        self.assertIn("AI fabric:", txt)
        d = json.loads(json.dumps(A.to_dict(), default=str))
        self.assertTrue(d["ai"]["flows"] and d["fabric"]["qps"])
        html = render(A.to_dict())
        self.assertIn("R.ai = el", html)
        self.assertIn("R.fabric = el", html)


if __name__ == "__main__":
    unittest.main()
