"""Tests for crypto posture / post-quantum analysis: TLS ML-KEM, X.509, SSH, IKEv2/ESP, MACsec/MKA, EAP-TLS."""
import json
import os
import struct
import tempfile
import time
import unittest

from packetlens import synth, synth_crypto
from packetlens.analyzer import analyze_file
from packetlens.cli import text_report
from packetlens.dfilter import Ctx, compile_filter
from packetlens.protocols import ike, macsec, pqc, ssh, tls, x509
from packetlens.reader import open_capture
from packetlens.report.html import render

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="packetlens-crypto-")
DEMO = os.path.join(TMP, "demo.pcapng")
synth.write_demo(DEMO)
A = analyze_file(DEMO)
IDS = {f.id for f in A.findings}
RC = {r.id for r in A.root_causes}
SESS = {(s["proto"], s["name"]): s for s in A.crypto["sessions"]}


class ParserTests(unittest.TestCase):
    def test_client_hello_pqc_groups_and_key_shares(self):
        rec = tls.parse(synth_crypto.client_hello("pq.test", [0x11EC, 0x1D], [(0x11EC, 1216), (0x1D, 32)], sigs=(0x0905, 0x0403)))
        ch = rec["client_hello"]
        self.assertEqual(ch["groups"], ["X25519MLKEM768", "x25519"])
        self.assertEqual([(k["group"], k["len"]) for k in ch["key_shares"]], [("X25519MLKEM768", 1216), ("x25519", 32)])
        self.assertEqual(ch["pqc_offered"], ["X25519MLKEM768"])
        self.assertEqual(ch["pqc_sigs_offered"], ["mldsa65"])
        self.assertGreater(ch["length"], 1448)          # spans two segments, like a real browser ClientHello

    def test_server_hello_group_and_hello_retry(self):
        sh = tls.parse(synth_crypto.server_hello13(0x11EC, 1120))["server_hello"]
        self.assertEqual((sh["group"], sh["group_status"], sh["hrr"]), ("X25519MLKEM768", "hybrid", False))
        self.assertEqual(tls.key_exchange(sh), ("X25519MLKEM768", "hybrid"))
        hrr = tls.parse(synth_crypto.server_hello13(0x11EC, 0, hrr=True))["server_hello"]
        self.assertTrue(hrr["hrr"])
        self.assertEqual(tls.key_exchange({"cipher": 0x002F}), ("RSA key transport (no forward secrecy)", "weak"))

    def test_x509_rsa_and_ml_dsa(self):
        now = time.time()
        c = x509.parse(synth_crypto.certificate("a.test", "Issuer", now - 10, now + 100, bits=3072, san=("a.test", "b.test")))
        self.assertEqual((c["cn"], c["issuer_cn"], c["key_alg"], c["key_size"], c["sig_alg"]),
                         ("a.test", "Issuer", "RSA", 3072, "sha256WithRSAEncryption"))
        self.assertEqual(c["san"], ["a.test", "b.test"])
        self.assertAlmostEqual(c["not_after"], now + 100, delta=1)
        q = x509.parse(synth_crypto.certificate("q.test", "q.test", now, now + 100, key="2.16.840.1.101.3.4.3.17",
                                                sig="2.16.840.1.101.3.4.3.17"))
        self.assertEqual((q["key_alg"], q["sig_alg"], q["sig_status"], q["self_signed"]), ("ML-DSA-44", "ML-DSA-44", "pqc", True))
        self.assertIsNone(x509.parse(b"\x30\x82\xff\xff garbage"))

    def test_ssh_kexinit_and_negotiation(self):
        pkt = synth_crypto._kexinit(["mlkem768x25519-sha256", "curve25519-sha256"], ["ssh-ed25519"], ["aes256-gcm@openssh.com"], ["hmac-sha2-256"])
        m = ssh.parse(pkt)
        self.assertEqual(m["type"], "KEXINIT")
        self.assertEqual(m["kex"][0], "mlkem768x25519-sha256")
        self.assertEqual(ssh.negotiate(["a", "b", "c"], ["c", "b"]), "b")
        self.assertEqual(pqc.ssh_kex("mlkem768x25519-sha256"), "hybrid")
        self.assertEqual(ssh.parse(b"SSH-2.0-OpenSSH_10.0\r\n")["software"], "OpenSSH_10.0")

    def test_ike_sa_init_with_ml_kem_addke(self):
        msg = synth_crypto.ike2(b"\x01" * 8, b"\x00" * 8, 34, False, 0,
                                [(33, synth_crypto._proposal([(1, 20, 256), (2, 5), (4, 19), (6, 36)])),
                                 (34, struct.pack("!HH", 19, 0) + b"\x00" * 64)])
        d = ike.parse(msg)
        self.assertEqual((d["version"], d["exchange"], d["initiator"]), (2, "IKE_SA_INIT", True))
        names = [t["name"] for t in d["proposals"][0]["transforms"]]
        self.assertEqual(names, ["AES-GCM-16-256", "PRF-HMAC-SHA2-256", "ECP-256 (group 19)", "ML-KEM-768"])
        self.assertEqual(ike.kex_summary(d), ("ECP-256 (group 19) + ML-KEM-768", "hybrid"))
        self.assertEqual(ike.parse(b"\x00\x00\x00\x00" + msg, natt=True)["exchange"], "IKE_SA_INIT")
        self.assertEqual(ike.parse(struct.pack("!II", 0x1234, 7) + b"x" * 20, natt=True)["kind"], "esp")

    def test_macsec_sectag_and_mkpdu(self):
        d = macsec.parse_sectag(synth_crypto._sectag(2, 99, "0011223344550001"))
        self.assertEqual((d["an"], d["pn"], d["sci"], d["mode"]), (2, 99, "0011223344550001", "encrypted"))
        self.assertEqual(macsec.parse_sectag(synth_crypto._sectag(0, 1, "0011223344550001", encrypted=False))["mode"], "integrity-only")
        pdu = synth_crypto._mkpdu(16, True, "0011223344550001", "aa" * 12, 5, "ab" * 16, live=["bb" * 12], sak="0080c20001000004")
        m = macsec.parse_mka(pdu[4:])
        self.assertEqual((m["key_server"], m["msg_number"], m["live_peers"], m["cipher_suite"]), (True, 5, ["bb" * 12], "GCM-AES-XPN-256"))


class ExpertTests(unittest.TestCase):
    def test_tls_pqc_sessions_and_findings(self):
        self.assertEqual(SESS[("TLS", "pq.example-cdn.net")]["kex_status"], "hybrid")
        self.assertEqual(SESS[("TLS", "legacy-api.example.com")]["kex"], "x25519")
        self.assertEqual(SESS[("TLS", "hrr.example.net")]["hrr"], "X25519MLKEM768")
        for fid in ("pqc_kex_in_use", "pqc_offered_not_selected", "pqc_hello_retry", "pqc_draft_kyber", "pqc_clienthello_blocked",
                    "tls_ech_in_use", "quantum_vulnerable_kex"):
            self.assertIn(fid, IDS)
        self.assertIn("pqc_middlebox", RC)

    def test_certificates(self):
        certs = {c["cn"]: c for c in A.crypto["certificates"]}
        self.assertIn("self-signed", certs["printer.lab.local"]["issues"])
        self.assertTrue(any(i.startswith("weak key RSA-1024") for i in certs["printer.lab.local"]["issues"]))
        self.assertEqual(certs["pqc-pki.example"]["quantum"], "pqc")
        self.assertIn("EAP-TLS server", certs["radius.corp.example"]["context"])      # reassembled from two EAP fragments
        for fid in ("x509_expired", "x509_self_signed", "x509_weak_crypto", "x509_pqc_certificate", "x509_expiring_soon"):
            self.assertIn(fid, IDS)

    def test_ssh(self):
        self.assertEqual(SESS[("SSH", "10.71.1.10:22 OpenSSH_10.0")]["kex"], "mlkem768x25519-sha256")
        self.assertEqual(SESS[("SSH", "10.71.1.11:22 Cisco-1.25")]["kex_status"], "weak")
        for fid in ("ssh_weak_algorithms", "ssh_terrapin", "ssh_kex_failure"):
            self.assertIn(fid, IDS)

    def test_ike_and_esp(self):
        ok = SESS[("IKEv2", "10.90.0.1 ↔ 10.90.0.2")]
        self.assertEqual((ok["kex_status"], ok["result"], ok["frag_supported"]), ("hybrid", "ok", ["initiator", "responder"]))
        self.assertEqual(SESS[("IKEv2", "10.90.1.1 ↔ 10.90.1.2")]["result"], "NO_PROPOSAL_CHOSEN")
        esp = A.crypto["esp"][0]
        self.assertEqual((esp["missing"], esp["duplicates"]), (3, 1))
        for fid in ("ike_negotiation_failure", "ike_no_response", "ike_pqc_fragmentation", "ike_weak_crypto", "ike_v1_in_use",
                    "esp_sequence_anomaly"):
            self.assertIn(fid, IDS)
        self.assertTrue({"ike_pqc_mismatch", "ike_pqc_fragment_loss"} <= RC)

    def test_macsec_and_mka(self):
        scs = {s["sci"]: s for s in A.crypto["macsec"]}
        self.assertEqual(scs["001b540000010001"]["missing_pn"], 4)
        self.assertEqual(scs["001b540000030001"]["modes"], ["integrity-only"])
        mka = {m["mac"]: m for m in A.crypto["mka"]}
        self.assertEqual(mka["00:1b:54:00:00:01"]["cipher"], "GCM-AES-256")
        self.assertTrue(mka["00:1b:54:00:00:03"]["ckn_mismatch"])
        for fid in ("macsec_integrity_only", "macsec_pn_anomaly", "macsec_pn_exhaustion", "mka_no_live_peer"):
            self.assertIn(fid, IDS)
        self.assertIn("mka_ckn_mismatch", RC)

    def test_readiness_score(self):
        rd = A.crypto["readiness"]
        self.assertEqual(rd["score"], round(100 * (rd["quantum_safe"] + 0.5 * rd["counts"]["draft"]) / rd["known"]))
        self.assertIn("10.70.0.10", rd["pqc_capable_clients"])

    def test_no_crypto_traffic_gives_empty_inventory(self):
        g = synth.Gen()
        g.arp(0, "00:00:00:00:00:01", "10.0.0.1", "00:00:00:00:00:00", "10.0.0.2")
        p = os.path.join(TMP, "arp.pcap")
        g.save(p, "pcap")
        a = analyze_file(p)
        self.assertEqual(a.crypto["readiness"]["score"], None)
        self.assertFalse(a.warnings)


class SurfaceTests(unittest.TestCase):
    def test_display_filters(self):
        raw = list(open_capture(DEMO))
        n = lambda e: sum(1 for p in A.packets if compile_filter(e)(Ctx(p, lambda x=p.no: raw[x - 1].data)))  # noqa: E731
        self.assertGreater(n("tls.pqc"), 0)
        self.assertGreater(n("tls.handshake.extensions_supported_group == 4588"), 0)
        self.assertGreater(n("ssh.pqc"), 0)
        self.assertGreater(n("isakmp.pqc"), 0)
        self.assertGreater(n("isakmp.notify.error"), 0)
        self.assertEqual(n("esp.spi == 3237998081"), 38)
        self.assertEqual(n("macsec.encrypted == 0"), 10)
        self.assertGreater(n("mka"), 0)
        self.assertGreater(n("x509af"), 0)

    def test_cli_json_and_html(self):
        self.assertIn("PQC readiness:", text_report(A, color=False))
        d = json.loads(json.dumps(A.to_dict(), default=str))
        self.assertTrue(d["crypto"]["sessions"])
        self.assertIn("Crypto · PQC", render(A.to_dict()))

    @unittest.skipUnless(os.path.exists(os.path.join(ROOT, "pcap_list", "ISE", "EAP-TLS.pcap")), "sample capture not present")
    def test_real_eap_tls_capture(self):
        a = analyze_file(os.path.join(ROOT, "pcap_list", "ISE", "EAP-TLS.pcap"))
        certs = {c["cn"]: c for c in a.crypto["certificates"]}
        self.assertEqual(certs["radius.mordor"]["sig_alg"], "sha1WithRSAEncryption")
        self.assertIn("client", certs["perry.mordor"]["context"])


if __name__ == "__main__":
    unittest.main()
