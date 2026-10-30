"""Cryptographic posture and post-quantum (PQC) readiness expert.

Builds one inventory of every key exchange seen in the capture - TLS, SSH, IKE/IPsec, MACsec/MKA and the
TLS inside EAP (EAP-TLS / PEAP / TTLS) - classifies each as pqc / hybrid / draft / classical / weak
(``protocols.pqc``), checks every X.509 certificate, and raises findings for PQC negotiation problems
(offered but not selected, HelloRetryRequest, large ClientHellos dropped by middleboxes), weak algorithms,
IKE failures, ESP / MACsec sequence anomalies and MKA peers that never become live.
"""
from __future__ import annotations

import time
from collections import defaultdict

from ..knowledge import make
from ..protocols import ike, pqc, ssh, tls, x509

DAY = 86400.0
SSH_PSEUDO = ("ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com")


def _session(proto, client, server, name, no, t, **kw):
    s = {"proto": proto, "client": client, "server": server, "name": name, "no": no, "t": round(t, 6),
         "offered": [], "offered_status": "unknown", "kex": None, "kex_status": "unknown",
         "auth": None, "auth_status": "unknown", "cipher": None, "result": "unknown", "notes": [], "packets": [no]}
    s.update(kw)
    return s


def run(ctx) -> None:
    sessions: list = []
    certs: list = []
    _tls(ctx, sessions, certs)
    _ssh(ctx, sessions)
    _ike(ctx, sessions)
    _esp(ctx)
    mka = _macsec(ctx, sessions)
    _eap_tls(ctx, sessions, certs)
    _certificates(ctx, certs)
    _summary(ctx, sessions, certs, mka)


def _emit(ctx, fid, items, text, **kw):
    if items:
        ctx.findings.append(make(fid, text, packets=[n for s in items[:20] for n in s.get("packets", [s.get("no")])][:40],
                                 ts=min(ctx.t0 + s["t"] for s in items), count=len(items),
                                 entities=sorted({s.get("name") or s.get("server") or "?" for s in items})[:15], **kw))


# ------------------------------------------------------------------ TLS ---
def _tls(ctx, sessions, certs):
    by_stream: dict = {}
    for p in ctx.packets:
        d = p.layers.get("tls")
        if not d or p.tcp is None:
            continue
        sid = p.tcp.stream
        st = ctx.flows.streams[sid]
        if "client_hello" in d:
            ch = d["client_hello"]
            s = by_stream.get(sid)
            if s is None or s.get("final"):
                s = by_stream[sid] = _session("TLS", st.client, f"{st.server}:{st.sport}", ch["sni"] or st.server,
                                              p.no, p.rel_ts, stream=sid, ch=[])
            s["ch"].append(ch)
            s["packets"].append(p.no)
            s["offered"] = ch.get("groups", [])
            s["offered_status"] = pqc.best(pqc.tls_group(g)[1] for g in ch.get("group_codes", []))
            s.setdefault("key_shares", ch.get("key_shares", []))   # the first ClientHello's shares explain an HRR
            s["ch_len"] = ch.get("length")
            s["ech"] = s.get("ech") or ch.get("ech")
            s["pqc_sigs_offered"] = ch.get("pqc_sigs_offered", [])
        s = by_stream.get(sid)
        if s is None:
            if "server_hello" not in d and not d.get("certificates"):
                continue
            # ClientHello not decodable (SSLv2-format hello, capture started mid-handshake): start from the server side
            s = by_stream[sid] = _session("TLS", st.client, f"{st.server}:{st.sport}", st.server, p.no, p.rel_ts, stream=sid, ch=[])
        if "server_hello" in d:
            sh = d["server_hello"]
            s["packets"].append(p.no)
            if sh.get("hrr"):
                s["hrr"] = sh.get("group")
                s["notes"].append(f"HelloRetryRequest for {sh.get('group')}")
            else:
                s["kex"], s["kex_status"] = tls.key_exchange(sh)
                s["cipher"] = f"0x{sh['cipher']:04x}"
                s["version"] = sh["version"]
                s["result"] = "ok"
        if d.get("certificates"):
            chain = d["certificates"]
            leaf = chain[0]
            s["auth"], s["auth_status"] = leaf["sig_alg"], leaf["sig_status"]
            s["cert_key"] = f"{leaf['key_alg']}{'-' + str(leaf['key_size']) if leaf['key_size'] else ''}"
            for i, c in enumerate(chain):
                certs.append({**c, "context": f"TLS {s['name']}", "role": "leaf" if i == 0 else "chain",
                              "no": p.no, "ts": p.ts, "server": s["server"], "decrypted": bool(d.get("certificates_decrypted"))})
        if "alert" in d and s["result"] == "unknown":
            s["result"] = f"alert {d['alert']['description']}"
    for sid, s in by_stream.items():
        st = ctx.flows.streams[sid]
        if s["result"] == "unknown":
            s["result"] = "reset" if st.rst else "no ServerHello"
        s["retransmissions"] = st.count("retransmission") + st.count("fast_retransmission")
        s.pop("ch", None)
        sessions.append(s)

    F = ctx.findings
    q = [s for s in by_stream.values() if s["kex_status"] in pqc.QUANTUM_SAFE]
    sel = lambda s: s["kex_status"] not in ("unknown",) and s["result"] == "ok"  # noqa: E731
    not_sel = [s for s in by_stream.values() if s["offered_status"] in ("pqc", "hybrid") and sel(s) and s["kex_status"] not in pqc.QUANTUM_SAFE]
    _emit(ctx, "pqc_offered_not_selected", not_sel,
          f"{len(not_sel)} TLS session(s) where the client offered a post-quantum key exchange but the server chose a classical one: " +
          "; ".join(f"{s['name']} → {s['kex']} (offered {', '.join(g for g in s['offered'] if pqc.tls_group_status(g) != 'classical')[:60]})"
                    for s in not_sel[:5]))
    hrr = [s for s in by_stream.values() if s.get("hrr")]
    _emit(ctx, "pqc_hello_retry", hrr, f"{len(hrr)} TLS handshake(s) needed a HelloRetryRequest (one extra round trip): " +
          "; ".join(f"{s['name']}: server asked for {s['hrr']} (client sent key shares {', '.join(k['group'] for k in s.get('key_shares', [])) or 'none'})"
                    for s in hrr[:5]))
    draft = [s for s in by_stream.values() if s["kex_status"] == "draft" or
             any(pqc.tls_group_status(g) == "draft" for g in s["offered"])]
    _emit(ctx, "pqc_draft_kyber", draft, f"{len(draft)} TLS session(s) offer or use a pre-standard Kyber codepoint: " +
          "; ".join(f"{s['name']} ({s['kex'] if s['kex_status'] == 'draft' else 'offered'})" for s in draft[:5]))
    blocked = []
    for s in by_stream.values():
        big = (s.get("ch_len") or 0) > 1400 or any(k["len"] >= 800 for k in s.get("key_shares", []))
        if s["offered_status"] in ("pqc", "hybrid", "draft") and big and s["result"] in ("no ServerHello", "reset"):
            st = ctx.flows.streams[s["stream"]]
            s["blocked_evidence"] = {"retransmissions": s["retransmissions"], "rst": st.rst, "ch_len": s.get("ch_len"),
                                     "segments": len(s["packets"])}
            blocked.append(s)
    _emit(ctx, "pqc_clienthello_blocked", blocked,
          f"{len(blocked)} TLS connection(s) died right after a large post-quantum ClientHello: " +
          "; ".join(f"{s['name']} ({s.get('ch_len')} byte ClientHello, {s['retransmissions']} retransmission(s), "
                    f"{'RST' if ctx.flows.streams[s['stream']].rst else 'no ServerHello'})" for s in blocked[:5]))
    ech = [s for s in by_stream.values() if s.get("ech")]
    _emit(ctx, "tls_ech_in_use", ech, f"{len(ech)} ClientHello(s) carry Encrypted Client Hello (ECH): the real server name is "
          f"hidden; the visible SNI is the client-facing (outer) name: " + ", ".join(sorted({s['name'] for s in ech})[:6]))
    ctx._pqc_tls = {"quantum_safe": q, "blocked": blocked, "not_selected": not_sel}


# ------------------------------------------------------------------ SSH ---
def _ssh(ctx, sessions):
    by_stream: dict = {}
    for p in ctx.packets:
        d = p.layers.get("ssh")
        if not d or p.tcp is None:
            continue
        st = ctx.flows.streams[p.tcp.stream]
        s = by_stream.get(st.id)
        if s is None:
            s = by_stream[st.id] = _session("SSH", st.client, f"{st.server}:{st.sport}", f"{st.server}:{st.sport}",
                                            p.no, p.rel_ts, stream=st.id, kexinit={})
        side = "client" if p.src == st.client and p.sport == st.cport else "server"
        s["packets"].append(p.no)
        for m in d["messages"]:
            if m["type"] == "banner":
                s[f"{side}_banner"] = m["banner"]
                s[f"{side}_proto"] = m["proto_version"]
            elif m["type"] == "KEXINIT" and "kex" in m:
                s["kexinit"][side] = m
            elif m["type"] == "DISCONNECT":
                s["result"] = f"disconnect {m.get('reason')}"
                s["notes"].append(f"{side} DISCONNECT {m.get('reason')}: {m.get('description', '')}")
            elif m["type"] == "NEWKEYS" and s["result"] == "unknown":
                s["result"] = "ok"
    F_weak, F_terrapin, F_old, F_disc = [], [], [], []
    for s in by_stream.values():
        c, sv = s["kexinit"].get("client"), s["kexinit"].get("server")
        s["name"] = f"{s['server']} " + (s.get("server_banner") or "")[8:60]
        if c:
            real = [k for k in c["kex"] if k not in SSH_PSEUDO]
            s["offered"] = real
            s["offered_status"] = pqc.best(pqc.ssh_kex(k) for k in real)
        if c and sv:
            kex = ssh.negotiate([k for k in c["kex"] if k not in SSH_PSEUDO], sv["kex"])
            hk = ssh.negotiate(c["hostkey"], sv["hostkey"])
            enc = ssh.negotiate(c["enc_c2s"], sv["enc_c2s"])
            mac = ssh.negotiate(c["mac_c2s"], sv["mac_c2s"])
            s["kex"], s["kex_status"] = kex or "no common algorithm", ssh.kex_status(kex) if kex else "unknown"
            s["auth"], s["auth_status"] = hk, pqc.SSH_HOSTKEY.get(hk or "", "unknown")
            aead = enc and ("gcm" in enc or "chacha20-poly1305" in enc)
            s["cipher"] = (enc or "no common cipher") + ("" if aead or not enc else f" / {mac}")
            if kex is None:
                s["result"] = "no common key exchange"
            weak = [a for a in (kex, hk, enc, None if aead else mac) if a and (
                pqc.ssh_kex(a) == "weak" or pqc.SSH_HOSTKEY.get(a) == "weak" or a in pqc.SSH_WEAK_CIPHERS or a in pqc.SSH_WEAK_MACS)]
            offered_weak = sorted({a for lst in ("kex", "hostkey", "enc_c2s", "mac_c2s") for side in (c, sv)
                                   for a in side[lst] if pqc.ssh_kex(a) == "weak" or pqc.SSH_HOSTKEY.get(a) == "weak"
                                   or a in pqc.SSH_WEAK_CIPHERS or a in pqc.SSH_WEAK_MACS})
            if weak or offered_weak:
                s["weak_selected"], s["weak_offered"] = weak, offered_weak
                F_weak.append(s)
            strict = all(x in side["kex"] for x, side in zip(ssh.STRICT, (c, sv)))
            vulnerable = enc and ("chacha20-poly1305" in enc or ("-cbc" in enc and mac and "-etm" in mac))
            if vulnerable and not strict:
                s["notes"].append("Terrapin-exposed (CVE-2023-48795)")
                F_terrapin.append(s)
        for side in ("client", "server"):
            if s.get(f"{side}_proto") and s[f"{side}_proto"] not in ("2.0", "1.99"):
                F_old.append(s)
                break
        if s["result"].startswith("disconnect") or s["result"] == "no common key exchange":
            F_disc.append(s)
        s.pop("kexinit", None)
        sessions.append(s)
    _emit(ctx, "ssh_weak_algorithms", F_weak, "; ".join(
        f"{s['client']} → {s['server']}: " + (f"NEGOTIATED {', '.join(s['weak_selected'])}" if s["weak_selected"]
                                             else f"offered {', '.join(s['weak_offered'][:4])}") for s in F_weak[:5]),
          severity="high" if any(s["weak_selected"] for s in F_weak) else None)
    _emit(ctx, "ssh_terrapin", F_terrapin, f"{len(F_terrapin)} SSH session(s) negotiated ChaCha20-Poly1305 or CBC+EtM without "
          "strict key exchange on both sides: " + "; ".join(f"{s['server']} ({s['cipher']})" for s in F_terrapin[:5]))
    _emit(ctx, "ssh_v1", F_old, "SSH protocol 1 in use: " + "; ".join(
        f"{s.get('client_banner') or s['client']} ↔ {s.get('server_banner') or s['server']}" for s in F_old[:5]))
    _emit(ctx, "ssh_kex_failure", F_disc, "; ".join(f"{s['client']} → {s['server']}: {s['result']}" +
                                                   (f" ({s['notes'][-1]})" if s["notes"] else "") for s in F_disc[:5]))


# ------------------------------------------------------------ IKE / ESP ---
def _ike(ctx, sessions):
    sas: dict = {}
    for p in ctx.packets:
        d = p.layers.get("ike")
        if not d:
            continue
        s = sas.get(d["ispi"])
        if s is None:
            init_ip = p.src if d.get("initiator") else p.dst
            resp_ip = p.dst if d.get("initiator") else p.src
            s = sas[d["ispi"]] = _session(f"IKEv{d['version']}", init_ip, resp_ip, f"{init_ip} ↔ {resp_ip}", p.no, p.rel_ts,
                                          requests=defaultdict(list), responses=defaultdict(list), errors=[],
                                          exchanges=[], frag_supported=set(), intermediate=False, ike_frags=0,
                                          ip_fragmented=False, natt=4500 in (p.sport, p.dport))
        s["packets"].append(p.no)
        key = (d["exchange"], d["msg_id"])
        (s["responses"] if d.get("response") else s["requests"])[key].append(p.no)
        if d["exchange"] not in s["exchanges"]:
            s["exchanges"].append(d["exchange"])
        if d["exchange"] == "IKE_INTERMEDIATE":
            s["intermediate"] = True
        if d.get("frag"):
            s["ike_frags"] += 1
        if p.ip_mf or p.ip_frag_offset or "reassembled" in p.tags:
            s["ip_fragmented"] = True
        for n in d["notify"]:
            if n["error"]:
                s["errors"].append({**n, "no": p.no, "from": p.src})
            elif n["type"] == "IKEV2_FRAGMENTATION_SUPPORTED":
                s["frag_supported"].add("responder" if d.get("response") else "initiator")
        if d["proposals"]:
            name, status = ike.kex_summary(d)
            if d.get("response"):
                s["kex"], s["kex_status"] = name, status
                s["cipher"] = ", ".join(t["name"] for p_ in d["proposals"][:1] for t in p_["transforms"] if t["type"] in ("ENCR", "INTEG"))
                s["selected"] = d["proposals"][0]["transforms"] if d["proposals"] else []
            elif d["exchange"] in ("IKE_SA_INIT", "Main Mode", "Aggressive Mode") and not s["offered"]:
                s["offered"] = [f"{t['type']}={t['name']}" for p_ in d["proposals"] for t in p_["transforms"]][:30]
                s["offered_status"] = pqc.best(t["status"] for p_ in d["proposals"] for t in p_["transforms"]
                                               if t["type"] == "KE" or t["type"].startswith("ADDKE"))
                s["offered_transforms"] = [t for p_ in d["proposals"] for t in p_["transforms"]]
        if d["exchange"] == "Aggressive Mode":
            s["aggressive"] = True
    fail, noresp, weak, v1, frag = [], [], [], [], []
    for s in sas.values():
        unanswered = [k for k in s["requests"] if k not in s["responses"]]
        retx = sum(len(v) - 1 for v in s["requests"].values())
        s["retransmissions"] = retx
        if s["errors"]:
            s["result"] = ", ".join(dict.fromkeys(e["type"] for e in s["errors"]))
            fail.append(s)
        elif unanswered and retx:
            s["result"] = f"no response to {unanswered[0][0]}"
            noresp.append(s)
        elif s["kex"]:
            s["result"] = "ok"
        w = [t["name"] for t in s.get("selected", []) if t["status"] == "weak"]
        if not s.get("selected"):
            w = sorted({t["name"] for t in s.get("offered_transforms", []) if t["status"] == "weak"})
            s["weak_offered_only"] = bool(w)
        if w or s.get("aggressive"):
            s["weak"] = w + (["IKEv1 Aggressive Mode"] if s.get("aggressive") else [])
            weak.append(s)
        if s["proto"] == "IKEv1":
            v1.append(s)
        large = s["offered_status"] in ("pqc", "hybrid") or s["kex_status"] in pqc.QUANTUM_SAFE
        if large and (len(s["frag_supported"]) < 2 or s["ip_fragmented"]) and (s in noresp or s["ip_fragmented"]):
            frag.append(s)
        s["frag_supported"] = sorted(s["frag_supported"])
        for k in ("requests", "responses", "offered_transforms", "selected"):
            s.pop(k, None)
        sessions.append(s)
    _emit(ctx, "ike_negotiation_failure", fail, "; ".join(
        f"{s['client']} → {s['server']}: {s['result']}" +
        (f" (initiator proposed {s['offered_status']} key exchange)" if s["offered_status"] in pqc.QUANTUM_SAFE else "") +
        "".join(f"; responder accepts {e['accepted_group']}" for e in s["errors"] if e.get("accepted_group"))
        for s in fail[:5]))
    _emit(ctx, "ike_no_response", noresp, "; ".join(f"{s['client']} → {s['server']}: {s['result']} "
                                                    f"({s['retransmissions']} retransmission(s))" for s in noresp[:5]))
    _emit(ctx, "ike_weak_crypto", weak, "; ".join(f"{s['client']} ↔ {s['server']}: {', '.join(s['weak'])}"
                                                  + (" (offered)" if s.get("weak_offered_only") else "") for s in weak[:5]),
          severity="high" if any(not s.get("weak_offered_only") for s in weak) else None)
    _emit(ctx, "ike_v1_in_use", v1, f"{len(v1)} IKEv1 SA(s): " + ", ".join(s["name"] for s in v1[:6]))
    _emit(ctx, "ike_pqc_fragmentation", frag, "; ".join(
        f"{s['client']} → {s['server']}: ML-KEM key exchange, IKEv2 fragmentation supported by {', '.join(s['frag_supported']) or 'neither peer'}"
        + (", IKE messages IP-fragmented" if s["ip_fragmented"] else "") + f", result: {s['result']}" for s in frag[:5]))


def _esp(ctx):
    sas: dict = {}
    for p in ctx.packets:
        d = p.layers.get("esp")
        if not d or d.get("kind") != "esp":
            continue
        key = (p.src, p.dst, d["spi"])
        s = sas.setdefault(key, {"seqs": {}, "first": p.no, "ts": p.ts, "gaps": 0, "dups": 0, "back": 0, "last": None, "nos": [], "n": 0})
        s["n"] += 1
        seq = d["seq"]
        if seq in s["seqs"]:
            s["dups"] += 1
            s["nos"].append(p.no)
        elif s["last"] is not None:
            if seq > s["last"] + 1:
                s["gaps"] += seq - s["last"] - 1
                s["nos"].append(p.no)
            elif seq < s["last"]:
                s["back"] += 1
        s["seqs"][seq] = p.no
        s["last"] = seq if s["last"] is None else max(s["last"], seq)
    bad = []
    for (src, dst, spi), s in sas.items():
        if s["gaps"] or s["dups"]:
            bad.append({"name": f"{src} → {dst} SPI {spi}", "t": s["ts"] - ctx.t0, "packets": s["nos"][:10] or [s["first"]],
                        "dups": s["dups"],
                        "text": f"{src} → {dst} SPI {spi}: {s['gaps']} missing sequence number(s), {s['dups']} duplicate(s), "
                                f"{s['back']} out of order, of {s['n']} packets"})
    ctx.esp_sas = [{"src": k[0], "dst": k[1], "spi": k[2], "packets": v["n"], "missing": v["gaps"],
                    "duplicates": v["dups"], "reordered": v["back"]} for k, v in sas.items()]
    if bad:
        _emit(ctx, "esp_sequence_anomaly", bad, "; ".join(b["text"] for b in bad[:5]),
              severity="high" if any(b["dups"] for b in bad) else None)


# --------------------------------------------------------- MACsec / MKA ---
def _macsec(ctx, sessions):
    scs: dict = {}
    for p in ctx.packets:
        d = p.layers.get("macsec")
        if not d:
            continue
        key = (d.get("sci") or p.eth_src, d["an"])
        s = scs.setdefault(key, {"src": p.eth_src, "sci": d.get("sci") or p.eth_src, "an": d["an"], "first": p.no,
                                 "ts": p.ts, "pkts": 0, "gaps": 0, "replays": 0, "last": None, "max_pn": 0,
                                 "modes": set(), "nos": []})
        s["pkts"] += 1
        s["modes"].add(d["mode"])
        pn = d["pn"]
        if s["last"] is not None:
            if pn <= s["last"]:
                s["replays"] += 1
                s["nos"].append(p.no)
            elif pn > s["last"] + 1:
                s["gaps"] += pn - s["last"] - 1
                s["nos"].append(p.no)
        s["last"] = pn if s["last"] is None else max(s["last"], pn)
        s["max_pn"] = max(s["max_pn"], pn)
    ctx.macsec_scs = [{"sci": s["sci"], "an": s["an"], "src": s["src"], "packets": s["pkts"], "missing_pn": s["gaps"],
                       "replayed_pn": s["replays"], "max_pn": s["max_pn"], "modes": sorted(s["modes"])} for s in scs.values()]
    items = lambda cond: [{"name": f"SCI {s['sci']} AN {s['an']}", "t": s["ts"] - ctx.t0,  # noqa: E731
                           "packets": s["nos"][:10] or [s["first"]], **s} for s in scs.values() if cond(s)]
    integ = items(lambda s: "integrity-only" in s["modes"])
    _emit(ctx, "macsec_integrity_only", integ, f"{len(integ)} MACsec secure channel(s) send integrity-only frames "
          "(E=0, C=0: authenticated but NOT encrypted): " + ", ".join(i["name"] for i in integ[:6]))
    pn = items(lambda s: s["gaps"] or s["replays"])
    _emit(ctx, "macsec_pn_anomaly", pn, "; ".join(f"{i['name']} from {i['src']}: {i['gaps']} missing PN(s), "
                                                  f"{i['replays']} repeated/old PN(s) of {i['pkts']} frames" for i in pn[:5]),
          severity="high" if any(i["replays"] for i in pn) else None)
    exh = items(lambda s: s["max_pn"] >= 0xC0000000)
    _emit(ctx, "macsec_pn_exhaustion", exh, "; ".join(f"{i['name']}: PN {i['max_pn']:,} of 4,294,967,295 "
                                                      f"({i['max_pn'] / 0xFFFFFFFF:.0%} used)" for i in exh[:5]))
    # ------- MKA (EAPOL-MKA MKPDUs): one participant per (source MAC, CKN)
    parts: dict = {}
    for p in ctx.packets:
        m = (p.layers.get("eapol") or {}).get("mka")
        if not m:
            continue
        k = (p.eth_src, m["ckn"])
        s = parts.setdefault(k, {"mac": p.eth_src, "ckn": m["ckn"], "first": p.no, "ts": p.ts, "pdus": 0, "live": set(),
                                 "potential": set(), "key_server": False, "priority": m["key_server_priority"],
                                 "cipher": None, "sak": 0, "member": m["member_id"], "capability": m["capability"],
                                 "desired": m["macsec_desired"], "nos": []})
        s["pdus"] += 1
        s["live"] |= set(m["live_peers"])
        s["potential"] |= set(m["potential_peers"])
        s["key_server"] = s["key_server"] or m["key_server"]
        if m["sak_distributed"]:
            s["sak"] += 1
            s["cipher"] = m["cipher_suite"]
            s["confidentiality_offset"] = m.get("confidentiality_offset")
        if len(s["nos"]) < 10:
            s["nos"].append(p.no)
    out = []
    for s in parts.values():
        ckn_peers = [o for o in parts.values() if o is not s and o["ckn"] == s["ckn"]]
        other_ckn = [o for o in parts.values() if o["ckn"] != s["ckn"]]
        out.append({"mac": s["mac"], "ckn": s["ckn"][:32], "mkpdus": s["pdus"], "live_peers": len(s["live"]),
                    "potential_peers": len(s["potential"]), "key_server": s["key_server"], "priority": s["priority"],
                    "cipher": s["cipher"], "sak_distributions": s["sak"], "capability": s["capability"],
                    "macsec_desired": s["desired"], "ckn_mismatch": bool(other_ckn and not ckn_peers)})
        if s["cipher"]:
            sessions.append(_session("MACsec/MKA", s["mac"], "", f"CKN {s['ckn'][:16]}…", s["first"], s["ts"] - ctx.t0,
                                     kex="MKA (pre-shared CAK, AES key wrap)", kex_status="classical",
                                     cipher=s["cipher"], result="SAK distributed", packets=s["nos"],
                                     notes=["symmetric keys: quantum-resistant if the CAK is 256-bit"]))
    ctx.mka = out
    dead = [{"name": f"{s['mac']} (CKN {s['ckn'][:16]}…)", "t": s["ts"] - ctx.t0, "packets": s["nos"], **s}
            for s in parts.values() if s["pdus"] >= 3 and not s["live"]]
    _emit(ctx, "mka_no_live_peer", dead, "; ".join(
        f"{d['name']}: {d['pdus']} MKPDUs, no live peer" + (f", {len(d['potential'])} potential peer(s)" if d["potential"] else "") +
        (" — another participant uses a different CKN" if any(o["ckn"] != d["ckn"] for o in parts.values()) else "")
        for d in dead[:5]))
    return out


# --------------------------------------------- EAP-TLS / PEAP / TTLS ----
def _eap_tls(ctx, sessions, certs):
    flows: dict = {}
    for p in ctx.packets:
        e = (p.layers.get("eapol") or {}).get("eap") or (p.layers.get("radius") or {}).get("eap")
        if not isinstance(e, dict) or "tls_data" not in e:
            continue
        data = e.pop("tls_data")
        src = p.eth_src if "eapol" in p.layers else p.src
        dst = p.eth_dst if "eapol" in p.layers else p.dst
        f = flows.setdefault((src, dst), {"buf": bytearray(), "ids": set(), "nos": [], "method": e.get("method"), "msgs": [],
                                          "side": "server" if e["code"] == "Request" else "client"})
        if e["id"] in f["ids"] and data:
            continue                       # retransmitted request
        f["ids"].add(e["id"])
        f["buf"] += data
        f["nos"].append(p.no)
        if not e["tls_flags"]["more"] and f["buf"]:
            f["msgs"].append((bytes(f["buf"]), p))
            f["buf"] = bytearray()
    for (src, dst), f in flows.items():
        for buf, p in f["msgs"]:
            hs = bytearray()
            off = 0
            while off + 5 <= len(buf):
                ln = int.from_bytes(buf[off + 3:off + 5], "big")
                if buf[off] == 22:
                    hs += buf[off + 5:off + 5 + ln]
                off += 5 + ln
            i = 0
            while i + 4 <= len(hs):
                ht, hl = hs[i], int.from_bytes(hs[i + 1:i + 4], "big")
                body = bytes(hs[i + 4:i + 4 + hl])
                if ht == 11 and len(body) == hl:
                    for j, c in enumerate(x509.parse_chain(body)):
                        certs.append({**c, "context": f"{f['method']} {f['side'] if j == 0 else 'chain'} ({src} → {dst})",
                                      "role": "leaf" if j == 0 else "chain", "no": p.no, "ts": p.ts, "server": src})
                elif ht == 2:
                    try:
                        sh = tls._server_hello(body)
                        kx, st = tls.key_exchange(sh)
                        sessions.append(_session(f["method"] or "EAP-TLS", dst, src, f"{f['method']} {src}", p.no, p.rel_ts,
                                                 kex=kx, kex_status=st, cipher=f"0x{sh['cipher']:04x}",
                                                 result="ok", packets=f["nos"][:10], version=sh["version"]))
                    except (IndexError, ValueError):
                        pass
                i += 4 + hl


# --------------------------------------------------------- certificates ---
def _certificates(ctx, certs):
    seen: set = set()
    uniq = []
    future = ctx.packets and ctx.packets[-1].ts > time.time() + DAY
    for c in certs:
        if c["sha256"] in seen:
            continue
        seen.add(c["sha256"])
        issues = []
        now = c["ts"]
        if c["not_after"] and c["not_after"] < now:
            issues.append(f"expired {(now - c['not_after']) / DAY:.0f} day(s) before the capture"
                          + (f" (capture clock says {time.strftime('%Y-%m-%d', time.gmtime(now))}, in the future: "
                             "check the capture host's clock)" if future else ""))
        elif c["not_after"] and c["not_after"] - now < 30 * DAY:
            issues.append(f"expires in {(c['not_after'] - now) / DAY:.0f} day(s)")
        if c["not_before"] and c["not_before"] > now:
            issues.append("not yet valid (check clocks)")
        if c["self_signed"] and c["role"] == "leaf":
            issues.append("self-signed")
        if c["sig_status"] == "weak" and not c["self_signed"]:
            issues.append(f"weak signature {c['sig_alg']}")
        if c["key_alg"] == "RSA" and c["key_size"] and c["key_size"] < 2048 or c["key_alg"] == "DSA":
            issues.append(f"weak key {c['key_alg']}-{c['key_size']}")
        c["issues"] = issues
        c["quantum"] = pqc.worst([c["key_status"], c["sig_status"]])
        uniq.append(c)
    ctx.certificates = uniq
    item = lambda c: {"name": c["cn"] or c["subject"][:60], "t": c["ts"] - ctx.t0, "packets": [c["no"]]}  # noqa: E731
    expired = [c for c in uniq if any(i.startswith(("expired", "not yet")) for i in c["issues"])]
    _emit(ctx, "x509_expired", [item(c) for c in expired], "; ".join(
        f"{c['cn'] or c['subject']} [{c['context']}]: {', '.join(i for i in c['issues'] if i.startswith(('expired', 'not yet')))}"
        for c in expired[:5]))
    soon = [c for c in uniq if any(i.startswith("expires in") for i in c["issues"])]
    _emit(ctx, "x509_expiring_soon", [item(c) for c in soon], "; ".join(
        f"{c['cn'] or c['subject']} [{c['context']}]: {next(i for i in c['issues'] if i.startswith('expires in'))}" for c in soon[:5]))
    selfs = [c for c in uniq if "self-signed" in c["issues"]]
    _emit(ctx, "x509_self_signed", [item(c) for c in selfs], "; ".join(f"{c['cn'] or c['subject']} [{c['context']}]" for c in selfs[:5]))
    weak = [c for c in uniq if any(i.startswith("weak") for i in c["issues"])]
    _emit(ctx, "x509_weak_crypto", [item(c) for c in weak], "; ".join(
        f"{c['cn'] or c['subject']} [{c['context']}]: {', '.join(i for i in c['issues'] if i.startswith('weak'))}" for c in weak[:5]))
    pq = [c for c in uniq if c["quantum"] == "pqc" or c["sig_status"] == "pqc"]
    _emit(ctx, "x509_pqc_certificate", [item(c) for c in pq], "; ".join(
        f"{c['cn'] or c['subject']}: key {c['key_alg']}, signed with {c['sig_alg']}" for c in pq[:6]))


# -------------------------------------------------------------- summary ---
def _summary(ctx, sessions, certs, mka):
    known = [s for s in sessions if s["kex_status"] != "unknown"]
    counts = defaultdict(int)
    for s in known:
        counts[s["kex_status"]] += 1
    safe = counts["pqc"] + counts["hybrid"]
    score = round(100 * (safe + 0.5 * counts["draft"]) / len(known)) if known else None
    pqc_clients = sorted({s["client"] for s in sessions if s["offered_status"] in pqc.QUANTUM_SAFE})
    ctx.crypto = {
        "sessions": sessions[:2000], "certificates": [{k: v for k, v in c.items()} for c in ctx.certificates[:500]],
        "esp": ctx.esp_sas[:500], "macsec": ctx.macsec_scs[:500], "mka": mka[:200],
        "readiness": {"score": score, "sessions": len(sessions), "known": len(known), "counts": dict(counts),
                      "quantum_safe": safe, "exposed": counts["classical"] + counts["weak"],
                      "pqc_capable_clients": pqc_clients[:100],
                      "by_protocol": _by_proto(sessions)},
    }
    if not known:
        return
    q = [s for s in known if s["kex_status"] in pqc.QUANTUM_SAFE]
    _emit(ctx, "pqc_kex_in_use", q, f"{len(q)} of {len(known)} key exchange(s) are quantum-safe (hybrid or pure ML-KEM): " +
          "; ".join(f"{s['proto']} {s['name']} → {s['kex']}" for s in q[:6]))
    exposed = [s for s in known if s["kex_status"] in ("classical", "weak") and s["proto"] != "MACsec/MKA"]
    _emit(ctx, "quantum_vulnerable_kex", exposed,
          f"{len(exposed)} of {len(known)} key exchange(s) use only classical algorithms "
          f"(PQC readiness score {score}/100): " + ", ".join(
              f"{proto} {n}" for proto, n in sorted(_count(exposed).items(), key=lambda x: -x[1])))


def _count(items):
    out = defaultdict(int)
    for s in items:
        out[s["proto"]] += 1
    return out


def _by_proto(sessions):
    out: dict = {}
    for s in sessions:
        d = out.setdefault(s["proto"], defaultdict(int))
        d[s["kex_status"]] += 1
    return {k: dict(v) for k, v in out.items()}
