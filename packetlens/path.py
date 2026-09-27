"""Source-to-destination path inference.

A capture only sees the link it was taken on, so the path of a flow is rebuilt from
evidence inside the packets:

* the capture link's two ends: CDP/LLDP announcements, frame MAC addresses
* how many routers each side is away: initial TTL (32/64/128/255) minus received TTL
* which router handed a packet to the capture link: the frame's source MAC, resolved
  through CDP, ARP and routing-protocol speakers (a TTL showing 0 hops means the IP
  belongs to the device that sent the frame)
* the exact hop list where traceroute probes were captured (ICMP time-exceeded reporters)
* tunnel segments: GRE/VXLAN outer endpoints; an outer TTL showing 0 hops means the
  frame's sender is the encapsulating router
* where a flow broke: ICMP errors name the reporting router, RSTs name the resetting side,
  unanswered SYNs/queries place the break beyond the capture point

Every node and link is marked ``observed`` (seen in the capture) or inferred.
Several captures of the same network (one folder) are merged with :func:`stitch`.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from .experts.network import initial_ttl

MAX_FLOWS = 16
MAX_STEPS = 40            # animated packets per flow
CLOUD_AFTER = 3           # more unseen routers than this are drawn as one cloud
TRACEROUTE_PORTS = range(33434, 33535)
CONTROL = {"OSPF": "hellos", "EIGRP": "hellos", "PIM": "hellos / joins", "HSRP": "hellos", "VRRP": "advertisements",
           "ISIS": "hellos", "RIP": "updates", "STP": "BPDUs", "BGP": "keepalives / updates", "IGMP": "queries / reports",
           "CDP": "announcements", "LLDP": "announcements"}
RANK = {"segment": 0, "cloud": 0, "host": 1, "server": 2, "ap": 3, "switch": 4, "router": 5, "l3switch": 6}
ROUTED = ("router", "l3switch")


def _ip(x):
    try:
        return ipaddress.ip_address(x)
    except (ValueError, TypeError):
        return None


def _unicast(ip) -> bool:
    a = _ip(ip)
    if a is None or a.is_multicast or a.is_unspecified:
        return False
    return not (a.version == 4 and str(a).endswith(".255"))          # limited / directed broadcast


def _group(mac) -> bool:
    return bool(mac) and int(mac[:2], 16) & 1 == 1


def _probe(p) -> bool:
    return p.ip_proto == 17 and p.dport in TRACEROUTE_PORTS


def _hops(ttls) -> int | None:
    """Routed hops between the sender and the capture point (largest TTL = the least-decremented packet).
    TTL 1-2 at the capture point is a link-local protocol sent that way on purpose (eBGP, OSPF, HSRP), not a long path."""
    ttls = [t for t in ttls if t is not None]
    if not ttls:
        return None
    t = max(ttls)
    return 0 if t <= 2 else initial_ttl(t) - t


class Topology:
    """Device registry with MAC/IP aliases so every sighting of a device merges into one node."""

    def __init__(self, capture: str):
        self.capture = capture
        self.nodes: dict[str, dict] = {}
        self.by_mac: dict[str, str] = {}
        self.by_ip: dict[str, str] = {}
        self.links: dict[tuple, dict] = {}
        self.hops_of: dict[str, int] = {}      # IP -> routed hops to the capture point (all its non-probe packets)

    def node(self, nid: str, kind: str = "host", label: str | None = None, *, mac=None, ip=None,
             observed=True, evidence: str | None = None, role: str | None = None) -> str:
        if nid not in self.nodes:           # a new name for a device already known by MAC/IP merges into it
            nid = self.by_mac.get(mac) or self.by_ip.get(ip) or nid
        n = self.nodes.setdefault(nid, {"id": nid, "label": label or nid, "kind": kind, "ips": [], "macs": [],
                                        "roles": [], "observed": observed, "evidence": []})
        if RANK.get(kind, 0) > RANK.get(n["kind"], 0):
            n["kind"] = kind
        n["observed"] = n["observed"] or observed
        if mac and not _group(mac):
            if mac not in n["macs"]:
                n["macs"].append(mac)
            self.by_mac.setdefault(mac, nid)
        if ip and _unicast(ip):
            if ip not in n["ips"]:
                n["ips"].append(ip)
            self.by_ip.setdefault(ip, nid)
        if evidence and evidence not in n["evidence"] and len(n["evidence"]) < 8:
            n["evidence"].append(evidence)
        if role and role not in n["roles"]:
            n["roles"].append(role)
        return nid

    def link(self, a: str, b: str, kind: str = "l2", observed=True, label: str = "", capture: bool = False) -> None:
        if a == b or a is None or b is None:
            return
        k = tuple(sorted((a, b)))
        ln = self.links.setdefault(k, {"a": k[0], "b": k[1], "kind": kind, "observed": observed, "label": label,
                                       "captures": []})
        ln["observed"] = ln["observed"] or observed
        ln["label"] = ln["label"] or label
        if capture and self.capture not in ln["captures"]:
            ln["captures"].append(self.capture)
        if kind == "tunnel":
            ln["kind"] = "tunnel"


def infer(a, capture: str | None = None) -> dict:
    cap = capture or a.source
    T = Topology(cap)
    _identities(a, T)
    edge = _capture_link(a, T)
    flows = []
    trace = _traceroute(a, T, edge)
    if trace:
        flows.append(trace)
    flows += _tunnel_flows(a, T)
    flows += _ip_flows(a, T, edge, skip={(f["src_ip"], f["dst_ip"]) for f in flows})
    flows += _service_flows(a, T, edge)
    flows += _control_flows(a, T, edge)
    flows = flows[:MAX_FLOWS]
    for f in flows:
        for x, y in zip(f["hops"], f["hops"][1:]):
            if (x, y) in f.get("tunnel_hops", ()):
                continue
            nx, ny = T.nodes[x], T.nodes[y]
            T.link(x, y, "l3" if nx["kind"] in ROUTED and ny["kind"] in ROUTED else "l2",
                   observed=nx["observed"] and ny["observed"] and f.get("observed_links", True))
        f.pop("tunnel_hops", None)
        f.pop("observed_links", None)
    for x, y in edge["pairs"]:
        T.link(x, y, capture=True)
    return {"capture": cap, "nodes": list(T.nodes.values()), "links": list(T.links.values()), "flows": flows,
            "notes": _notes(T, edge)}


# ------------------------------------------------------------ identities ----
def _identities(a, T: Topology) -> None:
    pk = a.packets
    # pass 1: discovery protocols name devices; key by MAC because lab devices get renamed mid-capture
    for p in pk:
        for proto in ("cdp", "lldp"):
            d = p.layers.get(proto)
            if not d or not p.eth_src:
                continue
            name = d.get("device_id") or d.get("system_name") or d.get("chassis_id") or p.eth_src
            caps = d.get("capabilities") or []
            plat = d.get("platform") or d.get("system_description") or ""
            kind = ("l3switch" if "Router" in caps and ("Switch" in caps or "Bridge" in caps) else
                    "router" if "Router" in caps else
                    "ap" if "Station" in caps or plat.startswith(("AIR-", "Meraki MR")) else
                    "switch" if "Switch" in caps or "Bridge" in caps else "host")
            nid = T.by_mac.get(p.eth_src)
            if nid is None:
                nid = name if name not in T.nodes else f"{name} ({p.eth_src})"
            nid = T.node(nid, kind, mac=p.eth_src, evidence=f"{proto.upper()}: {plat[:40]} port {d.get('port_id', '?')}")
            T.nodes[nid]["label"] = name                      # latest announced hostname wins
            for ip in d.get("addresses", []):
                T.node(nid, ip=ip)
    # pass 2: roles and addresses from control / service protocols
    ip_macs = defaultdict(Counter)
    ip_ttl = defaultdict(list)
    mac_ips = defaultdict(set)
    for p in pk:
        L = p.layers
        if "arp" in L and L["arp"]["sender_ip"] != "0.0.0.0":      # the sender pair is valid in requests and replies
            T.node(L["arp"]["sender_ip"], "host", mac=L["arp"]["sender_mac"], ip=L["arp"]["sender_ip"], evidence="ARP")
        for proto, role in (("ospf", "OSPF"), ("eigrp", "EIGRP"), ("pim", "PIM"), ("rip", "RIP")):
            if proto in L and p.src:
                rid = L[proto].get("router_id") if proto == "ospf" else None
                nid = T.node(p.src, "router", f"RID {rid}" if rid else None,
                             mac=None if "tunneled" in p.tags else p.eth_src, ip=p.src,
                             evidence=f"{role} speaker" + (f" (router-id {rid})" if rid else ""), role=role)
                if rid and _unicast(rid):
                    T.by_ip.setdefault(rid, nid)
        if "fhrp" in L and p.src:
            f = L["fhrp"]
            T.node(p.src, "router", mac=p.eth_src, ip=p.src, role=f"{f['proto']} {f['state']}",
                   evidence=f"{f['proto']} group {f['group']} VIP {f['vip']}")
        if "isis" in L and L["isis"].get("system_id"):
            T.node(f"IS-IS {L['isis']['system_id']}", "router", mac=p.eth_src, role="IS-IS", evidence="IS-IS hello")
        if ("stp" in L or "dtp" in L) and p.eth_src:
            T.node(p.eth_src, "switch", mac=p.eth_src, role="STP bridge" if "stp" in L else None,
                   evidence="sends BPDUs" if "stp" in L else "sends DTP")
        if p.tcp is not None and 179 in (p.sport, p.dport) and p.src:
            T.node(p.src, "router", ip=p.src, role="BGP", evidence="BGP speaker")
        if "radius" in L:
            srv, nas = (p.dst, p.src) if L["radius"]["code_num"] in (1, 4) else (p.src, p.dst)
            T.node(srv, "server", ip=srv, role="RADIUS server", evidence="answers RADIUS")
            T.node(nas, "switch", ip=nas, role="NAS (authenticator)", evidence="sends RADIUS requests")
        if "dhcp" in L and L["dhcp"]["op"] == 2 and p.src:
            T.node(p.src, "server", ip=p.src, mac=p.eth_src, role="DHCP server", evidence="DHCP OFFER/ACK")
        if p.src and p.eth_src and _unicast(p.src) and "tunneled" not in p.tags and not _probe(p):
            ip_macs[p.src][p.eth_src] += 1
            ip_ttl[p.src].append(p.ttl)
            mac_ips[p.eth_src].add(p.src)
    for t in a.dns_transactions:
        if t["response_no"] is not None:
            T.node(t["server"], "server", ip=t["server"], role="DNS resolver", evidence="answers DNS")
    # an IP whose packets arrive with 0 routed hops belongs to the device that sent the frame
    for ip, macs in ip_macs.items():
        T.hops_of[ip] = _hops(ip_ttl[ip])
        if T.hops_of[ip] == 0:
            mac = macs.most_common(1)[0][0]
            T.node(T.by_mac.get(mac) or T.by_ip.get(ip) or ip, "host", mac=mac, ip=ip, evidence="sends on the capture link")
    # a MAC that forwards packets of many routed-away IPs is a router
    for mac, ips in mac_ips.items():
        routed = [ip for ip in ips if _hops(ip_ttl[ip])]
        if len(routed) >= 2:
            nid = T.by_mac.get(mac) or T.node(f"gw-{mac}", "router", f"Router {mac}", mac=mac)
            n = T.nodes[nid]
            if n["kind"] not in ROUTED:
                n["kind"] = "l3switch" if n["kind"] == "switch" else "router"
            if f"forwards traffic of {len(routed)} remote IPs" not in n["evidence"]:
                n["evidence"].append(f"forwards traffic of {len(routed)} remote IPs")


def _capture_link(a, T: Topology) -> dict:
    """The devices on the link the capture was taken on, and how they connect."""
    ends = []
    for p in a.packets:
        if ("cdp" in p.layers or "lldp" in p.layers) and p.eth_src in T.by_mac:
            nid = T.by_mac[p.eth_src]
            if nid not in ends:
                ends.append(nid)
    wlan = next((p.layers["wlan"] for p in a.packets if "wlan" in p.layers), None)
    if wlan:
        ap = T.node(T.by_mac.get(wlan["bssid"]) or f"AP {wlan['bssid']}", "ap", mac=wlan["bssid"], evidence="802.11 BSSID")
        ends = [ap] + [e for e in ends if e != ap]
    if len(ends) == 2:
        return {"ends": ends, "segment": None, "pairs": [(ends[0], ends[1])],
                "switched": all(T.nodes[e]["kind"] in ("switch", "l3switch") for e in ends)}
    seg = T.node(f"segment:{T.capture}", "segment", "Capture segment", evidence="the link / VLAN this capture was taken on")
    local = ends + [nid for nid, n in T.nodes.items() if n["macs"] and nid != seg and nid not in ends]
    return {"ends": ends, "segment": seg, "pairs": [(seg, e) for e in local], "switched": False}


def _near(T: Topology, edge: dict, nid: str, side: int) -> list:
    """How ``nid`` (a device sending on the capture link) connects to it: extra hops toward the link."""
    if edge["segment"] is not None or nid in edge["ends"] or T.nodes[nid]["kind"] in ("switch", "l3switch"):
        return []
    if edge["switched"]:        # hosts behind a switch-to-switch trunk: one switch per side (which one is inferred)
        return [edge["ends"][side]]
    bridges = [e for e in edge["ends"] if T.nodes[e]["kind"] in ("switch", "l3switch")]
    return bridges if len(bridges) == 1 else []    # not a link end, so it is bridged through the only switch end


# ----------------------------------------------------------------- flows ----
def _side(T: Topology, edge: dict, ip: str, frames: list, side: int) -> list:
    """Nodes from the capture link out to ``ip`` for frames sent BY ``ip``: [device on link, ..., ip]."""
    frames = [p for p in frames if not _probe(p)] or frames
    hops = T.hops_of.get(ip)
    if hops is None:
        hops = _hops([p.ttl for p in frames if not _probe(p)])
    mac = Counter(p.eth_src for p in frames if p.eth_src).most_common(1)
    dev = T.by_mac.get(mac[0][0]) if mac else None
    if hops == 0:                         # sent on the capture link by its owner
        host = T.node(dev or T.by_ip.get(ip) or ip, "host", ip=ip, mac=mac[0][0] if mac else None, evidence="IP endpoint")
        return _near(T, edge, host, side) + [host]
    host = T.by_ip.get(ip) or T.node(ip, "host", ip=ip, evidence="IP endpoint")
    if dev is None and mac:
        dev = T.node(f"gw-{mac[0][0]}", "router", f"Router {mac[0][0]}", mac=mac[0][0],
                     evidence=f"delivered packets of {ip} onto the capture link")
    chain = _near(T, edge, dev, side) + [dev] if dev else []
    if hops is None:                      # only traceroute probes seen: distance unknown
        return chain + [host]
    if dev and T.nodes[dev]["kind"] not in ROUTED:
        T.nodes[dev]["kind"] = "l3switch" if T.nodes[dev]["kind"] == "switch" else "router"
    unseen = hops - 1 if dev else hops
    if unseen > CLOUD_AFTER:
        # one WAN cloud per gateway (not one per destination network): labelled with the range of unseen hops
        cid = T.node(f"cloud:{dev}", "cloud", observed=False,
                     evidence=f"TTL of {ip} shows {hops} routed hops; the middle ones never touch the capture link")
        c = T.nodes[cid]
        c.setdefault("hop_range", [unseen, unseen])
        c["hop_range"] = [min(c["hop_range"][0], unseen), max(c["hop_range"][1], unseen)]
        lo, hi = c["hop_range"]
        c["label"] = f"WAN: {lo}{'–' + str(hi) if hi != lo else ''} routers (not visible)"
        chain.append(cid)
    else:
        for i in range(unseen):
            chain.append(T.node(f"inferred:{dev}:{_net(ip)}:{i}", "router", f"Router (hop {i + 2 if dev else i + 1})",
                                observed=False, evidence=f"TTL of {ip} shows {hops} routed hop(s)"))
    return chain + [host]


def _net(ip: str) -> str:
    a = _ip(ip)
    if a is None:
        return ip
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 64}", strict=False))


def _steps(pkts, is_fwd, status_of) -> list:
    t0 = pkts[0].rel_ts if pkts else 0
    return [{"no": p.no, "t": round(p.rel_ts - t0, 6), "dir": "fwd" if is_fwd(p) else "rev",
             "label": p.info[:90], "status": status_of(p)} for p in pkts[:MAX_STEPS]]


def _pkt_status(p) -> str:
    if p.tcp is not None:
        if p.tcp.rst:
            return "fail"
        if set(p.tcp.analysis) & {"retransmission", "fast_retransmission", "lost_segment", "zero_window", "duplicate_ack",
                                  "out_of_order", "spurious_retransmission"}:
            return "warn"
    ic = p.layers.get("icmp")
    if ic and ic["type"] in ((3, 11, 5) if not ic["v6"] else (1, 2, 3)):
        return "fail"
    return "ok"


def _ip_flows(a, T: Topology, edge: dict, skip: set) -> list:
    conv = defaultdict(list)
    for p in a.packets:
        if p.src and p.dst and _unicast(p.src) and _unicast(p.dst) and "tunneled" not in p.tags \
                and p.protocol not in CONTROL and p.protocol not in ("ICMPv6", "DHCP") \
                and not (p.layers.get("icmp", {}).get("type") in (3, 11) and not p.layers["icmp"]["v6"]):
            conv[tuple(sorted((p.src, p.dst)))].append(p)
    streams = {s.id: s for s in a.flows.streams}
    scored = []
    for pk in conv.values():
        first = pk[0]
        src, dst = first.src, first.dst
        if first.tcp is not None and streams.get(first.tcp.stream):
            st = streams[first.tcp.stream]
            src, dst = st.client, st.server
        if (src, dst) in skip or (dst, src) in skip:
            continue
        bad = any(_pkt_status(p) != "ok" for p in pk)
        scored.append((not bad, -len(pk), src, dst, pk))
    scored.sort(key=lambda s: s[:2])
    flows = []
    for _, _, src, dst, pk in scored[:MAX_FLOWS]:
        fwd = [p for p in pk if p.src == src]
        rev = [p for p in pk if p.src == dst]
        s_chain = _side(T, edge, src, fwd, 0)
        if rev:
            d_chain = _side(T, edge, dst, rev, 1)
        else:                                  # nothing came back: only the next device toward dst is known
            nxt = T.by_mac.get(Counter(p.eth_dst for p in fwd).most_common(1)[0][0]) if fwd else None
            host = T.by_ip.get(dst) or T.node(dst, "host", ip=dst, observed=False, evidence="destination (never answered)")
            d_chain = ([nxt] if nxt and nxt != host else []) + [host]
        hops = list(reversed(s_chain)) + [h for h in d_chain if h not in s_chain]
        protos = Counter(p.protocol for p in pk).most_common(2)
        status, where, why = _flow_status(a, pk, src, dst, fwd, rev, s_chain, d_chain, T)
        flows.append({"id": f"f{len(flows)}", "label": f"{src} → {dst} ({'/'.join(k for k, _ in protos)})",
                      "kind": "data", "src_ip": src, "dst_ip": dst, "hops": hops,
                      "capture_between": [s_chain[0], d_chain[0]], "status": status, "break_at": where, "why": why,
                      "packets": len(pk), "steps": _steps(pk, lambda p, s=src: p.src == s, _pkt_status),
                      "observed_links": not edge["switched"]})
    return flows


def _flow_status(a, pk, src, dst, fwd, rev, s_chain, d_chain, T):
    icmp_err = [p for p in a.packets if "icmp" in p.layers and (p.layers["icmp"].get("original") or {}).get("dst") == dst
                and (p.layers["icmp"].get("original") or {}).get("src") == src and not _probe_dport(p)]
    if icmp_err:
        p = icmp_err[0]
        rep = T.by_ip.get(p.src) or T.node(p.src, "router", ip=p.src, evidence="reported an ICMP error")
        return "fail", rep, f"{p.src} answered '{p.info}' — the packet got no further than this device."
    if fwd and all(_probe(p) for p in fwd) and any(_probe_dport(p) and p.src == dst for p in a.packets if "icmp" in p.layers):
        return "ok", None, f"Traceroute-style UDP probes reached {dst}: it answered 'port unreachable', the normal end of a trace."
    rst = [p for p in pk if p.tcp is not None and p.tcp.rst]
    if rst:
        who = rst[0].src
        node = s_chain[-1] if who == src else d_chain[-1]
        return "fail", node, f"{who} reset the connection (RST, packet #{rst[0].no})."
    if fwd and not rev:
        return "fail", d_chain[0], (f"No reply from {dst} seen here: packets left the capture point toward "
                                    f"{T.nodes[d_chain[0]]['label']} and nothing came back (or the reply takes a "
                                    "different path — asymmetric routing / ECMP).")
    if any(_pkt_status(p) == "warn" for p in pk):
        return "degraded", None, "Retransmissions / out-of-order / window problems on this flow (see the TCP findings)."
    return "ok", None, "Packets flowed in both directions without errors."


def _probe_dport(p) -> bool:
    return ((p.layers["icmp"].get("original") or {}).get("dport") or 0) in TRACEROUTE_PORTS


def _traceroute(a, T: Topology, edge: dict) -> dict | None:
    rep = [p for p in a.packets if "icmp" in p.layers and (p.layers["icmp"]["type"] == 11 and not p.layers["icmp"]["v6"]
                                                              or p.layers["icmp"]["v6"] and p.layers["icmp"]["type"] == 3)]
    if not rep:
        return None
    o = rep[0].layers["icmp"].get("original") or {}
    src, dst = o.get("src"), o.get("dst")
    if not src or not dst:
        return None
    order = []
    for p in rep:
        if (p.layers["icmp"].get("original") or {}).get("dst") == dst and p.src not in order:
            order.append(p.src)
    probes = [p for p in a.packets if p.src == src and p.dst == dst]
    other = [p for p in a.packets if p.src == src and not _probe(p) and p.ttl]
    hops = list(reversed(_side(T, edge, src, other or probes, 0)))
    for r in order:
        nid = T.by_ip.get(r) or T.node(r, "router", ip=r, evidence="answered a traceroute probe (TTL exceeded)")
        if T.nodes[nid]["kind"] not in ROUTED:
            T.nodes[nid]["kind"] = "router"
        T.nodes[nid]["evidence"].append("answered a traceroute probe (TTL exceeded)")
        if nid not in hops:
            hops.append(nid)
    end = [p for p in a.packets if "icmp" in p.layers and ((p.layers["icmp"].get("original") or {}).get("dst") == dst
                                                          and p.layers["icmp"].get("code_name") == "Port unreachable"
                                                          or p.src == dst)]
    last = T.by_ip.get(dst) or T.node(dst, "host", ip=dst, observed=bool(end), evidence="traceroute target")
    if end and end[0].src != dst:          # destination answered from another interface address
        last = T.node(last, ip=end[0].src)
    if last not in hops:
        hops.append(last)
    pk = sorted(rep + probes + end, key=lambda p: p.no)
    return {"id": "trace", "label": f"traceroute {src} → {dst}", "kind": "trace", "src_ip": src, "dst_ip": dst,
            "hops": hops, "capture_between": hops[:2], "status": "ok" if end else "fail",
            "break_at": None if end else hops[-2], "packets": len(pk),
            "why": (f"Traceroute reached {dst} through {len(order)} router(s): {' → '.join(order)} — each hop is named by its "
                    "ICMP time-exceeded reply." if end else
                    f"Traceroute stopped after {order[-1] if order else src}: no further hop or the destination answered."),
            "steps": _steps(pk, lambda p: p.src == src, lambda p: "warn" if "icmp" in p.layers and p.src != dst else "ok")}


def _tunnel_flows(a, T: Topology) -> list:
    out = []
    groups = defaultdict(list)
    for p in a.packets:
        for kind in ("gre", "vxlan"):
            if kind in p.layers:
                d = p.layers[kind]
                groups[(kind, d["outer_src"], d["outer_dst"], p.src or p.eth_src, p.dst or p.eth_dst)].append(p)
    # the router that encapsulated a packet with 0 outer hops is the frame's sender; IOS also decrements the outer TTL of
    # its own tunnel packets once, so 1 hop counts when the tunnel address shares a subnet with the sender's addresses
    endpoint = {}
    for (kind, osrc, odst, *_), pk in groups.items():
        oh = _hops([p.layers[kind]["outer_ttl"] for p in pk])
        mac = Counter(p.layers[kind]["outer_eth_src"] for p in pk).most_common(1)[0][0]
        if mac in T.by_mac and (oh == 0 or oh == 1 and any(_net(osrc) == _net(x) for x in T.nodes[T.by_mac[mac]]["ips"])):
            endpoint[osrc] = T.node(T.by_mac[mac], ip=osrc, role=f"{kind.upper()} tunnel endpoint",
                                    evidence=f"encapsulates {kind.upper()} (outer source {osrc})")
    seen = set()
    for (kind, osrc, odst, isrc, idst), pk in groups.items():
        key = (kind,) + tuple(sorted((osrc, odst))) + tuple(sorted((str(isrc), str(idst))))
        if key in seen:
            continue
        seen.add(key)
        rev = groups.get((kind, odst, osrc, idst, isrc), [])
        allp = sorted(pk + rev, key=lambda p: p.no)
        name = kind.upper()
        va = endpoint.get(osrc) or T.node(T.by_ip.get(osrc) or f"{name} endpoint {osrc}", "router", ip=osrc,
                                          role=f"{name} tunnel endpoint", evidence=f"{name} outer source")
        if _unicast(odst):
            vb = endpoint.get(odst) or T.node(T.by_ip.get(odst) or f"{name} endpoint {odst}", "router", ip=odst,
                                              role=f"{name} tunnel endpoint", evidence=f"{name} outer destination")
        else:
            vb = T.node(f"BUM group {odst}", "segment", f"Underlay multicast {odst}", evidence="flood-and-learn BUM group")
        # underlay devices seen on this link: whoever handed the packet over (if not the encapsulator) and the next hop
        prv = T.by_mac.get(Counter(p.layers[kind]["outer_eth_src"] for p in pk).most_common(1)[0][0])
        nxt = T.by_mac.get(Counter(p.layers[kind]["outer_eth_dst"] for p in pk).most_common(1)[0][0])
        under = [d for d in (prv, nxt) if d and d not in (va, vb)]
        under = [d for i, d in enumerate(under) if d not in under[:i]]
        inner_ip = _ip(isrc) is not None
        if kind == "gre" and _hops([p.ttl for p in pk]) == 0:   # routed tunnel: an unrouted inner source is the tunnel router itself
            hs = T.node(va, ip=isrc, evidence=f"tunnel interface address {isrc}")
        else:
            hs = T.by_ip.get(isrc) or T.by_mac.get(isrc) or T.node(str(isrc), "host", ip=isrc if inner_ip else None,
                                                                   mac=None if inner_ip else isrc,
                                                                   evidence=f"inner source inside {name}")
        to_host = _unicast(idst) or (not inner_ip and not _group(idst))
        hd = (T.by_ip.get(idst) or T.by_mac.get(idst) or T.node(str(idst), "host", ip=idst if inner_ip else None,
                                                                 mac=None if inner_ip else idst,
                                                                 evidence=f"inner destination inside {name}")) if to_host else None
        hops = [h for h in [hs, va] + under + [vb] + ([hd] if hd else []) if h]
        hops = [h for i, h in enumerate(hops) if h not in hops[:i]]
        vni = f" VNI {pk[0].layers[kind]['vni']}" if kind == "vxlan" else ""
        T.link(va, vb, "tunnel", label=f"{name}{vni}")
        outer_hops = _hops([p.layers[kind]["outer_ttl"] for p in pk]) or 0
        answered = bool(rev) or not to_host
        out.append({"id": f"t{len(out)}", "label": f"{isrc} → {idst} inside {name}{vni} ({osrc} → {odst})", "kind": "tunnel",
                    "src_ip": str(isrc), "dst_ip": str(idst), "hops": hops, "tunnel": [va, vb],
                    "capture_between": [prv or va, nxt or vb],        # the frame's outer MACs = the link captured on
                    "tunnel_hops": {(va, vb)} if under else set(),
                    "status": "ok" if answered else "oneway", "break_at": None, "packets": len(allp),
                    "why": (f"Encapsulated by {osrc}{vni}, carried across the underlay ({outer_hops} routed hop(s) in the "
                            f"outer TTL at this point) and decapsulated by {odst}." if _unicast(odst) else
                            f"Broadcast/unknown frame flooded by {osrc} to underlay multicast group {odst} (flood-and-learn).")
                           + ("" if answered else " Only this direction crosses this link — the return traffic takes "
                                                  "another path (ECMP across spines is normal)."),
                    "steps": _steps(allp, lambda p, s=osrc, k=kind: p.layers[k]["outer_src"] == s, _pkt_status)})
    return out


def _service_flows(a, T: Topology, edge: dict) -> list:
    """Exchanges that have no end-to-end unicast flow: DHCP, 802.1X/RADIUS."""
    out = []
    done = set()
    for t in a.dhcp_transactions:
        if t["client_mac"] in done or len(done) >= 2:
            continue
        done.add(t["client_mac"])
        cli = T.node(T.by_mac.get(t["client_mac"]) or f"DHCP client {t['client_mac']}", "host", mac=t["client_mac"],
                     evidence="DHCP client")
        srv = (T.by_ip.get(t["servers"][0]) or T.node(t["servers"][0], "server", ip=t["servers"][0], role="DHCP server")) \
            if t["servers"] else T.node("DHCP server (not reached)", "server", observed=False, evidence="no OFFER seen")
        relay = T.node(t["relay"], "router", ip=t["relay"], role="DHCP relay") if t.get("relay") else None
        hops = [cli] + ([relay] if relay else []) + [srv]
        pk = [a.pkt(n) for n, _, _ in t["messages"] if a.pkt(n)]
        ok = t["outcome"] == "success"
        out.append({"id": f"d{len(out)}", "label": f"DHCP {t['sequence']}", "kind": "service", "src_ip": t["client_mac"],
                    "dst_ip": "DHCP", "hops": hops, "capture_between": hops[:2], "status": "ok" if ok else "fail",
                    "break_at": None if ok else srv, "packets": len(pk),
                    "why": f"DORA exchange {t['sequence']} → {t['outcome']}.",
                    "steps": _steps(pk, lambda p: p.layers["dhcp"]["op"] == 1, lambda p: "ok")})
    eap = [p for p in a.packets if "eapol" in p.layers or "radius" in p.layers]
    if not eap:
        return out
    sup = next((p.eth_src for p in eap if "eapol" in p.layers and not _group(p.eth_src)
                and (p.layers["eapol"].get("eap") or {}).get("code") == "Response"), None)
    auth_mac = next((p.eth_src for p in eap if "eapol" in p.layers and p.eth_src != sup and not _group(p.eth_src)), None)
    rad = next((p for p in eap if "radius" in p.layers), None)
    wl = next((p.layers["wlan"] for p in eap if "wlan" in p.layers), None)
    hops = []
    if sup:
        hops.append(T.node(T.by_mac.get(sup) or f"Supplicant {sup}", "host", mac=sup, evidence="802.1X supplicant"))
    if auth_mac:
        hops.append(T.node(T.by_mac.get(auth_mac) or f"Authenticator {auth_mac}", "ap" if wl else "switch", mac=auth_mac,
                           role="802.1X authenticator", evidence="relays EAP between supplicant and RADIUS"))
    if rad:
        srv, nas = (rad.dst, rad.src) if rad.layers["radius"]["code_num"] in (1, 4) else (rad.src, rad.dst)
        n_nas = T.by_ip.get(nas) or T.node(nas, "switch", ip=nas, role="NAS")
        if n_nas not in hops:
            hops.append(n_nas)
        hops.append(T.by_ip.get(srv) or T.node(srv, "server", ip=srv, role="RADIUS server"))
    codes = [((p.layers.get("eapol") or {}).get("eap") or {}).get("code") or (p.layers.get("radius") or {}).get("code")
             for p in eap]
    ok = "Success" in codes or "Access-Accept" in codes
    failed = "Failure" in codes or "Access-Reject" in codes
    if len(hops) >= 2:
        out.append({"id": "aaa", "label": "802.1X / RADIUS authentication", "kind": "service", "src_ip": sup or "",
                    "dst_ip": "RADIUS", "hops": hops, "capture_between": hops[:2],
                    "status": "fail" if failed else "ok" if ok else "degraded", "break_at": hops[-1] if failed else None,
                    "packets": len(eap),
                    "why": ("Authentication succeeded (EAP-Success / Access-Accept)." if ok and not failed else
                            "Authentication was rejected." if failed else "The exchange did not finish inside the capture."),
                    "steps": _steps(eap, lambda p: p.eth_src == sup or ("radius" in p.layers
                                                                        and p.layers["radius"]["code_num"] in (1, 4)),
                                    lambda p: "fail" if "Failure" in p.info or "Reject" in p.info else "ok")})
    return out


def _control_flows(a, T: Topology, edge: dict) -> list:
    """Routing / switching control traffic between the devices on the capture link."""
    by = defaultdict(list)
    for p in a.packets:
        if p.protocol in CONTROL and "tunneled" not in p.tags:
            by[p.protocol].append(p)
    out = []
    for proto, pk in sorted(by.items(), key=lambda x: -len(x[1]))[:5]:
        speakers = []
        for p in pk:
            nid = T.by_mac.get(p.eth_src) or (T.by_ip.get(p.src) if p.src else None)
            if nid and nid not in speakers:
                speakers.append(nid)
        if not speakers:
            continue
        peer = edge["segment"] or next((e for e in edge["ends"] if e not in speakers[:1]), None)
        hops = speakers[:1] + ([peer] if peer and peer not in speakers[:1] else []) + \
            [s for s in speakers[1:] if s != peer][:3]
        if len(hops) < 2:
            continue
        bad = [f for f in a.findings if f.protocol.upper().startswith(proto[:3]) and f.severity in ("critical", "high", "medium")]
        out.append({"id": f"c{len(out)}", "label": f"{proto} {CONTROL[proto]} ({len(pk)})", "kind": "control",
                    "src_ip": "", "dst_ip": "", "hops": hops, "capture_between": hops[:2],
                    "status": "degraded" if bad else "ok", "break_at": None, "packets": len(pk),
                    "why": (f"{len(speakers)} device(s) exchange {proto} {CONTROL[proto]} on this link"
                            + (f"; problems: {'; '.join(f.title for f in bad[:3])}." if bad else " — no problems detected.")),
                    "steps": _steps(pk, lambda p, s=speakers[0]: (T.by_mac.get(p.eth_src) or T.by_ip.get(p.src)) == s,
                                    lambda p: "ok")})
    return out


def _notes(T: Topology, edge: dict) -> list:
    n = [f"Capture taken on the link between {' and '.join(T.nodes[e]['label'] for e in edge['ends'])}."
         if len(edge["ends"]) == 2 else
         "The capture link's devices did not announce themselves (no CDP/LLDP); devices seen on it are drawn on a shared "
         "capture segment."]
    if edge["switched"]:
        n.append("Both ends of the capture link are switches: hosts talking across it sit behind one switch or the other; "
                 "which side each host is on is inferred (dashed).")
    inferred = sum(1 for x in T.nodes.values() if not x["observed"])
    if inferred:
        n.append(f"{inferred} node(s) are inferred from TTL decrements: they are on the path but never sent a frame onto "
                 "the capture link, so their names are unknown.")
    return n


# --------------------------------------------------------------- stitch -----
def _addr_label(label: str) -> bool:
    return _ip(label) is not None or label.count(":") == 5 and len(label) == 17


def stitch(paths: list[dict]) -> dict:
    """Merge the inferred paths of several captures of the same network (one folder)."""
    nodes: dict = {}
    alias: dict = {}
    for P in paths:
        for n in P["nodes"]:
            keys = [n["id"], *n["macs"], *n["ips"]]
            key = next((alias[k] for k in keys if k in alias), n["id"])
            m = nodes.setdefault(key, {**n, "ips": [], "macs": [], "roles": [], "evidence": [], "captures": []})
            for f in ("ips", "macs", "roles", "evidence"):
                m[f] += [x for x in n[f] if x not in m[f]]
            if RANK.get(n["kind"], 0) > RANK.get(m["kind"], 0):
                m["kind"] = n["kind"]
            if _addr_label(m["label"]) and not _addr_label(n["label"]):      # a device name beats a bare address
                m["label"] = n["label"]
            m["observed"] = m["observed"] or n["observed"]
            if P["capture"] not in m["captures"]:
                m["captures"].append(P["capture"])
            for k in keys:
                alias.setdefault(k, key)
    A = lambda x: alias.get(x, x)  # noqa: E731
    links: dict = {}
    for P in paths:
        for ln in P["links"]:
            a, b = A(ln["a"]), A(ln["b"])
            if a == b:
                continue
            k = tuple(sorted((a, b)))
            m = links.setdefault(k, {**ln, "a": k[0], "b": k[1], "captures": []})
            m["captures"] += [c for c in ln["captures"] if c not in m["captures"]]
            m["observed"] = m["observed"] or ln["observed"]
            if ln["kind"] == "tunnel":
                m["kind"] = "tunnel"
    flows, merged = [], {}
    for P in paths:
        for f in P["flows"]:
            hops = [A(h) for h in f["hops"]]
            # the same conversation may be plain at one point and tunneled at another: match data flows on the endpoints
            family = "data" if f["kind"] in ("data", "tunnel", "trace") else f["kind"]
            key = (family,) + tuple(sorted((f["src_ip"], f["dst_ip"]))) if f["src_ip"] else None
            if key in merged:
                m = merged[key]
                if f["src_ip"] != m["src_ip"]:           # seen in the opposite direction here
                    hops = hops[::-1]
                for i, h in enumerate(hops):             # add hops this capture saw that the others did not
                    if h in m["hops"]:
                        continue
                    prev = next((x for x in reversed(hops[:i]) if x in m["hops"]), None)
                    nxt = next((x for x in hops[i + 1:] if x in m["hops"]), None)
                    ip, inx = (m["hops"].index(prev) if prev else -1), (m["hops"].index(nxt) if nxt else len(m["hops"]))
                    if prev and nxt and inx - ip > 1:    # another device already sits there: a parallel (ECMP) branch
                        m.setdefault("branches", []).append([prev, h, nxt])
                    else:
                        m["hops"].insert(ip + 1, h)
                m["captures"].append(P["capture"])
                m["capture_points"].append([A(x) for x in f["capture_between"]] + [P["capture"]])
                m["why"] += f" | At {P['capture']}: {f['why']}"
                if f["status"] == "fail" or (f["status"] != "ok" and m["status"] == "ok"):
                    m["status"], m["break_at"] = f["status"], A(f["break_at"]) if f["break_at"] else None
                continue
            nf = {**f, "id": f"s{len(flows)}", "hops": hops, "captures": [P["capture"]], "break_at": A(f["break_at"]) if f["break_at"] else None,
                  "capture_between": [A(x) for x in f["capture_between"]],
                  "capture_points": [[A(x) for x in f["capture_between"]] + [P["capture"]]]}
            if key:
                merged[key] = nf
            flows.append(nf)
    for f in flows:                                      # one-way at each point, but both directions overall
        if f["status"] == "oneway" and len(f["captures"]) > 1:
            f["status"] = "ok"
            f["why"] += " | Combined: each direction was seen at a different capture point (ECMP), so the flow is healthy."
    flows.sort(key=lambda f: (-len(f["captures"]), f["kind"] == "control"))
    return {"capture": " + ".join(P["capture"] for P in paths), "nodes": list(nodes.values()), "links": list(links.values()),
            "flows": flows[:MAX_FLOWS * 2],
            "notes": [x for P in paths for x in P["notes"][:1]] +
                     [f"{sum(1 for f in flows if len(f['captures']) > 1)} flow(s) were seen at more than one capture point and "
                      "are merged into one end-to-end path."]}
