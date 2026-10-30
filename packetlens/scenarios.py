"""Scenario library: how each protocol's packets normally travel, and what happens when it goes wrong.

Each topic has
* ``roles``     the devices involved, in path order (mapped onto the capture's real inferred path in the 3D view)
* ``normal``    the packet exchange that should happen: steps ``[from role, to role, label, what each device does]``
* ``failures``  classic failure modes: which step breaks (``at``) and where the packet dies (``drop``, a role index)
                or the unexpected answer (``reply``), what it looks like on the wire, why it happens, remediation now
                and mitigation to prevent it; ``findings`` link to the finding ids that detect it in a capture

Topics are attached to a capture when it contains their protocols (``match``) or findings.
"""
from __future__ import annotations



def step(frm, to, label, note):
    return {"from": frm, "to": to, "label": label, "note": note}


def fail(fid, title, at, symptom, why, fix, prevent, drop=None, reply=None, findings=()):
    return {"id": fid, "title": title, "at": at, "drop": drop, "reply": reply, "symptom": symptom, "why": why,
            "fix": fix, "prevent": prevent, "findings": list(findings)}


TOPICS: dict[str, dict] = {
    # ====================================================================== L2
    "arp": dict(
        title="ARP address resolution", match=["ARP"],
        roles=["Host A", "Switch", "Host B"],
        summary="Before an IPv4 packet can leave, the sender needs the next hop's MAC. It broadcasts 'who has IP B?'; "
                "every host in the VLAN receives it, only B answers with a unicast reply, and both cache the mapping.",
        normal=[step(0, 2, "ARP request (broadcast)", "Host A: no MAC for B in cache → broadcast to ff:ff:ff:ff:ff:ff. "
                                                      "Switch: learns A's MAC on the ingress port, floods the broadcast to every port in the VLAN."),
                step(2, 0, "ARP reply (unicast)", "Host B: recognises its IP, caches A, replies directly. Switch: learns B's port, "
                                                  "forwards the unicast only to A's port."),
                step(0, 2, "IP packet", "Host A: caches B's MAC (typ. 4 h on Cisco, minutes on hosts) and sends the waiting packet.")],
        failures=[
            fail("arp_no_reply", "Target never answers", 0, "Repeated 'Who has B?' broadcasts, no reply; ping shows 'Destination host unreachable'.",
                 ["Target host down or disconnected", "Target is in a different VLAN / subnet mask wrong on A (A thinks B is local)",
                  "Host firewall or port-security shut the port"],
                 ["Check the target is up and in the same VLAN", "Verify subnet masks on both hosts", "Check 'show interface status' for err-disabled ports"],
                 ["Consistent IP plans / DHCP", "Port monitoring alerts"], drop=2, findings=["arp_unanswered"]),
            fail("arp_spoof", "ARP spoofing (gateway MAC hijacked)", 1, "Two different MACs answer for the same IP (often the gateway); gratuitous ARPs from an unexpected MAC.",
                 ["An attacker poisons caches to become man-in-the-middle", "Duplicate static IP"],
                 ["Locate the second MAC in the CAM table and shut the port", "Clear ARP caches"],
                 ["Dynamic ARP Inspection with DHCP snooping", "Port security"], reply=[1, 0, "Forged ARP reply (attacker MAC)"],
                 findings=["arp_duplicate_ip"]),
            fail("arp_storm", "Broadcast storm", 0, "Broadcast share of all frames very high; switch CPUs busy; everything slows.",
                 ["Layer-2 loop (STP disabled / BPDU filtered)", "Scanning host ARPing whole subnets"],
                 ["Find the looping ports (MAC flapping logs) and shut one", "Rate-limit the scanning host"],
                 ["Storm control on access ports", "Keep STP enabled with BPDU Guard"], findings=["broadcast_high", "arp_scan"])]),
    "vlan": dict(
        title="802.1Q trunk, native VLAN and DTP", match=["802.1Q VLAN", "DTP", "CDP", "ISL"],
        roles=["Host (VLAN 10)", "Switch 1", "Switch 2", "Host (VLAN 10)"],
        summary="Access ports carry one VLAN untagged. Between switches a trunk carries many VLANs: each frame gets a 4-byte "
                "802.1Q tag (VLAN ID) on the trunk and loses it at the far access port. The native VLAN crosses untagged; "
                "DTP can negotiate whether a link becomes a trunk.",
        normal=[step(0, 1, "Untagged frame", "Access port in VLAN 10: the switch classifies the frame into VLAN 10."),
                step(1, 2, "Frame + 802.1Q tag 10", "Switch 1 inserts the tag on the trunk (unless VLAN 10 is the native VLAN) and forwards by MAC table."),
                step(2, 3, "Untagged frame", "Switch 2 reads tag 10, removes it and delivers on an access port in VLAN 10.")],
        failures=[
            fail("native_mismatch", "Native VLAN mismatch", 1, "CDP '%NATIVE_VLAN_MISMATCH'; STP blocks the port (PVID inconsistent); untagged traffic lands in the wrong VLAN.",
                 ["Different 'switchport trunk native vlan' on each end"], ["Set the same native VLAN on both ends"],
                 ["Unused native VLAN everywhere, or tag the native VLAN"], drop=2, findings=["cdp_native_vlan_mismatch"]),
            fail("vlan_not_allowed", "VLAN pruned from the trunk", 1, "Hosts in one VLAN can't reach across while other VLANs work; frames for that VLAN never appear on the trunk.",
                 ["VLAN missing from 'switchport trunk allowed vlan'", "VLAN not created on the far switch"],
                 ["Add the VLAN to the allowed list on both ends", "Create the VLAN"], ["Automate VLAN provisioning end-to-end"], drop=1),
            fail("dtp_auto_auto", "Trunk never forms (auto/auto)", 1, "Link stays access: only one VLAN passes; DTP frames show both sides 'auto'.",
                 ["Both ports 'dynamic auto'"], ["'switchport mode trunk' + 'nonegotiate' on both"], ["Static trunk configuration"],
                 drop=1, findings=["dtp_trunk_not_formed"]),
            fail("vlan_hop", "VLAN hopping attack", 0, "A host sends DTP 'desirable' (switch spoofing) or double-tagged frames (native VLAN = attacker's VLAN).",
                 ["DTP enabled on access ports", "User ports in the native VLAN"],
                 ["Disable DTP on access ports", "Move native VLAN to an unused VLAN"], ["Security baseline for all switch ports"],
                 reply=[0, 2, "Double-tagged frame reaches another VLAN"], findings=["dtp_negotiation_enabled", "vlan_native_vlan1"])]),
    "stp": dict(
        title="Spanning Tree", match=["STP"],
        roles=["Root bridge", "Switch B", "Switch C"],
        summary="Redundant switch links would loop broadcasts forever. STP elects a root bridge (lowest priority+MAC); every "
                "other switch keeps its best path to the root forwarding and blocks the rest. BPDUs every 2 s keep the tree alive.",
        normal=[step(0, 1, "BPDU (root = me)", "Root bridge advertises itself with path cost 0 every hello (2 s)."),
                step(1, 2, "BPDU (relayed, cost +)", "Switch B adds its port cost and relays; C compares BPDUs and blocks its worse redundant port."),
                step(1, 2, "Data frames on the loop-free tree", "Only root and designated ports forward; alternate ports stay blocking.")],
        failures=[
            fail("stp_tc_storm", "Topology change storm", 0, "Many BPDUs with the TC flag; MAC tables flushed repeatedly → unicast flooding and brief outages.",
                 ["Edge ports without PortFast flap (PCs rebooting)", "Flapping link or failing transceiver"],
                 ["Find the port generating TCNs ('show spanning-tree detail')", "Enable PortFast on host ports"],
                 ["PortFast + BPDU Guard on every edge port"], findings=["stp_topology_change"]),
            fail("stp_rogue_root", "Wrong switch becomes root", 0, "Root bridge ID changes to an access switch or a switch someone plugged in; traffic takes a sub-optimal path.",
                 ["Default priorities everywhere → oldest/lowest MAC wins", "New switch with lower priority"],
                 ["Set 'spanning-tree vlan X root primary' on the core"], ["Root Guard on ports facing access switches"],
                 reply=[2, 1, "Superior BPDU from rogue switch"], findings=["stp_summary"]),
            fail("stp_loop", "Layer-2 loop", 1, "Same broadcast seen over and over, MAC addresses flapping between ports, CPU 100 %.",
                 ["BPDUs filtered or STP disabled", "Unidirectional link: blocked port stops hearing BPDUs"],
                 ["Shut one of the looping links immediately"], ["UDLD/Loop Guard, never disable STP, storm control"], drop=2)]),
    # ====================================================================== L3 basics
    "ping": dict(
        title="ICMP echo (ping) across routers", match=["ICMP"],
        roles=["Source", "Gateway", "Router", "Destination"],
        summary="Ping sends ICMP echo request; each router decrements TTL, re-writes the Ethernet MACs for the next link and "
                "forwards by longest-prefix match; the destination answers with an echo reply that takes the reverse path.",
        normal=[step(0, 1, "Echo request", "Source: destination is off-subnet → send to default gateway's MAC (ARP if needed)."),
                step(1, 2, "Echo request (TTL-1)", "Gateway: route lookup, TTL-1, new source/destination MACs for the next link."),
                step(2, 3, "Echo request (TTL-2)", "Router: same process; last router ARPs for the destination."),
                step(3, 0, "Echo reply", "Destination answers; the reply is routed back independently (may take another path).")],
        failures=[
            fail("no_route", "No route to the destination", 1, "ICMP 'Destination network unreachable' from a router, or silence if ICMP is disabled.",
                 ["Missing static/dynamic route", "Routing protocol adjacency down"], ["Check 'show ip route' on the reporting router"],
                 ["Monitor routing adjacencies", "Default route toward the core"], drop=2, findings=["icmp_unreachable"]),
            fail("no_return", "Reply has no way back", 3, "Requests leave, no replies — but the destination does receive them (capture there).",
                 ["Return route missing on the destination side", "Asymmetric path through a stateful firewall that never saw the request"],
                 ["Add the return route", "Make the path symmetric through firewalls"], ["Symmetric routing design across stateful devices"],
                 drop=2),
            fail("icmp_filtered", "ICMP blocked", 1, "Ping fails but TCP applications work.",
                 ["ACL/firewall dropping ICMP"], ["Permit echo/echo-reply for monitoring hosts"], ["Don't blanket-block ICMP (PMTUD needs type 3/4)"],
                 drop=1, findings=["icmp_admin_prohibited"])]),
    "traceroute": dict(
        title="Traceroute", match=["icmp_ttl_exceeded"],
        roles=["Source", "Router 1", "Router 2", "Destination"],
        summary="Traceroute sends probes with TTL 1, 2, 3 …; each router that decrements TTL to 0 drops the probe and returns "
                "ICMP 'time exceeded', revealing itself. The destination answers 'port unreachable' (UDP probes) or echo reply.",
        normal=[step(0, 1, "Probe TTL=1", "Router 1 decrements TTL to 0 → drops it."),
                step(1, 0, "ICMP time exceeded", "Router 1 reveals its address — hop 1."),
                step(0, 2, "Probe TTL=2", "Router 1 forwards (TTL 1), Router 2 decrements to 0 and drops."),
                step(2, 0, "ICMP time exceeded", "Router 2 revealed — hop 2."),
                step(0, 3, "Probe TTL=3", "Reaches the destination with TTL 1."),
                step(3, 0, "ICMP port unreachable", "Destination: no service on the high UDP port → trace complete.")],
        failures=[
            fail("tr_stars", "'* * *' at a hop", 2, "One hop never answers but later hops do.",
                 ["That router rate-limits or disables ICMP time-exceeded (normal on many ISPs)"],
                 ["Nothing, if later hops answer"], ["Interpret stars in context; use TCP traceroute"], drop=2),
            fail("tr_loop", "Routing loop", 2, "The same two routers repeat hop after hop until TTL expires.",
                 ["Two routers point default/static routes at each other", "Redistribution loop"],
                 ["Fix the conflicting routes"], ["Summarise carefully, filter redistribution"], findings=["icmp_ttl_exceeded"],
                 reply=[2, 1, "Packet bounced back (loop)"]),
            fail("tr_stop", "Trace stops before the destination", 2, "Hops answer up to a point, then nothing.",
                 ["Firewall drops probes", "No route beyond that router"], ["Check the last responding router's routing/ACLs"],
                 ["Allow traceroute from management hosts"], drop=3)]),
    "dhcp": dict(
        title="DHCP (DORA)", match=["DHCP"],
        roles=["Client", "Relay / gateway", "DHCP server"],
        summary="A host without an address broadcasts DISCOVER; a relay (ip helper-address) forwards it as unicast to the server; "
                "the server OFFERs an address, the client REQUESTs it and the server ACKs — Discover, Offer, Request, Ack.",
        normal=[step(0, 1, "DISCOVER (broadcast)", "Client: source 0.0.0.0, broadcast. Gateway with ip helper-address relays it and sets giaddr."),
                step(1, 2, "DISCOVER (relayed unicast)", "Server picks a free address from the scope matching giaddr."),
                step(2, 0, "OFFER", "Address, mask, gateway, DNS, lease time."),
                step(0, 2, "REQUEST", "Client accepts one offer (broadcast so other servers withdraw theirs)."),
                step(2, 0, "ACK", "Lease committed; client ARPs for the address (conflict check) and starts using it.")],
        failures=[
            fail("dhcp_no_offer", "No OFFER", 1, "DISCOVERs repeat with growing intervals; client falls back to 169.254.x.x.",
                 ["No ip helper-address on the VLAN interface", "Server unreachable or scope exhausted", "DHCP snooping untrusted uplink"],
                 ["Configure the helper address", "Check scope utilisation", "Trust the uplink port for snooping"],
                 ["Monitor scope utilisation", "Redundant DHCP servers"], drop=1, findings=["dhcp_no_offer", "dhcp_apipa"]),
            fail("dhcp_nak", "NAK", 3, "Server answers REQUEST with NAK; client restarts DORA.",
                 ["Client moved to another subnet and requests its old address", "Lease expired / server has no record"],
                 ["Normal after moves; if persistent check scope/failover"], ["Consistent failover configuration"],
                 reply=[2, 0, "NAK"], findings=["dhcp_nak"]),
            fail("dhcp_rogue", "Rogue DHCP server", 2, "Two servers answer; some clients get a wrong gateway/DNS.",
                 ["Home router / lab device plugged in", "Attacker (MITM)"], ["Find the rogue server MAC and shut its port"],
                 ["DHCP snooping on all access switches"], reply=[1, 0, "OFFER from rogue server"], findings=["dhcp_multiple_servers"])]),
    "dns": dict(
        title="DNS resolution", match=["DNS"],
        roles=["Client", "Gateway", "Resolver"],
        summary="Before connecting to a name, the client asks its resolver (UDP/53). The resolver answers from cache or "
                "recursively asks the root, TLD and authoritative servers, then replies with the address.",
        normal=[step(0, 2, "Query A example.com", "Client sends to the resolver learned via DHCP."),
                step(2, 0, "Response A 93.184.216.34", "Resolver answers (from cache in < 5 ms, recursion 20–200 ms).")],
        failures=[
            fail("dns_timeout", "Resolver doesn't answer", 0, "Queries retransmitted after 1–5 s; applications hang at 'resolving host'.",
                 ["Resolver down / overloaded", "UDP 53 filtered"], ["Test with dig @resolver", "Fail over to the secondary"],
                 ["Two resolvers per site, health monitoring"], drop=2, findings=["dns_no_response"]),
            fail("dns_nx", "NXDOMAIN / SERVFAIL", 1, "Fast answer, but with an error code.",
                 ["Typo or missing record", "DNSSEC failure or broken forwarder (SERVFAIL)"], ["Check the zone / forwarders"],
                 ["Monitor SERVFAIL rates"], reply=[2, 0, "SERVFAIL / NXDOMAIN"], findings=["dns_nxdomain", "dns_servfail"]),
            fail("dns_slow", "Slow resolution", 1, "Answers take hundreds of ms — every new connection waits.",
                 ["Cache misses, slow upstream", "Resolver far away (WAN)"], ["Local caching resolver"], ["Resolver close to clients"],
                 findings=["dns_slow"])]),
    # ====================================================================== transport
    "tcp": dict(
        title="TCP connection lifecycle", match=["TCP"],
        roles=["Client", "Gateway", "Server"],
        summary="TCP opens with a three-way handshake (SYN, SYN-ACK, ACK) that agrees sequence numbers, MSS, window scaling and "
                "SACK; data is acknowledged cumulatively; the connection closes with FIN/ACK from each side (or RST to abort).",
        normal=[step(0, 2, "SYN", "Client: picks an ISN, offers MSS / window scale / SACK. Routers only forward."),
                step(2, 0, "SYN-ACK", "Server: a listener exists on the port → acknowledges the SYN, sends its own options."),
                step(0, 2, "ACK", "Connection established; iRTT = time from SYN to this ACK."),
                step(0, 2, "Request data", "Client sends; server ACKs within ~200 ms (delayed ACK)."),
                step(2, 0, "Response data", "Server sends up to the client's receive window before waiting for ACKs."),
                step(0, 2, "FIN", "Client closes its direction."),
                step(2, 0, "FIN-ACK", "Server closes; client ACKs and waits in TIME_WAIT.")],
        failures=[
            fail("tcp_syn_drop", "SYN never answered", 0, "SYN retransmitted after 1 s, 2 s, 4 s … then 'connection timed out'.",
                 ["Firewall silently drops the port", "Server down or route missing", "Wrong IP / NAT"],
                 ["Check firewall rules and routing toward the server", "Capture at the server: did the SYN arrive?"],
                 ["Flow inventory and firewall change testing"], drop=2, findings=["tcp_syn_no_response"]),
            fail("tcp_refused", "Connection refused (RST)", 1, "SYN answered immediately with RST,ACK.",
                 ["Nothing listening on the port", "Service crashed", "Host firewall rejects"], ["Start the service / fix the port"],
                 ["Service monitoring"], reply=[2, 0, "RST, ACK"], findings=["tcp_conn_refused"]),
            fail("tcp_loss", "Packet loss mid-transfer", 4, "Duplicate ACKs → fast retransmission, or RTO retransmission after ≥200 ms; throughput collapses.",
                 ["Congested/oversubscribed link", "CRC errors / duplex mismatch", "Policer dropping bursts"],
                 ["Check interface errors/drops along the path", "Capture at two points to locate the loss"],
                 ["Capacity planning, QoS, fix layer-1 errors"], drop=1, findings=["tcp_retransmissions", "tcp_duplicate_acks"]),
            fail("tcp_zero_window", "Receiver can't keep up (zero window)", 4, "Receiver advertises window 0; sender sends zero-window probes and waits.",
                 ["Receiving application not reading the socket (CPU/disk/DB bound)"], ["Profile the receiving application"],
                 ["Size buffers, scale the receiver"], findings=["tcp_zero_window"]),
            fail("tcp_reset_mid", "Connection reset mid-transfer", 4, "RST in the middle of data; TTL of the RST differs from the server's packets → a middlebox sent it.",
                 ["Firewall/IPS idle timeout or policy", "Application crash"], ["Check firewall/IPS logs and idle timers"],
                 ["Keep-alives shorter than middlebox idle timeouts"], reply=[1, 0, "RST (injected)"], findings=["tcp_reset_abort"])]),
    "mtu": dict(
        title="MTU, MSS and fragmentation", match=["ip_fragmentation", "icmp_frag_needed", "tcp_mss_clamped", "tunnel_mss_too_large",
                                                  "GRE", "VXLAN"],
        roles=["Client", "Router (MTU 1500)", "Tunnel / small-MTU link", "Server"],
        summary="Each link has a maximum frame size (MTU, usually 1500 bytes). TCP avoids fragmentation by announcing an MSS "
                "(MTU − 40) in the SYN; routers can clamp it. If a DF-marked packet is too big, the router must return ICMP "
                "'fragmentation needed' so the sender shrinks its packets (path MTU discovery).",
        normal=[step(0, 3, "SYN MSS 1460", "Client announces the largest segment it can receive."),
                step(2, 0, "SYN-ACK (MSS clamped 1360)", "The tunnel router rewrites MSS to fit its smaller MTU ('ip tcp adjust-mss')."),
                step(3, 0, "Data 1360 B", "Segments fit every link — no fragmentation, no drops.")],
        failures=[
            fail("pmtud_blackhole", "PMTUD black hole", 2, "Handshake works, small requests work, large responses hang; full-size segments retransmitted, no ICMP seen.",
                 ["ICMP 'fragmentation needed' blocked by a firewall", "Tunnel without MSS clamping"],
                 ["Clamp MSS on the tunnel", "Permit ICMP type 3 code 4 / ICMPv6 type 2"], ["Document MTU per path; PLPMTUD on servers"],
                 drop=2, findings=["tcp_retransmissions", "tunnel_mss_too_large"]),
            fail("frag_loss", "Fragments lost", 2, "Large UDP (DNS EDNS0, IKE) fails; incomplete fragment sets in the capture.",
                 ["Firewall dropping non-first fragments", "One fragment lost = whole datagram lost"],
                 ["Allow fragments or reduce UDP payload size (EDNS0 1232)"], ["Avoid fragmentation by design"],
                 drop=2, findings=["ip_fragmentation"]),
            fail("frag_needed", "Router reports 'fragmentation needed'", 2, "ICMP type 3 code 4 with next-hop MTU; sender retries smaller.",
                 ["Smaller MTU link in the path (normal PMTUD)"], ["None if the sender adapts; otherwise clamp MSS"],
                 ["Consistent MTU"], reply=[2, 0, "ICMP frag needed (MTU 1400)"], findings=["icmp_frag_needed"])]),
    "qos": dict(
        title="QoS classification and marking", match=["qos_dscp_summary", "qos_ef_misuse"],
        roles=["Host", "Edge router (classify & mark)", "Core router (queue by DSCP)", "Server"],
        summary="At the trust boundary traffic is classified (ACL/NBAR) and marked with a DSCP value; every hop queues by that "
                "DSCP: EF (46) in the strict-priority queue for voice, AF41 video, AF11/CS1 bulk, CS6 routing protocols.",
        normal=[step(0, 1, "Packet DSCP 0", "Untrusted host traffic arrives unmarked (or is re-marked)."),
                step(1, 2, "Packet DSCP EF/AF11", "Edge policy classifies and marks."),
                step(2, 3, "Queued by DSCP", "Core services queues by DSCP: EF first (policed), others by bandwidth share.")],
        failures=[
            fail("qos_wrong_class", "Traffic in the wrong class", 1, "Non-voice traffic (e.g. Telnet) marked EF competes with voice in the priority queue.",
                 ["Over-broad classification ACL", "Trusting endpoint markings"], ["Re-mark at the edge"],
                 ["Trust boundary at the access layer"], findings=["qos_ef_misuse"]),
            fail("qos_remark", "Markings reset in transit", 2, "DSCP changes to 0 after a hop (ISP / untrusted interface).",
                 ["Provider or firewall re-marking", "'mls qos trust' missing"], ["Configure trust / agree markings with the provider"],
                 ["Verify markings end-to-end"]),
            fail("qos_drop", "Priority queue policing drops", 2, "Voice jitter / drops during congestion although marked EF.",
                 ["EF traffic exceeds the priority policer"], ["Size LLQ for the call volume", "Call admission control"],
                 ["Capacity planning for real-time classes"], drop=2)]),
    # ====================================================================== redundancy / routing
    "fhrp": dict(
        title="HSRP / VRRP gateway redundancy", match=["HSRP", "VRRP"],
        roles=["Host", "Active router", "Standby router"],
        summary="Two routers share a virtual IP/MAC used as the hosts' default gateway. Hellos every 3 s (HSRP) / 1 s (VRRP) "
                "elect the active router by priority; if its hellos stop for the hold time (10 s / 3×), the standby takes over "
                "and sends gratuitous ARP for the virtual MAC.",
        normal=[step(1, 2, "Hello (Active, prio 110)", "Active router announces itself to 224.0.0.2 / 224.0.0.102."),
                step(2, 1, "Hello (Standby, prio 100)", "Standby listens and is ready to take over."),
                step(0, 1, "Traffic to virtual MAC", "Hosts send to the virtual gateway; only the active router forwards.")],
        failures=[
            fail("fhrp_split", "Both routers active (split brain)", 1, "Two routers send Active hellos; virtual MAC flaps between switch ports.",
                 ["Layer-2 path between the routers broken", "Authentication / group mismatch → they ignore each other"],
                 ["Restore the VLAN between the routers", "Match group, version and authentication"],
                 ["Redundant L2 path, monitoring of HSRP state"], drop=2, findings=["fhrp_split_brain"]),
            fail("fhrp_flap", "Active router flapping", 1, "Frequent state changes / coups; hosts lose packets at each switchover.",
                 ["Tracked interface flapping", "Preempt with short delays", "Lost hellos (congestion, CoPP)"],
                 ["Add preempt delay, fix the tracked link"], ["Tune timers; protect hellos with QoS"], findings=["fhrp_flap"]),
            fail("fhrp_auth", "Default cleartext authentication", 0, "HSRP hellos carry the text key 'cisco'.",
                 ["Default configuration"], ["Configure MD5 authentication"], ["Security baseline for FHRP"],
                 reply=[0, 1, "Attacker hello with priority 255"], findings=["fhrp_weak_auth"])]),
    "ospf": dict(
        title="OSPF adjacency", match=["OSPF"],
        roles=["Router A", "Router B"],
        summary="OSPF routers discover neighbours with Hellos (224.0.0.5, every 10 s, dead 40 s). Hello/dead timers, area, "
                "subnet mask, authentication and MTU must match. They then exchange database descriptions (DBD), request and "
                "flood LSAs until both LSDBs are identical (FULL) and run SPF.",
        normal=[step(0, 1, "Hello", "A lists the neighbours it hears; B sees itself listed → 2-WAY."),
                step(1, 0, "Hello (A listed)", "Bidirectional communication confirmed."),
                step(0, 1, "DBD (MTU, master/slave)", "EXSTART: MTU and master/slave negotiated."),
                step(1, 0, "LS Request / Update", "LOADING: missing LSAs requested and flooded."),
                step(0, 1, "LS Ack", "FULL: SPF runs, routes installed.")],
        failures=[
            fail("ospf_timer", "Hello/dead or area mismatch", 0, "Hellos in both directions but neighbours never list each other.",
                 ["Different hello/dead intervals, area, mask or auth"], ["Align interface parameters"],
                 ["Templates for OSPF interfaces"], drop=1, findings=["ospf_hello_mismatch", "ospf_area_mismatch", "ospf_auth_mismatch"]),
            fail("ospf_mtu", "Stuck in EXSTART (MTU mismatch)", 2, "Same DBD retransmitted every 5 s; neighbour flaps EXSTART/EXCHANGE.",
                 ["Different interface MTUs"], ["Match MTU (or 'ip ospf mtu-ignore')"], ["Standardise MTU per link type"],
                 drop=1, findings=["ospf_mtu_mismatch", "ospf_exstart_stuck"]),
            fail("ospf_oneway", "One-way (stuck in INIT)", 1, "A hears B but B never lists A.",
                 ["Unidirectional link, ACL dropping multicast, NBMA without neighbor statements"],
                 ["Check multicast reachability both ways"], ["UDLD / BFD"], drop=0, findings=["ospf_one_way"])]),
    "isis": dict(
        title="IS-IS adjacency", match=["ISIS"],
        roles=["Router A", "Router B"],
        summary="IS-IS runs directly over layer 2 (LLC). Routers exchange IIH hellos padded to the interface MTU; level (L1/L2), "
                "area (for L1), authentication and MTU must match. LSPs are then flooded and SPF computed.",
        normal=[step(0, 1, "IIH hello (padded)", "Announces system ID, level, area; padding proves the MTU."),
                step(1, 0, "IIH listing A", "Adjacency UP."), step(0, 1, "LSP / CSNP", "Databases synchronise, SPF runs.")],
        failures=[
            fail("isis_level", "Level or area mismatch", 0, "Hellos both ways, adjacency never comes up.",
                 ["L1-only vs L2-only circuits", "Different areas on an L1 adjacency"], ["Align circuit-type / area"],
                 ["Consistent IS-IS design"], drop=1, findings=["isis_circuit_mismatch", "isis_area_mismatch"]),
            fail("isis_mtu", "MTU mismatch", 0, "Larger padded hellos are dropped by the smaller-MTU side.",
                 ["Different interface MTUs"], ["Match MTU"], ["Standard MTU"], drop=1, findings=["isis_mtu_mismatch"]),
            fail("isis_churn", "LSP churn", 2, "LSPs regenerated repeatedly, frequent SPF runs.",
                 ["Flapping link or prefix"], ["Find the flapping source"], ["Dampening, stable addressing"], findings=["isis_lsp_churn"])]),
    "bgp": dict(
        title="BGP session", match=["BGP"],
        roles=["Router A (AS 65001)", "Router B (AS 65002)"],
        summary="BGP peers open a TCP connection to port 179, exchange OPEN (AS, hold time, router ID, capabilities), confirm "
                "with KEEPALIVE (Established), then send UPDATEs with prefixes and keepalives every 60 s (hold 180 s).",
        normal=[step(0, 1, "TCP SYN → 179", "A initiates to B's configured neighbour address (eBGP TTL 1)."),
                step(1, 0, "SYN-ACK", "B has A configured as a neighbour and accepts."),
                step(0, 1, "OPEN", "AS number, hold time, router ID."),
                step(1, 0, "OPEN + KEEPALIVE", "Parameters accepted → Established."),
                step(0, 1, "UPDATE (prefixes)", "Routes exchanged; keepalives maintain the session.")],
        failures=[
            fail("bgp_refused", "TCP 179 refused", 0, "SYN to 179 answered with RST; retried every 30–120 s.",
                 ["Neighbour not configured on the peer", "Wrong update-source / neighbour address"],
                 ["Configure the neighbour; match update-source"], ["Peer configuration templates"],
                 reply=[1, 0, "RST"], findings=["tcp_conn_refused", "bgp_connect_fail"]),
            fail("bgp_open_err", "OPEN rejected", 2, "NOTIFICATION 'OPEN message error / Bad Peer AS'.",
                 ["remote-as mismatch", "Unacceptable hold time"], ["Fix remote-as / timers"], ["Automated peer config"],
                 reply=[1, 0, "NOTIFICATION"], findings=["bgp_notification"]),
            fail("bgp_hold", "Hold timer expired", 4, "NOTIFICATION 'Hold Timer Expired'; all routes withdrawn.",
                 ["Keepalives lost to congestion or CoPP", "Peer CPU overload"], ["Fix loss, protect BGP with QoS/CoPP"],
                 ["BFD for fast, reliable failure detection"], drop=1, findings=["bgp_notification", "bgp_session_flap"])]),
    # ====================================================================== tunnels / overlay
    "gre": dict(
        title="GRE tunnel", match=["GRE"],
        roles=["Host A", "Tunnel router A", "Underlay / ISP", "Tunnel router B", "Host B"],
        summary="The tunnel router wraps the original IP packet in a new IP header (source/destination = tunnel endpoints) plus "
                "a 4-byte GRE header. The underlay routes only on the outer header; the far endpoint strips it and routes the "
                "inner packet. Adds 24 bytes, so the tunnel MTU is 1476.",
        normal=[step(0, 1, "Inner packet A → B", "Route to B points into Tunnel0."),
                step(1, 3, "Outer IP + GRE + inner", "Encapsulated; underlay sees only 1.1.1.1 → 2.2.2.2."),
                step(3, 4, "Inner packet A → B", "Decapsulated and routed normally.")],
        failures=[
            fail("gre_recursive", "Recursive routing", 1, "Tunnel flaps: '%TUN-5-RECURSIVE'.",
                 ["Tunnel destination learned through the tunnel itself"], ["Static route to the tunnel destination via the underlay"],
                 ["Filter tunnel endpoints from the overlay routing protocol"], drop=1),
            fail("gre_mtu", "Large packets dropped", 1, "Small traffic fine, big transfers stall.",
                 ["No 'ip mtu'/'adjust-mss' on the tunnel"], ["ip mtu 1400, ip tcp adjust-mss 1360"], ["MTU budget per tunnel"],
                 drop=2, findings=["tunnel_oversize", "tunnel_mss_too_large"]),
            fail("gre_underlay", "Underlay path lost", 1, "Tunnel interface up (GRE has no keepalive by default) but traffic black-holed.",
                 ["ISP/underlay outage"], ["Enable tunnel keepalives or run a routing protocol over the tunnel"],
                 ["BFD / IP SLA on the tunnel"], drop=2)]),
    "vxlan": dict(
        title="VXLAN overlay (flood-and-learn)", match=["VXLAN"],
        roles=["Host A", "Leaf-1 (VTEP)", "Spine", "Leaf-2 (VTEP)", "Host B"],
        summary="Leaf switches (VTEPs) extend a layer-2 segment (VNI) across a routed underlay: the host's Ethernet frame is "
                "wrapped in UDP/4789 with the VNI. Broadcast/unknown frames (e.g. ARP) go to the VNI's underlay multicast group; "
                "the far VTEP learns 'MAC A is behind VTEP 1' from the outer source and later sends unicast.",
        normal=[step(0, 1, "ARP request (broadcast)", "Leaf-1: unknown destination → flood."),
                step(1, 2, "VXLAN → multicast group", "Encapsulated to the VNI's BUM group (PIM in the underlay)."),
                step(2, 3, "VXLAN (replicated)", "Spine replicates to every VTEP that joined the group."),
                step(3, 4, "ARP request", "Leaf-2 decapsulates, learns A's MAC → VTEP-1, floods locally."),
                step(4, 0, "Reply / ping (unicast VXLAN)", "Now known: unicast VXLAN between the VTEP loopbacks; ECMP may use either spine.")],
        failures=[
            fail("vx_mtu", "Underlay MTU too small", 2, "Pings work, large transfers fail — 50 bytes of overhead exceed 1500.",
                 ["Underlay links left at 1500"], ["Jumbo MTU (9216) on all underlay links"], ["MTU checks in fabric validation"],
                 drop=2, findings=["tunnel_oversize"]),
            fail("vx_mcast", "BUM multicast broken", 1, "ARP never reaches the remote host; unicast to learned MACs still works.",
                 ["PIM/RP problem in the underlay", "VTEP didn't join the group"], ["Check 'show ip mroute' for the group, RP reachability"],
                 ["Use ingress replication or BGP EVPN"], drop=2, findings=["pim_register_no_stop"]),
            fail("vx_vni", "VNI mismatch", 3, "Traffic encapsulated but dropped by the far VTEP.",
                 ["Different VLAN-to-VNI mapping on the leaves"], ["Align the mapping"], ["Automate fabric config"], drop=3)]),
    # ====================================================================== multicast
    "pim": dict(
        title="PIM sparse-mode multicast", match=["PIM"],
        roles=["Source", "First-hop DR", "RP", "Last-hop router", "Receiver"],
        summary="Receivers' routers join a shared tree toward the rendezvous point (RP). The source's DR unicasts the first "
                "packets to the RP inside PIM Register; the RP joins toward the source and sends Register-Stop; traffic then "
                "flows natively and last-hop routers may switch to the shortest-path tree.",
        normal=[step(4, 3, "IGMP report (join G)", "Receiver asks for group G."),
                step(3, 2, "PIM (*,G) Join", "Last-hop router joins the shared tree toward the RP."),
                step(0, 1, "Multicast data", "Source starts sending."),
                step(1, 2, "PIM Register (data inside)", "DR encapsulates to the RP."),
                step(2, 1, "Register-Stop", "RP has joined (S,G); native forwarding begins."),
                step(1, 4, "Native multicast", "Data flows down the tree to the receiver.")],
        failures=[
            fail("pim_rp", "RP unreachable / inconsistent", 3, "Registers without Register-Stop; receivers get nothing.",
                 ["Different RP configured on routers", "No route to the RP", "RPF failure"], ["Verify RP mapping and RPF"],
                 ["BSR/Anycast-RP redundancy"], drop=2, findings=["pim_register_no_stop"]),
            fail("pim_neighbor", "PIM not enabled on a link", 1, "Joins never cross a link; no PIM hellos there.",
                 ["'ip pim sparse-mode' missing on an interface"], ["Enable PIM on every multicast path interface"],
                 ["Config audit"], drop=2, findings=["pim_neighbors"]),
            fail("pim_rpf", "RPF check failure", 5, "Data arrives on the 'wrong' interface and is dropped.",
                 ["Unicast routing toward the source differs from the multicast path"], ["Static mroute or fix unicast routing"],
                 ["Congruent unicast/multicast topology"], drop=3)]),
    "igmp": dict(
        title="IGMP membership", match=["IGMP"],
        roles=["Receiver", "Switch (snooping)", "Querier router"],
        summary="The querier (lowest IP router) asks 'who wants multicast?' every 125 s; hosts answer with membership reports. "
                "Snooping switches forward each group only to ports that reported it.",
        normal=[step(2, 0, "General query", "Querier asks all hosts."), step(0, 2, "Membership report G", "Host wants group G."),
                step(0, 2, "Leave group G", "v2: router sends a group-specific query before pruning.")],
        failures=[
            fail("igmp_noq", "No querier", 0, "Memberships time out every few minutes; streams stop.",
                 ["PIM disabled on the VLAN interface", "L2-only VLAN without snooping querier"], ["Enable PIM or an IGMP snooping querier"],
                 ["Monitor querier presence"], drop=1, findings=["igmp_no_querier"]),
            fail("igmp_ver", "Version mismatch", 1, "IGMPv3 source-specific joins ignored.",
                 ["Router on v2, hosts on v3"], ["Align versions"], ["Standardise IGMP version"], findings=["igmp_version_mix"])]),
    # ====================================================================== IPv6
    "ipv6nd": dict(
        title="IPv6 neighbor discovery and SLAAC", match=["ICMPv6"],
        roles=["Host", "Router"],
        summary="IPv6 hosts build a link-local address, check it is unique (DAD), ask for routers (RS), and receive a Router "
                "Advertisement with the prefix and flags. With M=0/O=0 they form their global address themselves (SLAAC). "
                "Neighbor Solicitation/Advertisement replaces ARP.",
        normal=[step(0, 0, "DAD: NS from ::", "Host checks nobody owns its tentative address (no answer = unique)."),
                step(0, 1, "Router Solicitation", "Host asks ff02::2 for routers."),
                step(1, 0, "Router Advertisement", "Prefix 2001:db8::/64, router lifetime, M/O flags."),
                step(0, 1, "NS for router", "Resolve the router's MAC (solicited-node multicast)."),
                step(1, 0, "NA", "Router answers; traffic flows.")],
        failures=[
            fail("nd_no_ra", "No Router Advertisement", 1, "Hosts only have link-local addresses; no IPv6 default route.",
                 ["'ipv6 unicast-routing' missing", "RA suppressed"], ["Enable IPv6 routing on the gateway"], ["Monitor RA presence"],
                 drop=1, findings=["ipv6_rs_no_ra"]),
            fail("nd_rogue", "Rogue RA", 2, "Second router advertises another prefix; hosts pick a bogus gateway.",
                 ["Misconfigured device or attacker"], ["Locate and shut the port"], ["RA Guard on access ports"],
                 reply=[1, 0, "RA from rogue router"], findings=["ipv6_multiple_ra_sources"]),
            fail("nd_dad", "Duplicate address", 0, "DAD NS answered by another node; the address is disabled.",
                 ["Static duplicate / cloned VM"], ["Re-address one node"], ["DHCPv6 reservations or stable privacy addresses"],
                 reply=[1, 0, "NA: address in use"], findings=["ipv6_dad_conflict"])]),
    # ====================================================================== access control / applications
    "dot1x": dict(
        title="802.1X / RADIUS network access", match=["EAPOL", "RADIUS"],
        roles=["Supplicant (client)", "Authenticator (switch / AP)", "RADIUS server (ISE)"],
        summary="Until authenticated, the port passes only EAPOL. The authenticator asks for an identity, relays the EAP "
                "method exchange (TLS/PEAP/MD5) inside RADIUS Access-Requests to the server, and opens the port (with the "
                "VLAN/ACL the server returns) on Access-Accept → EAP-Success. Wi-Fi then derives keys in the 4-way handshake.",
        normal=[step(1, 0, "EAP Request/Identity", "Port in unauthorised state."),
                step(0, 1, "EAP Response/Identity", "Username / certificate identity."),
                step(1, 2, "RADIUS Access-Request (EAP inside)", "Relayed to the server with NAS-IP, port, MAC."),
                step(2, 1, "Access-Challenge (method)", "Server picks the method (EAP-TLS …); several round trips."),
                step(2, 1, "Access-Accept (+VLAN/ACL)", "Policy matched."),
                step(1, 0, "EAP Success", "Port authorised; Wi-Fi runs the 4-way key handshake.")],
        failures=[
            fail("dot1x_reject", "Access-Reject", 4, "Access-Reject → EAP-Failure; client lands in auth-fail/guest VLAN.",
                 ["Wrong credentials / expired or untrusted certificate", "Authorization policy mismatch"],
                 ["Read the failure reason in the RADIUS/ISE live log"], ["Certificate lifecycle management"],
                 reply=[2, 1, "Access-Reject"], findings=["dot1x_failure", "radius_reject"]),
            fail("radius_down", "RADIUS server not answering", 2, "Access-Requests retransmitted, no reply; clients stuck authenticating.",
                 ["Server down/unreachable", "Shared secret mismatch (server silently drops)", "NAS not defined on the server"],
                 ["Check reachability and NAS definition / secret"], ["Two RADIUS servers, critical-auth VLAN"],
                 drop=2, findings=["radius_no_response", "dot1x_incomplete"]),
            fail("dot1x_no_supplicant", "No supplicant", 0, "Identity requests repeat every 30 s with no response.",
                 ["Client has 802.1X disabled (printer, phone)"], ["Enable the supplicant or use MAB"], ["MAB fallback / device profiling"],
                 drop=0, findings=["dot1x_incomplete"]),
            fail("dot1x_md5", "Weak method (EAP-MD5)", 3, "EAP-MD5 challenge/response visible in the clear.",
                 ["Legacy policy allows MD5"], ["Move to EAP-TLS / PEAP"], ["Remove weak methods from allowed protocols"],
                 findings=["dot1x_weak_method"])]),
    "tls": dict(
        title="TLS handshake", match=["TLS"],
        roles=["Client", "Gateway / firewall", "Server"],
        summary="After the TCP handshake the client sends ClientHello (versions, cipher suites, SNI, ALPN); the server answers "
                "ServerHello with its choice and certificate; keys are agreed and application data flows encrypted.",
        normal=[step(0, 2, "ClientHello (SNI)", "Offers TLS 1.3/1.2 and cipher suites."),
                step(2, 0, "ServerHello + certificate", "Chooses version/cipher; proves identity."),
                step(0, 2, "Finished", "Keys confirmed."), step(2, 0, "Encrypted application data", "HTTP/2 or HTTP/1.1 inside.")],
        failures=[
            fail("tls_alert", "Handshake alert", 1, "Server/client sends a fatal alert (handshake_failure, unknown_ca, protocol_version).",
                 ["No common cipher/version", "Untrusted or expired certificate", "SNI unknown to the server"],
                 ["Check the alert code; align versions/ciphers; fix the certificate chain"], ["Certificate monitoring"],
                 reply=[2, 0, "Alert (fatal)"], findings=["tls_alert", "tls_handshake_failure"]),
            fail("tls_intercept", "Blocked by SNI inspection", 0, "ClientHello followed by RST from a device with a different TTL.",
                 ["Firewall URL/SNI policy"], ["Review the firewall policy"], ["Clear block pages / logging"],
                 reply=[1, 0, "RST (firewall)"], findings=["tls_handshake_failure"]),
            fail("tls_old", "Old protocol / weak cipher", 1, "TLS 1.0/1.1 or 3DES/RC4 negotiated.",
                 ["Legacy server or client configuration"], ["Disable old versions/ciphers"], ["TLS configuration baseline"],
                 findings=["tls_old_version", "tls_weak_cipher"])]),
    "http": dict(
        title="HTTP request / response", match=["HTTP", "HTTP2"],
        roles=["Browser", "Gateway / proxy", "Web server"],
        summary="Over an established TCP (or TLS) connection the client sends a request line and headers; the server answers "
                "with a status code, headers and body. Keep-alive reuses the connection; HTTP/2 multiplexes streams.",
        normal=[step(0, 2, "GET /index.html", "Request with Host header."), step(2, 0, "200 OK + body", "Server response.")],
        failures=[
            fail("http_5xx", "Server error (5xx)", 1, "502/503/504 from a proxy or 500 from the application.",
                 ["Application crash / back-end unreachable", "Proxy timeout to the back-end"], ["Check application and proxy logs"],
                 ["Health checks, capacity"], reply=[2, 0, "503 Service Unavailable"], findings=["http_server_errors"]),
            fail("http_slow", "Slow server response", 1, "Request ACKed quickly, first response byte seconds later (server think time).",
                 ["Slow database / back-end", "Resource exhaustion"], ["Profile the application"], ["APM monitoring"],
                 findings=["http_slow_response", "tcp_slow_response"])]),
}


def for_capture(stats: dict, findings: list, folder: str = "") -> list[str]:
    """Topic ids relevant to a capture, most specific first."""
    have = {k for k, _ in stats.get("protocols", [])} | {k for k, _ in stats.get("layers", [])} | {f.id for f in findings}
    folder = folder.lower()
    out = []
    for tid, t in TOPICS.items():
        if tid in folder or t["title"].lower().split()[0] in folder or have & set(t["match"]):
            out.append(tid)
    # the folder's own topic first
    out.sort(key=lambda t: (not (t in folder or TOPICS[t]["title"].lower().split()[0] in folder), list(TOPICS).index(t)))
    return out
