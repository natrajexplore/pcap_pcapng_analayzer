"""Layer-2 switching expert: CDP/LLDP neighbors, DTP trunking, ISL, 802.1Q/native VLAN, per-VLAN spanning tree."""
from __future__ import annotations

from collections import defaultdict

from ..knowledge import make

L2_CONTROL = {"STP", "CDP", "DTP", "LLDP", "LOOP", "DEC-MOP-RC", "LLC"}


def run(ctx) -> None:
    F = ctx.findings
    pk = ctx.packets
    # ------------------------------------------------------- neighbors --
    nbrs: dict = {}
    for p in pk:
        for proto in ("cdp", "lldp"):
            d = p.layers.get(proto)
            if not d:
                continue
            name = d.get("device_id") or d.get("system_name") or d.get("chassis_id") or p.eth_src
            n = nbrs.setdefault(name, {"device": name, "protocol": proto.upper(), "mac": p.eth_src, "ports": set(),
                                       "platform": d.get("platform") or d.get("system_description"),
                                       "capabilities": d.get("capabilities", []), "addresses": set(),
                                       "native_vlan": set(), "duplex": set(), "vlans": set(), "first_no": p.no,
                                       "ts": p.ts})
            n["ports"].add(d.get("port_id", "?"))
            n["addresses"].update(d.get("addresses", []))
            if "native_vlan" in d:
                n["native_vlan"].add(d["native_vlan"])
            if "duplex" in d:
                n["duplex"].add(d["duplex"])
            if p.vlan is not None:
                n["vlans"].add(p.vlan)
    ns = list(nbrs.values())
    if ns:
        F.append(make("l2_neighbors", f"{len(ns)} neighbor device(s) announce themselves on this link: " + "; ".join(
            f"{n['device']} ({(n['platform'] or '?')[:40]}) port {', '.join(sorted(n['ports']))}"
            + (f", native VLAN {', '.join(map(str, sorted(n['native_vlan'])))}" if n["native_vlan"] else "")
            for n in ns[:6]) + ".", entities=[n["device"] for n in ns], ts=ns[0]["ts"],
            packets=[n["first_no"] for n in ns][:20]))
    natives = {n["device"]: sorted(n["native_vlan"]) for n in ns if n["native_vlan"]}
    if len({v for vs in natives.values() for v in vs}) > 1:
        F.append(make("cdp_native_vlan_mismatch", "Neighbors disagree on the trunk native VLAN: " +
                      "; ".join(f"{d} native VLAN {', '.join(map(str, v))}" for d, v in natives.items()) +
                      ". Untagged frames from one side land in a different VLAN on the other side.",
                      entities=list(natives), packets=[n["first_no"] for n in ns if n["native_vlan"]],
                      ts=ns[0]["ts"], details={"native_vlans": natives}))
    duplex = {n["device"]: sorted(n["duplex"]) for n in ns if n["duplex"]}
    if len({v for vs in duplex.values() for v in vs}) > 1:
        F.append(make("cdp_duplex_mismatch", "Neighbors report different duplex settings: " +
                      "; ".join(f"{d} {', '.join(v)}" for d, v in duplex.items()) + ".",
                      entities=list(duplex), packets=[n["first_no"] for n in ns if n["duplex"]], ts=ns[0]["ts"]))

    # ------------------------------------------------------------- DTP --
    dtp: dict = {}
    for p in pk:
        d = p.layers.get("dtp")
        if d:
            dtp.setdefault(p.eth_src, {"mac": p.eth_src, "admin": set(), "operational": set(), "encapsulation": set(),
                                       "first_no": p.no, "ts": p.ts})
            for k in ("admin", "operational", "encapsulation"):
                if d.get(k):
                    dtp[p.eth_src][k].add(d[k])
    if dtp:
        sp = list(dtp.values())
        F.append(make("dtp_negotiation_enabled",
                      f"{len(sp)} switch port(s) are sending DTP: " + "; ".join(
                          f"{s['mac']} mode {'/'.join(sorted(s['admin']))} → {'/'.join(sorted(s['operational']))}"
                          for s in sp[:6]) + ". Any host on these ports could negotiate a trunk (switch spoofing).",
                      entities=[s["mac"] for s in sp], packets=[s["first_no"] for s in sp][:20], ts=sp[0]["ts"]))
        auto = [s for s in sp if s["admin"] == {"auto"}]
        if len(auto) >= 2 and all(s["operational"] == {"access"} for s in auto):
            F.append(make("dtp_trunk_not_formed",
                          f"Both ends are in DTP 'dynamic auto' ({', '.join(s['mac'] for s in auto)}): each waits for the "
                          "other to ask, so the link stays an access port and only one VLAN crosses it.",
                          entities=[s["mac"] for s in auto], packets=[s["first_no"] for s in auto], ts=auto[0]["ts"]))

    # --------------------------------------------------- ISL / 802.1Q --
    isl = [p for p in pk if "isl" in p.layers]
    if isl:
        F.append(make("isl_trunk", f"{len(isl)} frames use Cisco ISL trunk encapsulation "
                                   f"(VLANs {', '.join(map(str, sorted({p.layers['isl']['vlan'] for p in isl})))}).",
                      packets=[p.no for p in isl[:10]], ts=isl[0].ts, count=len(isl)))
    eth = [p for p in pk if p.eth_src and "wlan" not in p.layers and "isl" not in p.layers]
    tagged = [p for p in eth if p.vlan is not None]
    if tagged:
        untagged = [p for p in eth if p.vlan is None]
        # switch control frames (CDP/DTP/STP/keepalives) are always untagged; only user traffic shows native-VLAN use
        user_untagged = [p for p in untagged if p.protocol not in L2_CONTROL]
        vlans = sorted({p.vlan for p in tagged})
        native = sorted({v for n in ns for v in n["native_vlan"]})
        F.append(make("vlan_trunk_summary",
                      f"802.1Q trunk carrying VLAN(s) {', '.join(map(str, vlans))} ({len(tagged)} tagged frames); "
                      f"{len(untagged)} untagged frames belong to the native VLAN"
                      + (f" (VLAN {', '.join(map(str, native))} per CDP)" if native else "") + ".",
                      ts=tagged[0].ts, details={"vlans": vlans, "tagged": len(tagged), "untagged": len(untagged),
                                               "native": native}))
        if 1 in native or user_untagged:
            ev = user_untagged or untagged
            F.append(make("vlan_native_vlan1",
                          (f"The trunk's native VLAN is the default VLAN 1 (per CDP)" if 1 in native else
                           f"{len(user_untagged)} untagged user frame(s) cross this trunk in the native VLAN")
                          + f" alongside tagged VLANs {', '.join(map(str, vlans[:8]))}. A frame double-tagged with the "
                          "native VLAN can hop into another VLAN.", packets=[p.no for p in ev[:5]], ts=ev[0].ts))

    # ------------------------------------------------- per-VLAN STP ----
    roots = defaultdict(set)
    for p in pk:
        d = p.layers.get("stp")
        if d and d.get("root"):
            roots[d.get("vlan") or p.vlan].add(d["root"])
    if roots:
        mode = "PVST+/Rapid-PVST+" if any(p.layers.get("stp", {}).get("pvst") for p in pk) else "802.1D/RSTP/MST"
        F.append(make("stp_summary", f"Spanning tree ({mode}) — root bridge per VLAN: " + "; ".join(
            f"VLAN {v if v is not None else 'untagged'}: {', '.join(sorted(r))}"
            for v, r in sorted(roots.items(), key=lambda x: (x[0] is None, x[0] or 0))[:8]) + ".",
            details={"roots": {str(v): sorted(r) for v, r in roots.items()}, "mode": mode}))
    ctx.routing["l2"] = {"neighbors": [{**n, "ports": sorted(n["ports"]), "addresses": sorted(n["addresses"]),
                                        "native_vlan": sorted(n["native_vlan"]), "duplex": sorted(n["duplex"]),
                                        "vlans": sorted(n["vlans"])} for n in ns],
                         "dtp": [{**s, "admin": sorted(s["admin"]), "operational": sorted(s["operational"]),
                                  "encapsulation": sorted(s["encapsulation"])} for s in dtp.values()],
                         "stp_roots": {str(v): sorted(r) for v, r in roots.items()}}
