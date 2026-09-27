"""Command-line interface.

    packetlens analyze capture.pcapng [--html report.html] [--json out.json]
    packetlens demo [--out demo.pcapng] [--html demo.html]
    packetlens serve [--host 127.0.0.1] [--port 8080]
    packetlens batch pcap_folder/ [--out packetlens-reports]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap

from . import __version__
from .analyzer import analyze_file
from .reader import CaptureFormatError
from .report import html

COL = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def _c(s: str, code: str, on: bool) -> str:
    return f"{code}{s}{RESET}" if on else s


def text_report(a, color: bool = True, verbose: bool = False, width: int = 100) -> str:
    st = a.stats()
    out = []
    w = lambda s="": out.append(s)  # noqa: E731
    wrap = lambda s, ind="    ": textwrap.fill(s, width, initial_indent=ind, subsequent_indent=ind)  # noqa: E731
    w(_c(f"PacketLens {__version__} — {os.path.basename(a.source)}", BOLD, color))
    w(f"  {st['packets']:,} packets · {st['bytes']:,} bytes · {st['duration']:.3f} s · "
      f"{st['tcp_streams']} TCP streams · {st['conversations']} conversations")
    h = st["health"]
    w("  Health: " + " · ".join(f"{k} {v}" for k, v in h.items()))
    if a.capture_point:
        w(f"  Capture point: {a.capture_point}")
    w("  Protocols: " + ", ".join(f"{k} {v}" for k, v in st["protocols"][:12]))
    for warn in a.warnings:
        w(_c(f"  ! {warn}", COL["medium"], color))
    w()
    w(_c(f"ROOT CAUSES ({len(a.root_causes)})", BOLD, color))
    if not a.root_causes:
        w("  none — no correlated problems found")
    for i, r in enumerate(a.root_causes, 1):
        w(f"  {i}. " + _c(f"[{r.severity.upper()}]", COL[r.severity], color) +
          f" {_c(r.title, BOLD, color)}  {DIM if color else ''}(fault domain: {r.fault_domain}, confidence {r.confidence:.0%}){RESET if color else ''}")
        w(wrap("What happened: " + r.verdict, "     "))
        w(wrap("Why: " + r.narrative, "     "))
        if r.chain:
            w("     Chain:")
            for s in r.chain:
                when = f"t={s['t']:.3f}s" if s["t"] is not None else "t=?"
                w(f"       → {when:>12} {('#' + str(s['no'])) if s['no'] else '':>6} [{s['layer']}] {s['text'][:width - 30]}")
        if verbose:
            for k, v in r.perspectives.items():
                w(wrap(f"{k.capitalize()} perspective: {v}", "     "))
        w("     Remediation: " + (r.remediation[0] if r.remediation else "—"))
        for x in r.remediation[1:3 if not verbose else None]:
            w("                  " + x)
        w()
    w(_c(f"FINDINGS ({len(a.findings)})", BOLD, color))
    for f in a.findings:
        w(f"  {f.uid} " + _c(f"{f.severity.upper():8}", COL[f.severity], color) + f" {f.protocol:6} {_c(f.title, BOLD, color)}")
        w(wrap(f.summary, "        "))
        if verbose:
            w(wrap("Likely causes: " + "; ".join(f.causes[:4]), "        "))
            for k, v in f.perspectives.items():
                w(wrap(f"{k}: {v}", "        "))
            w(wrap("Fix: " + "; ".join(f.remediation), "        "))
            if f.filter:
                w(f"        Wireshark filter: {f.filter}")
    return "\n".join(out)


def _output_args(p) -> None:
    p.add_argument("--html", help="write the interactive HTML report to this path")
    p.add_argument("--json", help="write the full analysis as JSON to this path ('-' for stdout)")
    p.add_argument("--keylog", help="TLS key log (SSLKEYLOGFILE) to decrypt TLS 1.2/1.3 sessions")
    p.add_argument("--packet-list", type=int, default=5000, help="packets embedded in the HTML/JSON packet list")
    p.add_argument("-v", "--verbose", action="store_true", help="print perspectives, causes and filters for every finding")
    p.add_argument("-q", "--quiet", action="store_true", help="no console report")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="exit 2 if a finding at or above this severity exists (CI use)")


def _emit(a, args, extra_text: str = "") -> int:
    color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    data = a.to_dict(packet_limit=args.packet_list) if (args.html or args.json) else None
    if args.json:
        js = json.dumps(data, default=html._json_default, indent=1)
        if args.json == "-":
            print(js)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(js)
    if args.html:
        html.write(data, args.html)
    if not args.quiet and args.json != "-":
        if extra_text:
            print(extra_text + "\n")
        print(text_report(a, color=color, verbose=args.verbose))
        if args.html:
            print(f"\nHTML report: {args.html}")
    if args.fail_on:
        from .findings import SEVERITY_ORDER
        if any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[args.fail_on] for f in a.findings):
            return 2
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="packetlens", description="Modern pcap/pcapng analyzer with root-cause correlation.")
    ap.add_argument("--version", action="version", version=f"PacketLens {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="analyze a capture file")
    an.add_argument("capture")
    an.add_argument("--max-packets", type=int, default=None)
    an.add_argument("--keep-payload", action="store_true", help="keep payload bytes in memory after decoding")
    _output_args(an)
    cp = sub.add_parser("compare", help="compare two captures of the same traffic taken at different points (locate loss)")
    cp.add_argument("capture_a")
    cp.add_argument("capture_b")
    _output_args(cp)
    lv = sub.add_parser("live", help="capture live traffic (Linux, root/CAP_NET_RAW) and analyze it")
    lv.add_argument("-i", "--interface", default="any")
    lv.add_argument("-d", "--duration", type=float, default=30.0, help="seconds to capture (default 30)")
    lv.add_argument("-c", "--count", type=int, default=None, help="stop after N packets")
    lv.add_argument("--host", help="only packets to/from this IPv4 address")
    lv.add_argument("--port", type=int, help="only TCP/UDP packets on this port")
    lv.add_argument("-s", "--snaplen", type=int, default=262144)
    lv.add_argument("-w", "--write", default="packetlens-live.pcapng", help="pcapng file to save the capture to")
    _output_args(lv)
    dm = sub.add_parser("demo", help="generate a demo capture covering every analyzer and analyze it")
    dm.add_argument("--out", default="packetlens-demo.pcapng")
    dm.add_argument("--html", default="packetlens-demo.html")
    dm.add_argument("--format", choices=["pcapng", "pcap"], default="pcapng")
    sv = sub.add_parser("serve", help="run the local web UI (upload a capture in the browser)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    sv.add_argument("--max-mb", type=int, default=200)
    bt = sub.add_parser("batch", help="analyze every capture under a folder and build an index of 3D reports")
    bt.add_argument("folder")
    bt.add_argument("--out", default="packetlens-reports", help="output folder (default: packetlens-reports)")
    bt.add_argument("--max-packets", type=int, default=None)
    ap_ = sub.add_parser("app", help="run PacketLens Studio: library, 3D replay, packet simulator and live capture")
    ap_.add_argument("folder", nargs="?", help="capture library folder (optional)")
    ap_.add_argument("--port", type=int, default=8090)
    ap_.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    args = ap.parse_args(argv)

    if args.cmd == "app":
        from .app.server import serve as serve_app
        if args.folder and not os.path.isdir(args.folder):
            print(f"error: {args.folder} is not a folder", file=sys.stderr)
            return 1
        serve_app(args.folder, port=args.port, open_browser=not args.no_browser)
        return 0
    if args.cmd == "batch":
        from .batch import run as run_batch
        if not os.path.isdir(args.folder):
            print(f"error: {args.folder} is not a folder", file=sys.stderr)
            return 1
        print(f"Analyzing captures under {args.folder} …")
        res = run_batch(args.folder, args.out, args.max_packets)
        print(f"\n{res['captures']} captures analyzed ({res['errors']} errors, {res['skipped_pkt']} .pkt files skipped).")
        print(f"Open: {res['index']}")
        return 1 if res["errors"] else 0
    if args.cmd == "serve":
        from .web import serve
        serve(args.host, args.port, args.max_mb)
        return 0
    if args.cmd == "demo":
        from .synth import write_demo
        n = write_demo(args.out, args.format)
        print(f"Wrote demo capture {args.out} ({n} packets)")
        a = analyze_file(args.out)
        html.write(a.to_dict(), args.html)
        print(text_report(a, color=sys.stdout.isatty()))
        print(f"\nHTML report: {args.html}")
        return 0
    try:
        if args.cmd == "compare":
            from .compare import annotate, compare_files, text
            a, _b, res = compare_files(args.capture_a, args.capture_b, keylog_path=args.keylog)
            annotate(a, res)
            return _emit(a, args, text(res))
        if args.cmd == "live":
            from . import live
            print(f"Capturing on {args.interface} for {args.duration:g}s"
                  + (f" or {args.count} packets" if args.count else "") + " … (Ctrl+C to stop early)", file=sys.stderr)
            frames: list = []
            try:
                live.capture(args.interface, args.duration, args.count, args.snaplen, args.host, args.port,
                             on_packet=frames.append)
            except KeyboardInterrupt:
                pass
            live.save(frames, args.write)
            print(f"Saved {len(frames)} packets to {args.write}", file=sys.stderr)
            a = analyze_file(args.write, keylog_path=args.keylog)
            return _emit(a, args)
        a = analyze_file(args.capture, max_packets=args.max_packets, keylog_path=args.keylog,
                         keep_payload=args.keep_payload)
    except (CaptureFormatError, FileNotFoundError, PermissionError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        from .live import LiveCaptureError
        if isinstance(exc, LiveCaptureError):
            print(f"error: {exc}", file=sys.stderr)
            return 1
        raise
    return _emit(a, args)


if __name__ == "__main__":
    sys.exit(main())
