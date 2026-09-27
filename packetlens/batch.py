"""Batch mode: analyze every capture under a folder, stitch captures that share a folder, write one report per
capture (mirroring the folder tree) and an index.html hub linking them."""
from __future__ import annotations

import html
import os
import shutil
import time
from pathlib import Path

from . import __version__
from .analyzer import analyze_file, worst_severity
from .path import stitch
from .reader import CaptureFormatError
from .report.html import THREE_JS, write

CAPTURE_EXT = (".pcap", ".pcapng", ".cap")
ASSETS = "_assets"


def run(src: str, out: str, max_packets: int | None = None, log=print) -> dict:
    src_p, out_p = Path(src), Path(out)
    files = sorted(p for p in src_p.rglob("*") if p.is_file() and p.suffix.lower() in CAPTURE_EXT)
    skipped = sorted(p for p in src_p.rglob("*.pkt"))
    (out_p / ASSETS).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(THREE_JS, out_p / ASSETS / THREE_JS.name)
    shutil.copyfile(THREE_JS.with_name("LICENSE-three.txt"), out_p / ASSETS / "LICENSE-three.txt")
    results, by_folder = [], {}
    for f in files:
        rel = f.relative_to(src_p)
        t = time.time()
        try:
            a = analyze_file(str(f), max_packets=max_packets)
        except (CaptureFormatError, OSError) as exc:
            log(f"  ! {rel}: {exc}")
            results.append({"rel": rel, "error": str(exc)})
            continue
        r = {"rel": rel, "a": a, "seconds": time.time() - t}
        results.append(r)
        by_folder.setdefault(rel.parent, []).append(r)
        log(f"  {rel}  {len(a.packets)} packets, {len(a.findings)} findings, {len(a.root_causes)} root causes")
    for folder, rs in by_folder.items():                   # several captures of one network: one stitched path
        paths = [r["a"].path for r in rs if r["a"].path]
        folder_path = stitch(paths) if len(paths) > 1 else None
        for r in rs:
            data = r["a"].to_dict()
            if folder_path:
                data["path_folder"] = folder_path
            target = out_p / r["rel"].with_suffix(r["rel"].suffix + ".html")
            target.parent.mkdir(parents=True, exist_ok=True)
            write(data, str(target), three_src=os.path.relpath(out_p / ASSETS / THREE_JS.name, target.parent).replace(os.sep, "/"))
            r["report"] = target.relative_to(out_p).as_posix()
            r["stitched"] = bool(folder_path)
            r["topics"] = [s["title"] for s in data["scenarios"]]
            r["health"] = data["stats"]["health"]["overall"]
    index = out_p / "index.html"
    index.write_text(_index(src_p, results, skipped), encoding="utf-8")
    return {"index": str(index), "captures": len(files), "errors": sum(1 for r in results if "error" in r),
            "skipped_pkt": len(skipped)}


def _index(src: Path, results: list, skipped: list) -> str:
    e = html.escape
    folders: dict = {}
    for r in results:
        folders.setdefault(r["rel"].parent.as_posix() if r["rel"].parent.as_posix() != "." else "(top level)", []).append(r)
    cards = []
    for folder, rs in sorted(folders.items(), key=lambda x: x[0].lower()):
        rows = []
        for r in rs:
            if "error" in r:
                rows.append(f'<li class="cap"><span>{e(r["rel"].name)}</span><span class="muted">error: {e(r["error"])}</span></li>')
                continue
            a = r["a"]
            worst = worst_severity(a) or "info"
            top = a.root_causes[0].title if a.root_causes else (a.findings[0].title if a.findings else "No problems detected")
            rows.append(f'<li class="cap"><a href="{e(r["report"])}">{e(r["rel"].name)}</a>'
                        f'<span class="meta"><span class="sev {e(worst)}">{e(worst)}</span> health {r["health"]} · '
                        f'{len(a.packets):,} pkts · {len(a.findings)} findings</span>'
                        f'<span class="muted small">{e(top)}</span></li>')
        ok = [r for r in rs if "error" not in r]
        topics = sorted({t for r in ok for t in r["topics"][:3]})
        cards.append(f'<section class="card" data-q="{e(folder.lower())} {e(" ".join(topics).lower())}"><h2>{e(folder)}</h2>'
                     + (f'<div class="chips">{"".join(f"<span class=chip>{e(t)}</span>" for t in topics)}</div>' if topics else "")
                     + (f'<p class="small muted">{len(ok)} captures of this folder are stitched into one end-to-end path '
                        '(see “Whole folder” in each report\'s Path 3D tab).</p>' if any(r.get("stitched") for r in ok) else "")
                     + f'<ul>{"".join(rows)}</ul></section>')
    total = sum(len(r["a"].packets) for r in results if "error" not in r)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PacketLens Library</title><style>
:root{{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--surface-2:#f0efec;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;--border:rgba(11,11,11,.10);--accent:#2a78d6;
 --crit:#d03b3b;--high:#ec835a;--med:#fab219;--low:#2a78d6;--info:#898781}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;--ink:#fff;--ink-2:#c3c2b7;--border:rgba(255,255,255,.10);--accent:#3987e5;--low:#3987e5}}}}
:root[data-theme="dark"]{{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--surface-2:#232321;--ink:#fff;--ink-2:#c3c2b7;--border:rgba(255,255,255,.10);--accent:#3987e5;--low:#3987e5}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--page);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1300px;margin:0 auto;padding:20px 16px}} h1{{font-size:24px;margin:0 0 4px}} h2{{font-size:16px;margin:0 0 6px}}
a{{color:var(--accent)}} .muted{{color:var(--ink-2)}} .small{{font-size:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px;margin-top:14px}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;min-width:0}}
ul{{list-style:none;margin:6px 0 0;padding:0}} li.cap{{display:grid;gap:2px;padding:8px 0;border-top:1px solid var(--border)}}
li.cap a{{font-weight:600;word-break:break-all}} .meta{{font-size:12.5px;color:var(--ink-2)}}
.sev{{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:600;text-transform:uppercase;margin-right:6px}}
.sev::before{{content:"";width:9px;height:9px;border-radius:3px;background:var(--c)}}
.sev.critical{{--c:var(--crit)}} .sev.high{{--c:var(--high)}} .sev.medium{{--c:var(--med)}} .sev.low{{--c:var(--low)}} .sev.info{{--c:var(--info)}}
.chips{{margin:2px 0 4px}} .chip{{display:inline-block;padding:1px 8px;border-radius:999px;border:1px solid var(--border);background:var(--surface-2);font-size:11.5px;color:var(--ink-2);margin:0 4px 4px 0}}
input{{font:inherit;padding:7px 11px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);width:min(420px,100%)}}
header{{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;justify-content:space-between}}
</style></head><body><main><header><div><h1>PacketLens capture library</h1>
<div class="muted">{len(results)} captures · {total:,} packets · {len(folders)} topics · source <code>{e(src.name)}</code> · v{e(__version__)}</div>
{f'<div class="muted small">{len(skipped)} Cisco Packet Tracer (.pkt) files were skipped — they are simulation labs, not packet captures.</div>' if skipped else ''}</div>
<input type="search" id="q" placeholder="Filter by folder or protocol…" aria-label="Filter captures"></header>
<p class="small muted">Each report: <b>Path 3D</b> (inferred source→destination path, animated packets, break point), <b>Scenarios</b> (normal packet travel, what goes wrong, why, fix and prevention), root causes and findings.</p>
<div class="grid" id="g">{"".join(cards)}</div></main>
<script>document.getElementById("q").addEventListener("input",e=>{{const q=e.target.value.toLowerCase();
document.querySelectorAll("#g section").forEach(s=>s.style.display=s.dataset.q.includes(q)||s.textContent.toLowerCase().includes(q)?"":"none");}});</script>
</body></html>"""
