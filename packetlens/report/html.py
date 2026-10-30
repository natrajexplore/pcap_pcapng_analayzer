"""HTML report renderer (works offline; the 3D view loads the bundled three.min.js placed next to the report)."""
from __future__ import annotations

import html
import json
import shutil
from pathlib import Path

TEMPLATE = Path(__file__).with_name("template.html")
THREE_JS = Path(__file__).with_name("vendor") / "three.min.js"


def _json_default(o):
    if isinstance(o, (set, frozenset, tuple)):
        return sorted(o) if isinstance(o, (set, frozenset)) else list(o)
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def render(data: dict, three_src: str = "three.min.js") -> str:
    payload = json.dumps(data, default=_json_default, separators=(",", ":"))
    # keep the JSON island from closing the <script> element early
    payload = payload.replace("<", "\\u003c")
    # fill the template's own placeholders before inserting capture data, which must never be substituted into
    page = TEMPLATE.read_text(encoding="utf-8").replace("__THREE_SRC__", html.escape(three_src, quote=True))
    return page.replace("__PACKETLENS_DATA__", payload)


def write(data: dict, path: str, three_src: str | None = None) -> str:
    """Write the report; unless ``three_src`` points elsewhere, put three.min.js next to it (once)."""
    out = Path(path)
    if three_src is None:
        three_src = THREE_JS.name
        target = out.parent / THREE_JS.name
        if not target.exists():
            shutil.copyfile(THREE_JS, target)
    out.write_text(render(data, three_src), encoding="utf-8")
    return path
