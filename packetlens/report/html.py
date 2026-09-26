"""Self-contained HTML report renderer (no external assets, works offline)."""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name("template.html")


def _json_default(o):
    if isinstance(o, (set, frozenset, tuple)):
        return sorted(o) if isinstance(o, (set, frozenset)) else list(o)
    if isinstance(o, bytes):
        return o.hex()
    return str(o)


def render(data: dict) -> str:
    payload = json.dumps(data, default=_json_default, separators=(",", ":"))
    # keep the JSON island from closing the <script> element early
    payload = payload.replace("<", "\\u003c")
    return TEMPLATE.read_text(encoding="utf-8").replace("__PACKETLENS_DATA__", payload)


def write(data: dict, path: str) -> str:
    Path(path).write_text(render(data), encoding="utf-8")
    return path
