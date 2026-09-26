"""HTTP/1.x request / response line and header parser."""
from __future__ import annotations

import re

METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ",
           b"CONNECT ", b"TRACE ", b"PROPFIND ")
_REQ = re.compile(rb"^([A-Z]+) (\S+) (HTTP/\d\.\d)\r?\n")
_RESP = re.compile(rb"^(HTTP/\d\.\d) (\d{3}) ?([^\r\n]*)\r?\n")


def looks_like_http(payload: bytes) -> bool:
    return payload.startswith(METHODS) or payload.startswith(b"HTTP/1.")


def parse(payload: bytes) -> dict | None:
    head, _, body = payload.partition(b"\r\n\r\n")
    m = _REQ.match(head + b"\n")
    d: dict
    if m:
        d = {"type": "request", "method": m.group(1).decode(), "uri": m.group(2).decode("latin-1"),
             "version": m.group(3).decode()}
    else:
        m = _RESP.match(head + b"\n")
        if not m:
            return None
        d = {"type": "response", "version": m.group(1).decode(), "status": int(m.group(2)),
             "reason": m.group(3).decode("latin-1").strip()}
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        k, sep, v = line.partition(b":")
        if sep:
            headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    d["headers"] = headers
    d["host"] = headers.get("host")
    d["user_agent"] = headers.get("user-agent")
    d["content_type"] = headers.get("content-type")
    d["body_len"] = len(body)
    d["body_preview"] = body[:200].decode("latin-1", "replace")
    if d["type"] == "request":
        host = d["host"] or ""
        uri = d["uri"]
        d["url"] = uri if uri.startswith("http") else f"http://{host}{uri}"
    return d


def info(d: dict) -> str:
    if d["type"] == "request":
        return f"{d['method']} {d['uri']} {d['version']}"
    return f"{d['version']} {d['status']} {d['reason']}"
