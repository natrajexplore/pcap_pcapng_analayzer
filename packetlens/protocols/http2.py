"""HTTP/2 (RFC 9113) frame parser.

Frame headers, SETTINGS, RST_STREAM, GOAWAY and WINDOW_UPDATE are decoded with the
standard library. HEADERS / CONTINUATION blocks are decoded when the optional
``hpack`` package is installed (HPACK is stateful, so one decoder is kept per
connection direction).
"""
from __future__ import annotations

import struct

try:
    import hpack
    HAVE_HPACK = True
except ImportError:  # pragma: no cover
    HAVE_HPACK = False

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
TYPES = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
         6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
ERRORS = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR", 4: "SETTINGS_TIMEOUT",
          5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM", 8: "CANCEL", 9: "COMPRESSION_ERROR",
          10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM", 12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
SETTINGS = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS", 4: "INITIAL_WINDOW_SIZE",
            5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE", 8: "ENABLE_CONNECT_PROTOCOL"}


class HeaderDecoder:
    def __init__(self):
        self._dec = hpack.Decoder() if HAVE_HPACK else None
        self._pending = b""
        self.broken = False

    def block(self, data: bytes, end_headers: bool) -> list | None:
        if self._dec is None or self.broken:
            return None
        self._pending += data
        if not end_headers:
            return None
        blk, self._pending = self._pending, b""
        try:
            return [(k.decode("latin-1") if isinstance(k, bytes) else k, v.decode("latin-1") if isinstance(v, bytes) else v)
                    for k, v in self._dec.decode(blk)]
        except Exception:
            self.broken = True      # lost HPACK state (capture started mid-connection)
            return None


def parse_frame(frame: bytes, decoder: HeaderDecoder | None = None) -> dict:
    ln = int.from_bytes(frame[:3], "big")
    ftype, flags = frame[3], frame[4]
    stream = struct.unpack("!I", frame[5:9])[0] & 0x7FFFFFFF
    body = frame[9:9 + ln]
    f: dict = {"type": TYPES.get(ftype, f"0x{ftype:02x}"), "stream": stream, "flags": flags, "length": ln}
    if ftype in (0, 1) and flags & 0x08 and body:          # PADDED
        body = body[1:len(body) - body[0]]
    if ftype == 1:
        f["end_stream"] = bool(flags & 0x01)
        if flags & 0x20:                                   # PRIORITY
            body = body[5:]
        if decoder is not None:
            f["headers"] = decoder.block(body, bool(flags & 0x04))
    elif ftype == 9 and decoder is not None:
        f["headers"] = decoder.block(body, bool(flags & 0x04))
    elif ftype == 0:
        f["end_stream"] = bool(flags & 0x01)
    elif ftype == 3 and len(body) >= 4:
        code = struct.unpack("!I", body[:4])[0]
        f["error"] = ERRORS.get(code, f"0x{code:x}")
    elif ftype == 4:
        f["ack"] = bool(flags & 0x01)
        f["settings"] = {SETTINGS.get(k, str(k)): v for k, v in
                         (struct.unpack("!HI", body[i:i + 6]) for i in range(0, len(body) - 5, 6))}
    elif ftype == 7 and len(body) >= 8:
        last, code = struct.unpack("!II", body[:8])
        f.update(last_stream=last & 0x7FFFFFFF, error=ERRORS.get(code, f"0x{code:x}"),
                 debug=body[8:200].decode("latin-1", "replace"))
    elif ftype == 8 and len(body) >= 4:
        f["increment"] = struct.unpack("!I", body[:4])[0] & 0x7FFFFFFF
    return f


def info(frames: list[dict]) -> str:
    parts = []
    for f in frames[:6]:
        s = f["type"]
        h = dict(f.get("headers") or [])
        if ":method" in h:
            s += f" {h[':method']} {h.get(':path', '')}"
        elif ":status" in h:
            s += f" {h[':status']}"
        if f.get("error"):
            s += f" {f['error']}"
        parts.append(f"{s}[{f['stream']}]")
    return "HTTP/2 " + ", ".join(parts) + (" …" if len(frames) > 6 else "")
