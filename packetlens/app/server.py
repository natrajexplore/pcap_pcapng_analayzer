"""HTTP server for the PacketLens app (standard library only).

Serves the single-page UI and a JSON API. Local by design: it binds to 127.0.0.1, rejects
requests whose Host header is not local (DNS rebinding) and requires a custom header on
every POST, which a browser cannot send cross-site without a CORS preflight this server
never grants.
"""
from __future__ import annotations

import io
import json
import mimetypes
import os
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__, live, sim
from ..analyzer import Analysis, analyze_file
from ..decode import dissect
from ..reader import CaptureFormatError, write_pcapng
from ..report import html
from ..report.html import THREE_JS, _json_default
from .library import Library, capture_view, summary

STATIC = Path(__file__).with_name("static")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]"}
MAX_UPLOAD = 200 * 1024 * 1024
LIVE_BUFFER = 50000


class State:
    def __init__(self, library: str | None):
        self.lib = Library(library)
        self.sims: dict[str, dict] = {}          # id -> {"pcap": bytes, "key": library cache key}
        self.live: dict[str, dict] = {}


def _dump(obj) -> bytes:
    return json.dumps(obj, default=_json_default, separators=(",", ":")).encode()


def make_handler(state: State):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"PacketLens/{__version__}"
        protocol_version = "HTTP/1.1"

        # ------------------------------------------------------------ utils --
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, _dump(obj), "application/json")

        def _error(self, code, msg):
            self._json({"error": msg}, code)

        def _local(self) -> bool:
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return host in LOCAL_HOSTS

        def _body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_UPLOAD:
                raise ValueError(f"upload larger than {MAX_UPLOAD // 2**20} MB")
            return self.rfile.read(n) if n > 0 else b""

        def log_message(self, fmt, *args):
            if os.environ.get("PACKETLENS_QUIET"):
                return
            print(f"[packetlens] {self.address_string()} {fmt % args}")

        # ------------------------------------------------------------ GET ----
        def do_GET(self):
            if not self._local():
                return self._error(403, "only local access is allowed")
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path in ("/", "/index.html"):
                    return self._static("index.html")
                if u.path.startswith("/static/"):
                    return self._static(u.path[len("/static/"):])
                if u.path == "/api/meta":
                    return self._json({"version": __version__, "library": str(state.lib.root) if state.lib.root else None})
                if u.path == "/api/library":
                    return self._json(state.lib.listing(analyze=q.get("analyze") == "1"))
                if u.path == "/api/capture":
                    key = q.get("id", "")
                    a = self._analysis(key)
                    return self._json({"id": key, **capture_view(a, state.lib.folder_path(key))})
                if u.path == "/api/report":
                    a = self._analysis(q.get("id", ""))
                    return self._send(200, html.render(a.to_dict(), "/static/three.min.js").encode(), "text/html; charset=utf-8")
                if u.path == "/api/sim/options":
                    return self._json({"traffic": sim.TRAFFIC,
                                       "faults": {k: {"label": v[0], "where": v[1], "traffic": sorted(v[2])}
                                                  for k, v in sim.FAULTS.items()}})
                if u.path == "/api/sim/pcap":
                    s = state.sims.get(q.get("id", ""))
                    if not s:
                        return self._error(404, "unknown simulation")
                    return self._send(200, s["pcap"], "application/vnd.tcpdump.pcap",
                                      {"Content-Disposition": f'attachment; filename="packetlens-sim-{q["id"][:8]}.pcapng"'})
                if u.path == "/api/live/interfaces":
                    return self._json({"interfaces": live.interfaces(), "platform": os.name})
                if u.path == "/api/live/stream":
                    return self._stream(q.get("id", ""))
                return self._error(404, "not found")
            except FileNotFoundError:
                return self._error(404, "capture not found")
            except (CaptureFormatError, ValueError) as exc:
                return self._error(400, str(exc))

        def _static(self, name: str):
            if name == "three.min.js":
                return self._send(200, THREE_JS.read_bytes(), "text/javascript; charset=utf-8")
            p = (STATIC / name).resolve()
            if STATIC.resolve() not in p.parents or not p.is_file():
                return self._error(404, "not found")
            ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            return self._send(200, p.read_bytes(), ctype)

        def _analysis(self, key: str) -> Analysis:
            return state.lib.get(key)          # cached simulations/uploads/live captures, or a library file

        # ------------------------------------------------------------ POST ---
        def do_POST(self):
            if not self._local():
                return self._error(403, "only local access is allowed")
            if self.headers.get("X-PacketLens") != "1":
                return self._error(403, "missing X-PacketLens header")
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path == "/api/sim":
                    return self._simulate(json.loads(self._body() or b"{}"))
                if u.path == "/api/upload":
                    return self._upload(q.get("name", "upload.pcapng"), self._body())
                if u.path == "/api/live/start":
                    return self._live_start(json.loads(self._body() or b"{}"))
                if u.path == "/api/live/stop":
                    return self._live_stop(q.get("id", ""))
                return self._error(404, "not found")
            except (ValueError, KeyError, TypeError) as exc:
                return self._error(400, str(exc))
            except CaptureFormatError as exc:
                return self._error(400, str(exc))

        def _simulate(self, cfg: dict):
            allowed = {"traffic", "fault", "where", "routers", "switch", "capture", "link_ms", "size_kb", "loss_rate",
                       "latency_ms", "mtu", "think_s", "seed"}
            cfg = {k: v for k, v in cfg.items() if k in allowed}
            cfg["size_kb"] = max(1, min(int(cfg.get("size_kb", 64)), 2048))
            t = time.time()
            res = sim.simulate(**cfg)
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "sim.pcapng")
                sim.write(res, p)
                data = Path(p).read_bytes()
            sid = uuid.uuid4().hex
            a = analyze_file(io.BytesIO(data), name=f"simulation-{sid[:8]}.pcapng")
            key = f"sim:{sid}"
            state.lib.put(key, a)
            state.sims[sid] = {"pcap": data}
            if len(state.sims) > 50:                            # keep memory bounded
                old = next(iter(state.sims))
                state.sims.pop(old)
                state.lib.cache.pop(f"sim:{old}", None)
            ids = {f.id for f in a.findings}
            detected = [f.id for f in a.findings if f.id in res["expected"]]
            return self._json({"id": sid, "key": key, "journey": res["journey"], "topology": res["topology"],
                               "config": res["config"], "notes": res["notes"], "expected": res["expected"],
                               "detected": detected, "verdict": ("detected" if detected else "missed") if res["expected"]
                               else ("clean" if not [f for f in a.findings if f.severity in ("critical", "high", "medium")]
                                     else "noisy"),
                               "fault_side": res["fault_side"], "visible_frames": res["visible_frames"],
                               "findings_all": sorted(ids), "seconds": round(time.time() - t, 3),
                               "analysis": capture_view(a)})

        def _upload(self, name: str, data: bytes):
            if not data:
                raise ValueError("empty upload")
            a = analyze_file(io.BytesIO(data), name=os.path.basename(name))
            key = f"upload:{uuid.uuid4().hex[:12]}:{os.path.basename(name)}"
            state.lib.put(key, a)
            return self._json({"id": key, **summary(a)})

        # ------------------------------------------------------------ live ---
        def _live_start(self, cfg: dict):
            lid = uuid.uuid4().hex[:12]
            sess = {"frames": [], "stop": threading.Event(), "error": None, "done": False, "started": time.time(),
                    "iface": cfg.get("interface") or "any"}
            state.live[lid] = sess

            def worker():
                try:
                    live.capture(sess["iface"], float(cfg.get("duration", 60)), None, 262144, cfg.get("host") or None,
                                 int(cfg["port"]) if cfg.get("port") else None,
                                 on_packet=lambda fr: len(sess["frames"]) < LIVE_BUFFER and sess["frames"].append(fr),
                                 stop=sess["stop"])
                except live.LiveCaptureError as exc:
                    sess["error"] = str(exc)
                except Exception as exc:  # noqa: BLE001 - surfaced to the UI
                    sess["error"] = f"capture failed: {exc!r}"
                finally:
                    sess["done"] = True
            threading.Thread(target=worker, daemon=True).start()
            time.sleep(0.3)
            if sess["error"]:
                return self._error(400, sess["error"])
            return self._json({"id": lid})

        def _stream(self, lid: str):
            sess = state.live.get(lid)
            if not sess:
                return self._error(404, "unknown live session")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            sent = 0
            try:
                while True:
                    frames = sess["frames"]
                    batch = []
                    for i in range(sent, len(frames)):
                        p = dissect(i + 1, frames[i])
                        batch.append({"no": i + 1, "t": round(frames[i].ts - sess["started"], 4), "src": p.src or p.eth_src,
                                      "dst": p.dst or p.eth_dst, "proto": p.protocol, "len": p.wirelen, "info": p.info[:120],
                                      "sport": p.sport, "dport": p.dport,
                                      "bad": bool(p.tcp and (p.tcp.rst or p.tcp.analysis))})
                    sent = len(frames)
                    if batch:
                        self.wfile.write(b"data: " + _dump({"packets": batch}) + b"\n\n")
                    if sess["error"] or sess["done"]:
                        self.wfile.write(b"event: end\ndata: " + _dump({"error": sess["error"], "packets": sent}) + b"\n\n")
                        break
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    time.sleep(0.25)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
            self.close_connection = True

        def _live_stop(self, lid: str):
            sess = state.live.get(lid)
            if not sess:
                return self._error(404, "unknown live session")
            sess["stop"].set()
            for _ in range(40):
                if sess["done"]:
                    break
                time.sleep(0.05)
            if not sess["frames"]:
                return self._json({"id": None, "packets": 0, "error": sess["error"]})
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "live.pcapng")
                write_pcapng(p, [(f.ts, f.data, f.linktype, f.wirelen) for f in sess["frames"]])
                data = Path(p).read_bytes()
            a = analyze_file(io.BytesIO(data), name=f"live-{lid}.pcapng")
            key = f"live:{lid}"
            state.lib.put(key, a)
            state.sims[lid] = {"pcap": data}
            return self._json({"id": key, "pcap": lid, **summary(a)})

    return Handler


def serve(library: str | None = None, host: str = "127.0.0.1", port: int = 8090, open_browser: bool = True) -> None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("the app only listens on the local machine")
    state = State(library)
    httpd = ThreadingHTTPServer((host, port), make_handler(state))
    httpd.daemon_threads = True
    url = f"http://{host}:{httpd.server_address[1]}/"
    print(f"PacketLens app on {url}  (library: {library or 'none'}; Ctrl+C to stop)")
    if open_browser:
        import webbrowser
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
