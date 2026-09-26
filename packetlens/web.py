"""Minimal local web UI: drag-and-drop a capture, get the interactive report.

Standard library only. Binds to 127.0.0.1 by default; captures are analyzed
in memory and never written to disk.
"""
from __future__ import annotations

import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .analyzer import analyze_file
from .reader import CaptureFormatError
from .report import html

UPLOAD_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>PacketLens</title>
<style>
:root{color-scheme:light;--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink-2:#52514e;--border:rgba(11,11,11,.14);--accent:#2a78d6}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink-2:#c3c2b7;--border:rgba(255,255,255,.14);--accent:#3987e5}}
:root[data-theme="dark"]{color-scheme:dark;--page:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink-2:#c3c2b7;--border:rgba(255,255,255,.14);--accent:#3987e5}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:720px;margin:10vh auto;padding:0 16px}
h1{font-size:26px;margin:0 0 6px}p{color:var(--ink-2)}
#drop{border:2px dashed var(--border);border-radius:14px;padding:48px 16px;text-align:center;background:var(--surface);cursor:pointer}
#drop.over{border-color:var(--accent)}
#status{margin-top:14px;min-height:1.5em}
</style></head><body><main>
<h1>PacketLens</h1>
<p>Drop a <b>.pcap</b> or <b>.pcapng</b> capture. It is analyzed locally for TCP, UDP, DNS, DHCP, HTTP/URLs, TLS, ICMP, ARP, STP, BGP, OSPF, EIGRP and RIP issues, with correlated root causes, per-perspective explanations and remediation.</p>
<label id="drop">Drop capture here or click to choose<input type="file" id="file" accept=".pcap,.pcapng,.cap" hidden></label>
<p style="font-size:13px">Optional TLS key log (SSLKEYLOGFILE) to decrypt HTTPS: <input type="file" id="keylog" accept=".log,.txt,.keys,*/*"></p>
<div id="status"></div>
<p style="font-size:12px">v__VERSION__ · Nothing leaves this machine.</p>
</main><script>
const drop=document.getElementById('drop'), st=document.getElementById('status'), inp=document.getElementById('file');
async function send(f){ st.textContent='Analyzing '+f.name+' ('+(f.size/1e6).toFixed(1)+' MB)…';
  const kf=document.getElementById('keylog').files[0]; const kb=kf?new Uint8Array(await kf.arrayBuffer()):new Uint8Array(0);
  try{ const r=await fetch('/analyze?name='+encodeURIComponent(f.name),{method:'POST',body:new Blob([kb,f]),
      headers:{'Content-Type':'application/octet-stream','X-Keylog-Length':String(kb.length)}});
    const t=await r.text(); if(!r.ok){ st.textContent='Error: '+t; return; }
    document.open(); document.write(t); document.close(); }catch(e){ st.textContent='Error: '+e; } }
inp.onchange=()=>inp.files[0]&&send(inp.files[0]);
['dragenter','dragover'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.add('over');}));
['dragleave','drop'].forEach(e=>drop.addEventListener(e,ev=>{ev.preventDefault();drop.classList.remove('over');}));
drop.addEventListener('drop',ev=>{ const f=ev.dataTransfer.files[0]; if(f) send(f); });
</script></body></html>"""


def make_handler(max_mb: int):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"PacketLens/{__version__}"

        def _send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8"):
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._send(200, UPLOAD_PAGE.replace("__VERSION__", __version__))
            if self.path == "/health":
                return self._send(200, "ok", "text/plain")
            self._send(404, "not found", "text/plain")

        def do_POST(self):
            if not self.path.startswith("/analyze"):
                return self._send(404, "not found", "text/plain")
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return self._send(400, "empty upload", "text/plain")
            if length > max_mb * 1024 * 1024:
                return self._send(413, f"capture larger than {max_mb} MB", "text/plain")
            raw = self.rfile.read(length)
            name = "upload.pcapng"
            if "name=" in self.path:
                from urllib.parse import parse_qs, urlparse
                name = parse_qs(urlparse(self.path).query).get("name", [name])[0]
            try:
                klen = int(self.headers.get("X-Keylog-Length") or 0)
            except ValueError:
                klen = 0
            klen = max(0, min(klen, len(raw)))
            keylog, raw = raw[:klen].decode("utf-8", "replace"), raw[klen:]
            try:
                a = analyze_file(io.BytesIO(raw), keylog_text=keylog or None, name=name)
            except CaptureFormatError as exc:
                return self._send(400, str(exc), "text/plain")
            self._send(200, html.render(a.to_dict()))

        def log_message(self, fmt, *args):  # quieter default logging
            print(f"[packetlens] {self.address_string()} {fmt % args}")
    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080, max_mb: int = 200) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(max_mb))
    print(f"PacketLens web UI on http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
