"""Self-hostable team collector — ingests endpoint metadata and serves the fleet dashboard.

Run inside the organisation's own network:

    contextduty team serve --token <shared-secret>

Endpoints push metadata (never content) to ``/api/ingest``; the browser view
at ``/`` shows fleet coverage, prevention metrics, and tamper events. All data
stays in this instance — single-tenant by design.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .aggregate import aggregate_fleet
from .model import VALID_EVENTS, sanitize_event

DEFAULT_PORT = 7043
DEFAULT_STORE = Path.home() / ".contextduty" / "fleet.jsonl"


def _load_events(store: Path) -> list[dict[str, Any]]:
    if not store.exists():
        return []
    out: list[dict[str, Any]] = []
    with store.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return out


def _append_event(store: Path, event: dict[str, Any]) -> None:
    store.parent.mkdir(parents=True, exist_ok=True)
    with store.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")


_HTML = """<!doctype html><html><head><meta charset=utf-8>
<title>ContextDuty — Fleet</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark}
body{margin:0;background:#0f1117;color:#e6e6e6;font:14px/1.5 system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#8b8f9a;margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:#181b24;border:1px solid #262a36;border-radius:10px;padding:14px}
.card .n{font-size:26px;font-weight:700}.card .l{color:#8b8f9a;font-size:12px}
.g{color:#4ade80}.r{color:#f87171}.y{color:#fbbf24}
table{width:100%;border-collapse:collapse;margin-bottom:24px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232735;font-size:13px}
th{color:#8b8f9a;font-weight:600}
.pill{padding:2px 8px;border-radius:20px;font-size:11px}
.enf{background:#14351f;color:#4ade80}.dark{background:#3a1a1a;color:#f87171}
.tag{display:inline-block;background:#232735;border-radius:5px;padding:1px 6px;margin:1px;font-size:11px}
h2{font-size:15px;margin:24px 0 8px;color:#c9cdd6}
.mono{font-family:ui-monospace,monospace;color:#9aa0ac}
</style></head><body><div class=wrap>
<h1>🛡️ ContextDuty — Fleet</h1><p class=sub id=gen>loading…</p>
<div class=cards id=cards></div>
<h2>Endpoints</h2><table id=eps><thead><tr><th>Host</th><th>User</th><th>Surfaces</th><th>Last seen</th><th>Status</th></tr></thead><tbody></tbody></table>
<h2>⚠️ Tamper / bypass events</h2><table id=tamper><thead><tr><th>When</th><th>User</th><th>Repo</th><th>Event</th><th>Detail</th></tr></thead><tbody></tbody></table>
<h2>Top detectors (fleet)</h2><div id=dets></div>
</div><script>
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
fetch('/api/fleet').then(r=>r.json()).then(d=>{
 const s=d.summary;
 document.getElementById('gen').textContent='generated '+d.generated_at;
 document.getElementById('cards').innerHTML=[
  ['Coverage',s.coverage_pct+'%',s.endpoints_dark?'y':'g'],
  ['Endpoints enforcing',s.endpoints_enforcing+' / '+s.endpoints_total,'g'],
  ['Dark endpoints',s.endpoints_dark,s.endpoints_dark?'r':'g'],
  ['Leaks prevented',s.leaks_prevented,'g'],
  ['Tamper events',s.tamper_events,s.tamper_events?'r':'g'],
  ['Policy variants',s.policy_variants,'y'],
 ].map(c=>`<div class=card><div class="n ${c[2]}">${esc(c[1])}</div><div class=l>${c[0]}</div></div>`).join('');
 document.querySelector('#eps tbody').innerHTML=d.endpoints.map(e=>{
  const su=Object.entries(e.surfaces||{}).filter(x=>x[1]).map(x=>`<span class=tag>${esc(x[0])}</span>`).join('');
  const cls=e.status==='dark'?'dark':'enf';
  return `<tr><td class=mono>${esc(e.host)}</td><td>${esc(e.user)}</td><td>${su}</td><td class=mono>${esc((e.last_seen||'').slice(0,16))}</td><td><span class="pill ${cls}">${esc(e.status)}</span></td></tr>`;
 }).join('');
 document.querySelector('#tamper tbody').innerHTML=(d.tamper_feed||[]).map(t=>
  `<tr><td class=mono>${esc((t.ts||'').slice(0,16))}</td><td>${esc(t.user)}</td><td>${esc(t.repo)}</td><td><span class="pill dark">${esc(t.event)}</span></td><td class=mono>${esc(t.detail)}</td></tr>`
 ).join('')||'<tr><td colspan=5 style="color:#4ade80">No tamper events 🎉</td></tr>';
 document.getElementById('dets').innerHTML=Object.entries(d.detector_totals||{}).map(([k,v])=>`<span class=tag>${esc(k)} · ${v}</span>`).join(' ');
});
</script></body></html>"""


def make_handler(store: Path, token: str):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _json(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/" or self.path.startswith("/index"):
                body = _HTML.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/api/fleet":
                self._json(200, aggregate_fleet(_load_events(store)))
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/api/ingest":
                self._json(404, {"error": "not found"})
                return
            if token and self.headers.get("Authorization") != f"Bearer {token}":
                self._json(401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                raw = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, json.JSONDecodeError):
                self._json(400, {"error": "invalid json"})
                return
            events = raw if isinstance(raw, list) else [raw]
            accepted = 0
            for ev in events:
                if not isinstance(ev, dict) or ev.get("event") not in VALID_EVENTS:
                    continue
                clean = sanitize_event(ev)  # strips anything that isn't metadata
                clean.setdefault("ts", datetime.now(timezone.utc).isoformat())
                _append_event(store, clean)
                accepted += 1
            self._json(200, {"accepted": accepted})

    return _Handler


def serve(
    *,
    port: int = DEFAULT_PORT,
    store: Path | None = None,
    token: str | None = None,
    demo: bool = False,
    open_browser: bool = True,
) -> None:
    """Start the team collector + fleet dashboard."""
    store = store or DEFAULT_STORE
    token = token or os.environ.get("CONTEXTDUTY_TEAM_TOKEN", "")
    if demo:
        from .demo import build_demo_fleet

        store = Path.home() / ".contextduty" / "fleet-demo.jsonl"
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(
            "\n".join(json.dumps(e) for e in build_demo_fleet()) + "\n", encoding="utf-8"
        )

    handler = make_handler(store, token)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    url = f"http://127.0.0.1:{port}"
    print(f"ContextDuty team collector → {url}")
    print(f"  store: {store}")
    print(f"  ingest: POST {url}/api/ingest  ({'token required' if token else 'no token (dev)'})")
    if demo:
        print("  mode: DEMO (synthetic fleet)")
    if open_browser and not demo:
        pass
    if open_browser:
        import threading
        import webbrowser

        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
