"""Local audit-log dashboard for ContextDuty.

Starts a stdlib HTTP server on localhost that serves a single-page
audit dashboard — no external dependencies, works fully offline.

Usage:
    contextduty dashboard
    contextduty dashboard --audit-log /path/to/audit.jsonl --port 7042
    contextduty dashboard --demo          # synthetic data, no real log needed
"""

from __future__ import annotations

import json
import threading
import webbrowser
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

DEFAULT_PORT = 7042
DEFAULT_LOG = Path.home() / ".contextduty" / "audit.jsonl"

# ---------------------------------------------------------------------------
# Data layer
# ---------------------------------------------------------------------------

_DETECTOR_LABELS: dict[str, str] = {
    "email": "Email address",
    "phone": "Phone number",
    "api_key": "Generic API key",
    "bearer_token": "Bearer token",
    "aws_key": "AWS access key ID",
    "aws_secret": "AWS secret key",
    "gcp_service_account": "GCP service account",
    "google_oauth_token": "Google OAuth token",
    "github_pat": "GitHub PAT",
    "openai_key": "OpenAI key",
    "anthropic_key": "Anthropic key",
    "huggingface_token": "HuggingFace token",
    "slack_token": "Slack token",
    "stripe_webhook": "Stripe webhook secret",
    "sendgrid_key": "SendGrid key",
    "mailchimp_key": "Mailchimp key",
    "npm_token": "npm token",
    "twilio_sid": "Twilio SID",
    "azure_storage_key": "Azure storage key",
    "db_dsn": "Database DSN (with creds)",
    "ssh_private_key": "SSH private key",
    "pgp_private_key": "PGP private key",
    "private_key_pem": "PEM private key",
    "jwt": "JWT token",
    "env_secret": ".env secret variable",
}


def _load_entries(log_path: Path) -> list[dict[str, Any]]:
    if not log_path.exists():
        return []
    entries = []
    with log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries


def _aggregate(entries: list[dict[str, Any]]) -> dict[str, Any]:
    total_scans = len(entries)
    total_findings = sum(e.get("findings_count", 0) for e in entries)
    total_blocked = sum(1 for e in entries if e.get("blocked"))
    clean_scans = sum(1 for e in entries if e.get("findings_count", 0) == 0)

    detector_totals: dict[str, int] = {}
    for e in entries:
        for det, cnt in e.get("detector_counts", {}).items():
            detector_totals[det] = detector_totals.get(det, 0) + cnt
    detector_totals = dict(sorted(detector_totals.items(), key=lambda x: x[1], reverse=True))

    blocked_by_totals: dict[str, int] = {}
    for e in entries:
        for det in e.get("blocked_by", []):
            blocked_by_totals[det] = blocked_by_totals.get(det, 0) + 1

    # Daily buckets — last 30 days
    now = datetime.now(timezone.utc)
    daily: dict[str, int] = {}
    for i in range(29, -1, -1):
        day = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        daily[day] = 0
    for e in entries:
        ts = e.get("ts", "")
        day = ts[:10]
        if day in daily:
            daily[day] = daily.get(day, 0) + e.get("findings_count", 0)

    users: dict[str, int] = {}
    for e in entries:
        u = e.get("user", "unknown")
        users[u] = users.get(u, 0) + 1
    users = dict(sorted(users.items(), key=lambda x: x[1], reverse=True))

    operations: dict[str, int] = {}
    for e in entries:
        op = e.get("operation", "scan")
        operations[op] = operations.get(op, 0) + 1

    recent = sorted(entries, key=lambda e: e.get("ts", ""), reverse=True)[:50]

    detector_labels = {k: _DETECTOR_LABELS.get(k, k) for k in detector_totals}

    return {
        "summary": {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "total_blocked": total_blocked,
            "clean_scans": clean_scans,
            "unique_detectors": len(detector_totals),
            "block_rate_pct": round(100 * total_blocked / total_scans, 1) if total_scans else 0,
        },
        "detector_totals": detector_totals,
        "detector_labels": detector_labels,
        "blocked_by_totals": blocked_by_totals,
        "daily_findings": daily,
        "users": users,
        "operations": operations,
        "recent": recent,
        "generated_at": now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Demo / seed data
# ---------------------------------------------------------------------------

_DEMO_ENTRIES: list[dict[str, Any]] = []


def _build_demo_entries() -> list[dict[str, Any]]:
    """Return synthetic audit entries that tell a realistic startup story."""
    import random

    random.seed(42)
    now = datetime.now(timezone.utc)
    files = [
        "src/config/settings.py",
        ".env",
        "scripts/deploy.sh",
        "infra/terraform/main.tf",
        "notebooks/analysis.ipynb",
        "src/integrations/stripe.py",
        "tests/fixtures/sample_data.json",
        "docs/setup.md",
    ]
    users = ["priya", "alex", "sam", "jordan", "priya", "priya", "alex"]
    detectors_pool = [
        ("aws_key", 1),
        ("aws_secret", 1),
        ("email", 3),
        ("github_pat", 1),
        ("openai_key", 1),
        ("db_dsn", 2),
        ("stripe_webhook", 1),
        ("slack_token", 1),
        ("phone", 2),
        ("jwt", 1),
        ("ssh_private_key", 1),
        ("env_secret", 2),
        ("anthropic_key", 1),
        ("huggingface_token", 1),
    ]
    operations = ["scan", "scan", "scan", "redact", "scan", "scan", "redact"]

    entries = []
    for i in range(180):
        days_ago = random.randint(0, 29)
        hours_ago = random.randint(0, 23)
        ts = now - timedelta(days=days_ago, hours=hours_ago, minutes=random.randint(0, 59))

        # ~35% of scans find something
        if random.random() < 0.35:
            n_detectors = random.randint(1, 4)
            chosen = random.sample(detectors_pool, min(n_detectors, len(detectors_pool)))
            detector_counts = {d: c for d, c in chosen}
            findings_count = sum(detector_counts.values())
            # ~8% of scans that have findings are blocked
            blocked_by = [list(detector_counts.keys())[0]] if random.random() < 0.08 else []
            blocked = len(blocked_by) > 0
        else:
            detector_counts = {}
            findings_count = 0
            blocked = False
            blocked_by = []

        entries.append(
            {
                "ts": ts.isoformat(),
                "operation": random.choice(operations),
                "target": random.choice(files),
                "policy": "<default>",
                "findings_count": findings_count,
                "detector_counts": detector_counts,
                "blocked": blocked,
                "blocked_by": blocked_by,
                "hostname": "dev-laptop.local",
                "user": random.choice(users),
                "tool": random.choice(["cli", "cli", "mcp", "pre-commit"]),
            }
        )

    return sorted(entries, key=lambda e: e["ts"])


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContextDuty — Audit Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --heading: #f0f6fc;
    --blue: #388bfd; --green: #3fb950; --yellow: #d29922;
    --red: #f85149; --purple: #a371f7; --orange: #ffa657;
    --cyan: #39d353;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont,
    'Segoe UI', monospace; font-size: 14px; min-height: 100vh; }

  /* Header */
  .header { background: var(--surface); border-bottom: 1px solid var(--border);
    padding: 14px 24px; display: flex; align-items: center; justify-content: space-between;
    position: sticky; top: 0; z-index: 10; }
  .logo { display: flex; align-items: center; gap: 10px; }
  .logo-icon { width: 28px; height: 28px; background: var(--blue); border-radius: 6px;
    display: flex; align-items: center; justify-content: center; font-size: 16px; }
  .logo-text { font-size: 16px; font-weight: 600; color: var(--heading); }
  .logo-sub { font-size: 12px; color: var(--muted); margin-left: 4px; }
  .header-right { display: flex; align-items: center; gap: 16px; font-size: 12px; color: var(--muted); }
  .refresh-dot { width: 8px; height: 8px; background: var(--green); border-radius: 50%;
    display: inline-block; margin-right: 4px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .btn { background: var(--surface); border: 1px solid var(--border); color: var(--text);
    padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;
    text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
  .btn:hover { border-color: var(--blue); color: var(--blue); }

  /* Layout */
  .main { padding: 24px; max-width: 1400px; margin: 0 auto; }
  .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media (max-width: 900px) { .grid-4 { grid-template-columns: 1fr 1fr; }
    .grid-2 { grid-template-columns: 1fr; } }

  /* Cards */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .card-label { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); margin-bottom: 8px; }
  .card-value { font-size: 32px; font-weight: 700; color: var(--heading); line-height: 1; }
  .card-sub { font-size: 12px; color: var(--muted); margin-top: 6px; }
  .card-blue .card-value { color: var(--blue); }
  .card-yellow .card-value { color: var(--yellow); }
  .card-red .card-value { color: var(--red); }
  .card-green .card-value { color: var(--green); }

  /* Section headings */
  .section-head { font-size: 13px; font-weight: 600; color: var(--heading);
    margin-bottom: 16px; padding-bottom: 10px; border-bottom: 1px solid var(--border); }

  /* Detector bars */
  .det-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .det-name { font-size: 12px; color: var(--text); width: 180px; flex-shrink: 0;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .det-bar-wrap { flex: 1; background: var(--bg); border-radius: 4px; height: 8px; overflow: hidden; }
  .det-bar { height: 100%; border-radius: 4px; background: var(--blue); transition: width .4s ease; }
  .det-count { font-size: 12px; color: var(--muted); width: 40px; text-align: right; flex-shrink: 0; }

  /* SVG Timeline */
  .timeline-wrap { overflow: hidden; }
  svg.timeline { width: 100%; height: 160px; }
  .tl-label { font-size: 10px; fill: var(--muted); }

  /* Activity table */
  .tbl { width: 100%; border-collapse: collapse; font-size: 12px; }
  .tbl th { text-align: left; color: var(--muted); font-weight: 500;
    padding: 8px 12px; border-bottom: 1px solid var(--border);
    font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  .tbl td { padding: 9px 12px; border-bottom: 1px solid rgba(48,54,61,.5);
    vertical-align: middle; font-family: 'SF Mono', 'Fira Code', monospace; }
  .tbl tr:last-child td { border-bottom: none; }
  .tbl tr:hover td { background: rgba(56,139,253,.05); }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px;
    font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
  .badge-red { background: rgba(248,81,73,.15); color: var(--red); }
  .badge-yellow { background: rgba(210,153,34,.15); color: var(--yellow); }
  .badge-green { background: rgba(63,185,80,.15); color: var(--green); }
  .badge-blue { background: rgba(56,139,253,.15); color: var(--blue); }
  .badge-purple { background: rgba(163,113,247,.15); color: var(--purple); }
  .chip { display: inline-block; padding: 2px 6px; border-radius: 3px;
    font-size: 10px; background: rgba(56,139,253,.1); color: var(--blue); margin: 1px; }

  /* Donut */
  .donut-wrap { display: flex; align-items: center; gap: 20px; }
  svg.donut { width: 100px; height: 100px; flex-shrink: 0; }
  .donut-legend { flex: 1; }
  .legend-row { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

  /* Empty state */
  .empty { text-align: center; padding: 48px 24px; color: var(--muted); }
  .empty-icon { font-size: 40px; margin-bottom: 12px; }
  .empty code { background: var(--bg); border: 1px solid var(--border);
    padding: 2px 6px; border-radius: 4px; font-size: 12px; color: var(--blue); }

  /* Demo banner */
  .demo-banner { background: rgba(163,113,247,.1); border: 1px solid rgba(163,113,247,.3);
    border-radius: 6px; padding: 10px 16px; margin-bottom: 20px;
    font-size: 12px; color: var(--purple); display: flex; align-items: center; gap: 8px; }

  /* Scrollable table */
  .table-scroll { overflow-x: auto; }
</style>
</head>
<body>

<header class="header">
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <span class="logo-text">ContextDuty</span>
      <span class="logo-sub">Audit Dashboard</span>
    </div>
  </div>
  <div class="header-right">
    <span id="refresh-status"><span class="refresh-dot"></span>Live</span>
    <span id="last-updated">—</span>
    <a href="/api/data" class="btn" target="_blank">⬇ JSON</a>
    <button class="btn" onclick="exportCsv()">⬇ CSV</button>
  </div>
</header>

<main class="main">
  <div id="demo-banner" style="display:none" class="demo-banner">
    ✦ Demo mode — showing synthetic data. Run real scans with
    <code>contextduty scan &lt;file&gt; --audit-log ~/.contextduty/audit.jsonl</code>
    to populate with live data.
  </div>

  <!-- Summary cards -->
  <div class="grid-4" id="cards">
    <div class="card card-blue"><div class="card-label">Total scans</div>
      <div class="card-value" id="c-scans">—</div>
      <div class="card-sub" id="c-ops">—</div></div>
    <div class="card card-yellow"><div class="card-label">Total findings</div>
      <div class="card-value" id="c-findings">—</div>
      <div class="card-sub" id="c-detectors">—</div></div>
    <div class="card card-red"><div class="card-label">Commits blocked</div>
      <div class="card-value" id="c-blocked">—</div>
      <div class="card-sub" id="c-blockrate">—</div></div>
    <div class="card card-green"><div class="card-label">Clean scans</div>
      <div class="card-value" id="c-clean">—</div>
      <div class="card-sub" id="c-cleanpct">—</div></div>
  </div>

  <div class="grid-2">
    <!-- Detector breakdown -->
    <div class="card">
      <div class="section-head">Findings by detector</div>
      <div id="detector-bars"><div class="empty"><div class="empty-icon">📊</div>No data yet</div></div>
    </div>
    <!-- Timeline -->
    <div class="card">
      <div class="section-head">Findings — last 30 days</div>
      <div class="timeline-wrap" id="timeline-wrap">
        <div class="empty"><div class="empty-icon">📈</div>No data yet</div>
      </div>
    </div>
  </div>

  <div class="grid-2">
    <!-- Operations / tool breakdown -->
    <div class="card">
      <div class="section-head">Operations by source</div>
      <div id="ops-chart" class="donut-wrap">
        <div class="empty" style="flex:1"><div class="empty-icon">🔄</div>No data yet</div>
      </div>
    </div>
    <!-- Top users -->
    <div class="card">
      <div class="section-head">Scans by developer</div>
      <div id="user-bars"><div class="empty"><div class="empty-icon">👤</div>No data yet</div></div>
    </div>
  </div>

  <!-- Activity feed -->
  <div class="card">
    <div class="section-head" style="display:flex;justify-content:space-between">
      <span>Recent activity</span>
      <span id="activity-count" style="font-weight:400;color:var(--muted)"></span>
    </div>
    <div class="table-scroll">
      <table class="tbl">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>File / Target</th>
            <th>Operation</th>
            <th>Findings</th>
            <th>Detectors fired</th>
            <th>Status</th>
            <th>User</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody id="activity-body">
          <tr><td colspan="8" class="empty">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</main>

<script>
const COLORS = ['#388bfd','#3fb950','#d29922','#f85149','#a371f7',
                '#ffa657','#39d353','#79c0ff','#ff7b72','#ffa198'];
let _data = null;
let _countdown = 30;
let _timer = null;

async function fetchData() {
  try {
    const r = await fetch('/api/data');
    _data = await r.json();
    render(_data);
    resetCountdown();
  } catch(e) {
    document.getElementById('last-updated').textContent = 'Error fetching data';
  }
}

function resetCountdown() {
  clearInterval(_timer);
  _countdown = 30;
  _timer = setInterval(() => {
    _countdown--;
    document.getElementById('refresh-status').innerHTML =
      `<span class="refresh-dot"></span>Refreshing in ${_countdown}s`;
    if (_countdown <= 0) fetchData();
  }, 1000);
}

function fmt(n) { return n >= 1000 ? (n/1000).toFixed(1)+'k' : n; }

function render(d) {
  const s = d.summary;
  // Cards
  document.getElementById('c-scans').textContent = fmt(s.total_scans);
  document.getElementById('c-ops').textContent =
    Object.entries(d.operations||{}).map(([k,v])=>`${v} ${k}`).join(' · ') || '—';
  document.getElementById('c-findings').textContent = fmt(s.total_findings);
  document.getElementById('c-detectors').textContent =
    `${s.unique_detectors} detector type${s.unique_detectors!==1?'s':''} triggered`;
  document.getElementById('c-blocked').textContent = s.total_blocked;
  document.getElementById('c-blockrate').textContent =
    s.total_scans ? `${s.block_rate_pct}% block rate` : '—';
  document.getElementById('c-clean').textContent = fmt(s.clean_scans);
  const cleanPct = s.total_scans ? Math.round(100*s.clean_scans/s.total_scans) : 0;
  document.getElementById('c-cleanpct').textContent =
    s.total_scans ? `${cleanPct}% of all scans` : '—';

  // Last updated
  const gen = new Date(d.generated_at);
  document.getElementById('last-updated').textContent =
    'Updated ' + gen.toLocaleTimeString();

  // Demo banner
  if (d.demo) document.getElementById('demo-banner').style.display = 'flex';

  renderDetectorBars(d.detector_totals, d.detector_labels);
  renderTimeline(d.daily_findings);
  renderOps(d.operations || {});
  renderUserBars(d.users || {});
  renderActivity(d.recent || []);
}

function renderDetectorBars(totals, labels) {
  const el = document.getElementById('detector-bars');
  const entries = Object.entries(totals);
  if (!entries.length) { el.innerHTML = '<div class="empty"><div class="empty-icon">📊</div>No findings yet</div>'; return; }
  const max = entries[0][1];
  el.innerHTML = entries.slice(0,15).map(([k,v], i) => `
    <div class="det-row">
      <div class="det-name" title="${labels[k]||k}">${labels[k]||k}</div>
      <div class="det-bar-wrap">
        <div class="det-bar" style="width:${Math.round(100*v/max)}%;background:${COLORS[i%COLORS.length]}"></div>
      </div>
      <div class="det-count">${v}</div>
    </div>`).join('');
}

function renderTimeline(daily) {
  const el = document.getElementById('timeline-wrap');
  const days = Object.keys(daily).sort();
  const vals = days.map(d => daily[d]);
  const maxV = Math.max(...vals, 1);

  const W = 500, H = 140, PL = 4, PR = 4, PT = 10, PB = 30;
  const w = W - PL - PR, h = H - PT - PB;
  const xs = days.map((_, i) => PL + (i / (days.length - 1)) * w);
  const ys = vals.map(v => PT + h - (v / maxV) * h);

  const path = xs.map((x, i) => (i === 0 ? 'M' : 'L') + `${x},${ys[i]}`).join(' ');
  const area = `${path} L${xs[xs.length-1]},${PT+h} L${xs[0]},${PT+h} Z`;

  // x-axis labels — every 7 days
  const xlabels = days
    .map((d, i) => i % 7 === 0 ? `<text x="${xs[i]}" y="${H-4}" class="tl-label" text-anchor="middle">${d.slice(5)}</text>` : '')
    .join('');

  el.innerHTML = `<svg class="timeline" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
    <defs>
      <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#388bfd" stop-opacity=".25"/>
        <stop offset="100%" stop-color="#388bfd" stop-opacity="0"/>
      </linearGradient>
    </defs>
    <path d="${area}" fill="url(#grad)"/>
    <path d="${path}" fill="none" stroke="#388bfd" stroke-width="2" stroke-linejoin="round"/>
    <line x1="${PL}" y1="${PT+h}" x2="${W-PR}" y2="${PT+h}" stroke="#30363d" stroke-width="1"/>
    ${xlabels}
    <text x="${PL}" y="${PT+4}" class="tl-label">${maxV}</text>
  </svg>`;
}

function renderOps(ops) {
  const el = document.getElementById('ops-chart');
  const entries = Object.entries(ops);
  if (!entries.length) return;
  const total = entries.reduce((a,[,v])=>a+v,0);
  const colors = ['#388bfd','#3fb950','#d29922','#f85149','#a371f7'];

  // SVG donut
  const R = 36, r = 22, cx = 50, cy = 50;
  let angle = -Math.PI/2;
  let paths = '';
  entries.forEach(([,v], i) => {
    const sweep = (v/total)*2*Math.PI;
    const x1=cx+R*Math.cos(angle), y1=cy+R*Math.sin(angle);
    const x2=cx+R*Math.cos(angle+sweep), y2=cy+R*Math.sin(angle+sweep);
    const x3=cx+r*Math.cos(angle+sweep), y3=cy+r*Math.sin(angle+sweep);
    const x4=cx+r*Math.cos(angle), y4=cy+r*Math.sin(angle);
    const large = sweep > Math.PI ? 1 : 0;
    paths += `<path d="M${x1},${y1} A${R},${R} 0 ${large} 1 ${x2},${y2}
      L${x3},${y3} A${r},${r} 0 ${large} 0 ${x4},${y4} Z"
      fill="${colors[i%colors.length]}" stroke="var(--surface)" stroke-width="2"/>`;
    angle += sweep;
  });

  const legend = entries.map(([k,v],i)=>`
    <div class="legend-row">
      <div class="legend-dot" style="background:${colors[i%colors.length]}"></div>
      <span>${k}</span>
      <span style="margin-left:auto;color:var(--muted)">${v} (${Math.round(100*v/total)}%)</span>
    </div>`).join('');

  el.innerHTML = `
    <svg class="donut" viewBox="0 0 100 100">
      ${paths}
      <text x="50" y="50" text-anchor="middle" dominant-baseline="middle"
        fill="var(--heading)" font-size="14" font-weight="700">${total}</text>
      <text x="50" y="62" text-anchor="middle" fill="var(--muted)" font-size="8">total</text>
    </svg>
    <div class="donut-legend">${legend}</div>`;
}

function renderUserBars(users) {
  const el = document.getElementById('user-bars');
  const entries = Object.entries(users);
  if (!entries.length) return;
  const max = entries[0][1];
  el.innerHTML = entries.slice(0,8).map(([k,v],i)=>`
    <div class="det-row">
      <div class="det-name">${k}</div>
      <div class="det-bar-wrap">
        <div class="det-bar" style="width:${Math.round(100*v/max)}%;background:${COLORS[(i+3)%COLORS.length]}"></div>
      </div>
      <div class="det-count">${v}</div>
    </div>`).join('');
}

function renderActivity(rows) {
  const tbody = document.getElementById('activity-body');
  document.getElementById('activity-count').textContent =
    rows.length ? `last ${rows.length} entries` : '';
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">
      <div class="empty-icon">🔍</div>
      No activity yet.<br>
      Run: <code>contextduty scan &lt;file&gt; --audit-log ~/.contextduty/audit.jsonl</code>
    </td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(e => {
    const ts = new Date(e.ts);
    const tsStr = ts.toLocaleString(undefined, {month:'short',day:'numeric',
      hour:'2-digit',minute:'2-digit'});
    const target = e.target || '—';
    const short = target.length > 35 ? '…'+target.slice(-34) : target;
    const opBadge = e.operation === 'redact'
      ? `<span class="badge badge-purple">redact</span>`
      : e.operation === 'pre-commit'
      ? `<span class="badge badge-blue">hook</span>`
      : `<span class="badge badge-blue">scan</span>`;
    const findBadge = e.findings_count > 0
      ? `<span style="color:var(--yellow);font-weight:600">${e.findings_count}</span>`
      : `<span style="color:var(--muted)">0</span>`;
    const chips = Object.keys(e.detector_counts||{}).slice(0,4)
      .map(d=>`<span class="chip">${d}</span>`).join('');
    const more = Object.keys(e.detector_counts||{}).length > 4
      ? `<span class="chip" style="color:var(--muted)">+${Object.keys(e.detector_counts).length-4}</span>` : '';
    const status = e.blocked
      ? `<span class="badge badge-red">BLOCKED</span>`
      : e.findings_count > 0
      ? `<span class="badge badge-yellow">WARN</span>`
      : `<span class="badge badge-green">CLEAN</span>`;
    const tool = e.tool || 'cli';
    const toolBadge = tool === 'mcp'
      ? `<span class="badge badge-purple">mcp</span>`
      : tool === 'pre-commit'
      ? `<span class="badge badge-blue">hook</span>`
      : `<span style="color:var(--muted)">${tool}</span>`;
    return `<tr>
      <td style="color:var(--muted);white-space:nowrap">${tsStr}</td>
      <td title="${target}" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${short}</td>
      <td>${opBadge}</td>
      <td>${findBadge}</td>
      <td>${chips}${more}</td>
      <td>${status}</td>
      <td style="color:var(--muted)">${e.user||'—'}</td>
      <td>${toolBadge}</td>
    </tr>`;
  }).join('');
}

function exportCsv() {
  if (!_data) return;
  const rows = _data.recent || [];
  const header = ['timestamp','target','operation','findings_count','detectors','blocked','blocked_by','user','tool'];
  const csv = [header.join(','), ...rows.map(e=>[
    e.ts, `"${(e.target||'').replace(/"/g,'""')}"`, e.operation,
    e.findings_count, `"${Object.keys(e.detector_counts||{}).join(';')}"`,
    e.blocked, `"${(e.blocked_by||[]).join(';')}"`, e.user||'', e.tool||''
  ].join(','))].join('\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = `contextduty-audit-${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
}

fetchData();
</script>
</body>
</html>"""


class _Handler(BaseHTTPRequestHandler):
    audit_log: Path = DEFAULT_LOG
    demo_mode: bool = False

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        pass  # suppress stdlib access log

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/" or self.path == "/index.html":
            self._serve_html()
        elif self.path == "/api/data":
            self._serve_data()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_html(self) -> None:
        body = _HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _serve_data(self) -> None:
        if self.demo_mode:
            global _DEMO_ENTRIES
            if not _DEMO_ENTRIES:
                _DEMO_ENTRIES = _build_demo_entries()
            entries = _DEMO_ENTRIES
            is_demo = True
        else:
            entries = _load_entries(self.audit_log)
            is_demo = False

        data = _aggregate(entries)
        data["demo"] = is_demo
        data["log_path"] = str(self.audit_log)

        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


def serve(
    audit_log: Path = DEFAULT_LOG,
    port: int = DEFAULT_PORT,
    demo: bool = False,
    open_browser: bool = True,
) -> None:
    """Start the dashboard server and optionally open the browser."""

    class Handler(_Handler):
        pass

    Handler.audit_log = audit_log
    Handler.demo_mode = demo

    server = HTTPServer(("127.0.0.1", port), Handler)
    url = f"http://localhost:{port}"

    print("\n  ContextDuty Audit Dashboard")
    print("  ─────────────────────────────")
    if demo:
        print("  Mode    : demo (synthetic data)")
    else:
        print(f"  Log     : {audit_log}")
    print(f"  URL     : {url}")
    print("  Stop    : Ctrl+C\n")

    if open_browser:
        threading.Timer(0.3, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Dashboard stopped.")
        server.shutdown()
