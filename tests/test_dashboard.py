"""Tests for the audit-log dashboard module."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from contextduty.dashboard import (
    DEFAULT_LOG,
    _aggregate,
    _build_demo_entries,
    _load_entries,
    serve,
)

# ---------------------------------------------------------------------------
# _build_demo_entries
# ---------------------------------------------------------------------------


def test_demo_entries_count():
    entries = _build_demo_entries()
    assert len(entries) >= 100


def test_demo_entries_have_required_keys():
    required = {"ts", "operation", "findings_count", "blocked", "detector_counts"}
    for entry in _build_demo_entries():
        assert required <= entry.keys()


def test_demo_entries_deterministic():
    a = _build_demo_entries()
    b = _build_demo_entries()
    # Same number of entries and same blocked state (timestamps use timedelta so may vary slightly)
    assert len(a) == len(b)
    assert [e["blocked"] for e in a] == [e["blocked"] for e in b]


# ---------------------------------------------------------------------------
# _load_entries
# ---------------------------------------------------------------------------


def test_load_entries_empty_file(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text("")
    assert _load_entries(log) == []


def test_load_entries_valid(tmp_path):
    log = tmp_path / "audit.jsonl"
    entry = {
        "ts": "2026-05-01T10:00:00Z",
        "operation": "scan",
        "findings_count": 2,
        "blocked": False,
        "detector_counts": {"aws_key": 1, "github_pat": 1},
    }
    log.write_text(json.dumps(entry) + "\n")
    loaded = _load_entries(log)
    assert len(loaded) == 1
    assert loaded[0]["operation"] == "scan"


def test_load_entries_skips_malformed(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text('{"ts":"2026-05-01"}\nnot-json\n{"ts":"2026-05-02"}\n')
    loaded = _load_entries(log)
    assert len(loaded) == 2


def test_load_entries_missing_file():
    result = _load_entries(Path("/nonexistent/audit.jsonl"))
    assert result == []


# ---------------------------------------------------------------------------
# _aggregate
# ---------------------------------------------------------------------------


def test_aggregate_empty():
    agg = _aggregate([])
    s = agg["summary"]
    assert s["total_scans"] == 0
    assert s["total_findings"] == 0
    assert s["total_blocked"] == 0
    assert agg["detector_totals"] == {}


def test_aggregate_counts():
    entries = [
        {
            "ts": "2026-05-01T10:00:00Z",
            "operation": "scan",
            "findings_count": 3,
            "blocked": True,
            "blocked_by": ["aws_key"],
            "detector_counts": {"aws_key": 2, "github_pat": 1},
        },
        {
            "ts": "2026-05-01T11:00:00Z",
            "operation": "redact",
            "findings_count": 1,
            "blocked": False,
            "detector_counts": {"openai_key": 1},
        },
    ]
    agg = _aggregate(entries)
    s = agg["summary"]
    assert s["total_scans"] == 2
    assert s["total_findings"] == 4
    assert s["total_blocked"] == 1
    assert agg["detector_totals"]["aws_key"] == 2
    assert agg["detector_totals"]["github_pat"] == 1
    assert agg["detector_totals"]["openai_key"] == 1


def test_aggregate_recent_capped():
    entries = [
        {
            "ts": f"2026-05-01T{i:02d}:00:00Z",
            "operation": "scan",
            "findings_count": 1,
            "blocked": False,
            "detector_counts": {},
        }
        for i in range(60)
    ]
    agg = _aggregate(entries)
    assert len(agg["recent"]) <= 50


# ---------------------------------------------------------------------------
# HTTP server integration
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _start_server(demo: bool = True, log: Path | None = None):
    port = _free_port()
    audit_log = log or DEFAULT_LOG
    t = threading.Thread(
        target=serve,
        kwargs={"audit_log": audit_log, "port": port, "demo": demo, "open_browser": False},
        daemon=True,
    )
    t.start()
    # wait for server to bind
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://localhost:{port}/", timeout=0.5)
            break
        except Exception:
            time.sleep(0.1)
    return port


def test_server_serves_html():
    port = _start_server(demo=True)
    resp = urllib.request.urlopen(f"http://localhost:{port}/", timeout=5)
    assert resp.status == 200
    html = resp.read().decode()
    assert "ContextDuty" in html


def test_server_api_data():
    port = _start_server(demo=True)
    resp = urllib.request.urlopen(f"http://localhost:{port}/api/data", timeout=5)
    assert resp.status == 200
    data = json.loads(resp.read())
    assert "summary" in data
    assert "detector_totals" in data
    assert "total_scans" in data["summary"]


def test_server_404():
    port = _start_server(demo=True)
    req = urllib.request.Request(f"http://localhost:{port}/notfound")
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 404


# ---------------------------------------------------------------------------
# New dashboard v2 features
# ---------------------------------------------------------------------------


def test_aggregate_detection_methods():
    entries = [
        {
            "ts": "2026-05-01T10:00:00Z",
            "operation": "scan",
            "target": "app.py",
            "findings_count": 5,
            "blocked": False,
            "detector_counts": {"email": 2, "nlp_person": 3},
        },
    ]
    agg = _aggregate(entries)
    assert agg["detection_methods"]["regex"] == 2
    assert agg["detection_methods"]["nlp"] == 3


def test_aggregate_target_totals():
    entries = [
        {
            "ts": "2026-05-01T10:00:00Z",
            "operation": "scan",
            "target": "config.py",
            "findings_count": 5,
            "blocked": False,
            "detector_counts": {"aws_key": 5},
        },
        {
            "ts": "2026-05-01T11:00:00Z",
            "operation": "scan",
            "target": "config.py",
            "findings_count": 3,
            "blocked": False,
            "detector_counts": {"email": 3},
        },
        {
            "ts": "2026-05-01T12:00:00Z",
            "operation": "scan",
            "target": "app.py",
            "findings_count": 1,
            "blocked": False,
            "detector_counts": {"email": 1},
        },
    ]
    agg = _aggregate(entries)
    assert agg["target_totals"]["config.py"] == 8
    assert agg["target_totals"]["app.py"] == 1
    # Sorted descending
    keys = list(agg["target_totals"].keys())
    assert keys[0] == "config.py"


def test_aggregate_target_totals_excludes_clean():
    entries = [
        {
            "ts": "2026-05-01T10:00:00Z",
            "operation": "scan",
            "target": "clean.py",
            "findings_count": 0,
            "blocked": False,
            "detector_counts": {},
        },
    ]
    agg = _aggregate(entries)
    assert "clean.py" not in agg["target_totals"]


def test_demo_entries_include_nlp_detectors():
    entries = _build_demo_entries()
    all_detectors = set()
    for e in entries:
        all_detectors.update(e.get("detector_counts", {}).keys())
    nlp_dets = {d for d in all_detectors if d.startswith("nlp_")}
    assert len(nlp_dets) > 0, "Demo data should include NLP detectors"


def test_server_api_data_has_new_fields():
    port = _start_server(demo=True)
    resp = urllib.request.urlopen(f"http://localhost:{port}/api/data", timeout=5)
    data = json.loads(resp.read())
    assert "detection_methods" in data
    assert "target_totals" in data
    assert "regex" in data["detection_methods"]
    assert "nlp" in data["detection_methods"]


def test_html_contains_new_sections():
    port = _start_server(demo=True)
    resp = urllib.request.urlopen(f"http://localhost:{port}/", timeout=5)
    html = resp.read().decode()
    assert "method-breakdown" in html
    assert "target-bars" in html
    assert "filter-input" in html
