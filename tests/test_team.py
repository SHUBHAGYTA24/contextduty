"""Tests for the team layer — the privacy contract and fleet aggregation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from contextduty.team.aggregate import aggregate_fleet
from contextduty.team.demo import build_demo_fleet
from contextduty.team.model import is_content_free, sanitize_event

# ---------------------------------------------------------------------------
# The privacy contract — metadata only, never content
# ---------------------------------------------------------------------------


def test_sanitize_strips_content_fields():
    raw = {
        "event": "block",
        "host": "laptop-1",
        "detector_counts": {"aws_key": 2},
        # These must be dropped — they are content, not metadata:
        "matched_value": "AKIA1234567890ABCDEF",
        "file_content": "secret stuff",
        "prompt": "my password is hunter2",
    }
    clean = sanitize_event(raw)
    assert "matched_value" not in clean
    assert "file_content" not in clean
    assert "prompt" not in clean
    assert clean["detector_counts"] == {"aws_key": 2}
    assert is_content_free(clean)


def test_sanitize_coerces_count_maps_and_surfaces():
    clean = sanitize_event(
        {
            "event": "warn",
            "detector_counts": {"email": "3", "note": "x"},  # non-int dropped
            "surfaces": {"hook": 1, "proxy": 0},
        }
    )
    assert clean["detector_counts"] == {"email": 3}
    assert clean["surfaces"] == {"hook": True, "proxy": False}


# ---------------------------------------------------------------------------
# Fleet aggregation
# ---------------------------------------------------------------------------


def test_aggregate_coverage_and_dark_endpoints():
    now = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
    events = [
        {"host": "a", "event": "heartbeat", "ts": now.isoformat(), "surfaces": {"hook": True}},
        {"host": "b", "event": "heartbeat", "ts": (now - timedelta(hours=2)).isoformat()},
        {"host": "c", "event": "heartbeat", "ts": (now - timedelta(days=3)).isoformat()},  # dark
        {"host": "a", "event": "block", "ts": now.isoformat(), "detector_counts": {"aws_key": 1}},
        {"host": "b", "event": "bypass", "ts": now.isoformat(), "detail": "--no-verify"},
    ]
    agg = aggregate_fleet(events, now=now)
    s = agg["summary"]
    assert s["endpoints_total"] == 3
    assert s["endpoints_enforcing"] == 2
    assert s["endpoints_dark"] == 1
    assert s["leaks_prevented"] == 1
    assert s["tamper_events"] == 1
    assert agg["tamper_feed"][0]["event"] == "bypass"
    assert agg["detector_totals"]["aws_key"] == 1


def test_demo_fleet_is_content_free():
    for ev in build_demo_fleet():
        assert is_content_free(ev), f"demo event leaked a non-metadata field: {ev}"


# ---------------------------------------------------------------------------
# Endpoint reporting (Phase 0) — non-blocking, metadata-only
# ---------------------------------------------------------------------------


def test_report_noop_without_report_to():
    from contextduty.policy import Policy
    from contextduty.team.report import report

    p = Policy(mode="warn", detectors={"email"}, custom_detectors={})  # no report_to
    # Should simply do nothing (no exception, no network).
    report(p, {"event": "heartbeat"})


def test_report_scan_sends_sanitized_metadata(monkeypatch):
    import contextduty.team.report as report_mod
    from contextduty.engine import ScanResult
    from contextduty.policy import Policy

    sent: list[dict] = []
    monkeypatch.setattr(report_mod, "_post", lambda url, token, ev, timeout: sent.append(ev))

    p = Policy(
        mode="block",
        detectors={"aws_key"},
        custom_detectors={},
        report_to={"url": "https://collector.example", "token": "x"},
    )
    result = ScanResult(
        findings_count=2, detector_counts={"aws_key": 2}, blocked=True, blocked_by=["aws_key"]
    )
    report_mod.report_scan(p, result, tool="cli", repo="my-repo")

    # heartbeat + block event, both content-free
    from contextduty.team.model import is_content_free

    assert len(sent) == 2
    assert all(is_content_free(e) for e in sent)
    events = {e["event"] for e in sent}
    assert events == {"heartbeat", "block"}


# ---------------------------------------------------------------------------
# Signed / hardened policy distribution
# ---------------------------------------------------------------------------


def test_policy_url_rejects_plain_http(monkeypatch):
    monkeypatch.delenv("CONTEXTDUTY_ALLOW_INSECURE_POLICY", raising=False)
    from contextduty.core.exceptions import PolicyValidationError
    from contextduty.policy import _fetch_url_policy

    try:
        _fetch_url_policy("http://policy.example/p.json")
        raise AssertionError("expected http to be rejected")
    except PolicyValidationError as e:
        assert "https" in str(e)


def test_policy_sha256_pin_mismatch_rejected(monkeypatch):
    import hashlib

    from contextduty.core.exceptions import PolicyValidationError
    from contextduty.policy import _fetch_url_policy

    body = b'{"mode":"block","detectors":["email"]}'

    class _R:
        def read(self):
            return body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    import contextduty.policy as pol

    monkeypatch.setattr(pol.urllib.request, "urlopen", lambda *a, **k: _R())
    # correct pin passes
    good = hashlib.sha256(body).hexdigest()
    assert _fetch_url_policy("https://p.example/p.json", expected_sha256=good)["mode"] == "block"
    # wrong pin fails
    try:
        _fetch_url_policy("https://p.example/p.json", expected_sha256="deadbeef")
        raise AssertionError("expected integrity failure")
    except PolicyValidationError as e:
        assert "integrity" in str(e)
