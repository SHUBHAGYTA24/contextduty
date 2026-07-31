"""Tests for opt-in live-credential verification (all network calls mocked)."""

from __future__ import annotations

import json
import urllib.error

from contextduty import verify as V
from contextduty.policy import Policy


class _Resp:
    def __init__(self, status: int = 200, body: bytes = b""):
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_urlopen(monkeypatch, fn):
    monkeypatch.setattr(V.urllib.request, "urlopen", fn)


# ---------------------------------------------------------------------------
# verify()
# ---------------------------------------------------------------------------


def test_unsupported_detector_returns_unsupported():
    assert V.verify("aws_key", "AKIA1234567890ABCDEF") == V.UNSUPPORTED


def test_is_verifiable():
    assert V.is_verifiable("github_pat")
    assert V.is_verifiable("stripe_secret")
    assert not V.is_verifiable("email")


def test_github_active(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _Resp(200))
    assert V.verify("github_pat", "ghp_" + "a" * 36) == V.ACTIVE


def test_github_inactive_on_401(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.HTTPError("u", 401, "unauthorized", {}, None)

    _patch_urlopen(monkeypatch, boom)
    assert V.verify("github_pat", "ghp_" + "a" * 36) == V.INACTIVE


def test_network_error_is_unverified(monkeypatch):
    def boom(*a, **k):
        raise OSError("no network")

    _patch_urlopen(monkeypatch, boom)
    assert V.verify("openai_key", "sk-" + "a" * 40) == V.UNVERIFIED


def test_stripe_active(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _Resp(200))
    assert V.verify("stripe_secret", "sk_live_" + "a" * 24) == V.ACTIVE


def test_slack_ok_body_is_active(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _Resp(200, json.dumps({"ok": True}).encode()))
    assert V.verify("slack_bot_token", "xoxb-1-1-" + "a" * 24) == V.ACTIVE


def test_slack_not_ok_body_is_inactive(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _Resp(200, json.dumps({"ok": False}).encode()))
    assert V.verify("slack_bot_token", "xoxb-1-1-" + "a" * 24) == V.INACTIVE


# ---------------------------------------------------------------------------
# verify_findings()
# ---------------------------------------------------------------------------


def test_verify_findings_reports_status_without_raw_values(monkeypatch):
    _patch_urlopen(monkeypatch, lambda *a, **k: _Resp(200))
    policy = Policy(mode="warn", detectors={"github_pat", "email"}, custom_detectors={})
    text = "token ghp_" + "a" * 36 + " and email a@b.com"
    results = V.verify_findings(text, policy)
    # Only the verifiable detector (github_pat) is checked; email is ignored.
    assert results == [("github_pat", V.ACTIVE)]


def test_verify_findings_dedupes(monkeypatch):
    calls = {"n": 0}

    def counting(*a, **k):
        calls["n"] += 1
        return _Resp(200)

    _patch_urlopen(monkeypatch, counting)
    policy = Policy(mode="warn", detectors={"github_pat"}, custom_detectors={})
    tok = "ghp_" + "a" * 36
    text = f"{tok}\n{tok}\n{tok}"  # same token 3x
    results = V.verify_findings(text, policy)
    assert results == [("github_pat", V.ACTIVE)]
    assert calls["n"] == 1  # verified once, not three times
