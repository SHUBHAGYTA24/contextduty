"""Tests for per-detector modes and allow_patterns."""

from __future__ import annotations

import json

import pytest

from contextduty.engine import scan_text
from contextduty.policy import Policy, load_policy


def _policy(
    mode: str = "redact",
    detectors: list[str] | None = None,
    detector_modes: dict[str, str] | None = None,
    allow_patterns: dict[str, list[str]] | None = None,
) -> Policy:
    return Policy(
        mode=mode,
        detectors=set(detectors or ["email", "api_key", "aws_key", "bearer_token", "phone"]),
        custom_detectors={},
        detector_modes=detector_modes or {},
        allow_patterns=allow_patterns or {},
    )


# ---------------------------------------------------------------------------
# Per-detector modes — block
# ---------------------------------------------------------------------------


def test_detector_mode_block_overrides_global_redact():
    """api_key in block mode should block even if global mode is redact."""
    policy = _policy(mode="redact", detector_modes={"api_key": "block"})
    result = scan_text("key: sk_live_ABCDEFGHIJ1234567890", policy)
    assert result.scan.blocked is True
    assert "api_key" in result.scan.blocked_by


def test_detector_mode_block_email_does_not_affect_other_detectors():
    policy = _policy(mode="warn", detector_modes={"aws_key": "block"})
    result = scan_text("user@example.com AKIA1234567890ABCDEF", policy)
    assert result.scan.blocked is True
    assert "aws_key" in result.scan.blocked_by
    assert "email" not in result.scan.blocked_by


def test_multiple_detector_modes_block():
    policy = _policy(mode="warn", detector_modes={"api_key": "block", "aws_key": "block"})
    result = scan_text("AKIA1234567890ABCDEF sk_live_ABCDEFGHIJ1234567890", policy)
    assert result.scan.blocked is True
    assert sorted(result.scan.blocked_by) == ["api_key", "aws_key"]


def test_blocked_by_is_empty_when_not_blocked():
    policy = _policy(mode="warn", detector_modes={"api_key": "block"})
    result = scan_text("nothing sensitive here", policy)
    assert result.scan.blocked is False
    assert result.scan.blocked_by == []


# ---------------------------------------------------------------------------
# Per-detector modes — warn
# ---------------------------------------------------------------------------


def test_detector_mode_warn_does_not_mask():
    """phone in warn mode should be reported but not redacted."""
    policy = _policy(mode="redact", detector_modes={"phone": "warn"})
    result = scan_text("call +1 415-555-1212", policy)
    assert result.scan.findings_count == 1
    assert result.scan.detector_counts.get("phone") == 1
    assert result.scan.blocked is False
    assert "+1 415-555-1212" in result.redacted_text


def test_detector_mode_warn_while_others_redact():
    """email in warn mode, api_key in default redact — only api_key should be masked."""
    policy = _policy(mode="redact", detector_modes={"email": "warn"})
    result = scan_text("user@example.com key: sk_live_ABCDEFGHIJ1234567890", policy)
    assert "user@example.com" in result.redacted_text
    assert "sk_live_ABCDEFGHIJ1234567890" not in result.redacted_text


# ---------------------------------------------------------------------------
# Per-detector modes — redact override on warn policy
# ---------------------------------------------------------------------------


def test_detector_mode_redact_overrides_global_warn():
    """aws_key in redact mode while global is warn — aws_key should be masked."""
    policy = _policy(mode="warn", detector_modes={"aws_key": "redact"})
    result = scan_text("AKIA1234567890ABCDEF", policy)
    assert "AKIA1234567890ABCDEF" not in result.redacted_text
    assert result.scan.blocked is False


# ---------------------------------------------------------------------------
# Allow patterns
# ---------------------------------------------------------------------------


def test_allow_patterns_exempts_matching_value():
    policy = _policy(
        mode="block",
        allow_patterns={"email": ["noreply@.*", "alerts@.*\\.corp\\.com"]},
    )
    result = scan_text("from: noreply@corp.com", policy)
    assert result.scan.findings_count == 0
    assert result.scan.blocked is False


def test_allow_patterns_does_not_exempt_non_matching():
    policy = _policy(
        mode="redact",
        allow_patterns={"email": ["noreply@.*"]},
    )
    result = scan_text("patient@hospital.com", policy)
    assert result.scan.findings_count == 1
    assert "patient@hospital.com" not in result.redacted_text


def test_allow_patterns_partial_exemption():
    """noreply@ is allowed; patient@ is not."""
    policy = _policy(
        mode="redact",
        allow_patterns={"email": ["noreply@.*"]},
    )
    result = scan_text("noreply@corp.com patient@hospital.com", policy)
    assert result.scan.findings_count == 1
    assert "noreply@corp.com" in result.redacted_text
    assert "patient@hospital.com" not in result.redacted_text


def test_allow_patterns_different_detectors_independent():
    """Allow email but not api_key."""
    policy = _policy(
        mode="block",
        allow_patterns={"email": ["alerts@.*"]},
    )
    result = scan_text("alerts@corp.com sk_live_ABCDEFGHIJ1234567890", policy)
    assert result.scan.blocked is True
    assert "api_key" in result.scan.blocked_by
    assert "email" not in result.scan.blocked_by


# ---------------------------------------------------------------------------
# Policy loading — detector_modes and allow_patterns from file
# ---------------------------------------------------------------------------


def test_load_policy_detector_modes(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(
        json.dumps(
            {
                "mode": "warn",
                "detectors": ["email", "api_key"],
                "detector_modes": {"api_key": "block"},
            }
        )
    )
    policy = load_policy(f)
    assert policy.detector_modes["api_key"] == "block"
    assert "email" not in policy.detector_modes


def test_load_policy_invalid_detector_mode(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(
        json.dumps(
            {"mode": "redact", "detectors": ["email"], "detector_modes": {"email": "explode"}}
        )
    )
    with pytest.raises(ValueError, match="detector_modes"):
        load_policy(f)


def test_load_policy_allow_patterns(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(
        json.dumps(
            {
                "mode": "block",
                "detectors": ["email"],
                "allow_patterns": {"email": ["noreply@.*"]},
            }
        )
    )
    policy = load_policy(f)
    assert policy.allow_patterns["email"] == ["noreply@.*"]


def test_load_policy_allow_patterns_invalid_regex(tmp_path):
    f = tmp_path / "p.json"
    f.write_text(
        json.dumps(
            {
                "mode": "redact",
                "detectors": ["email"],
                "allow_patterns": {"email": ["[unclosed"]},
            }
        )
    )
    with pytest.raises(ValueError, match="invalid regex"):
        load_policy(f)


# ---------------------------------------------------------------------------
# Policy layering — detector_modes and allow_patterns merge
# ---------------------------------------------------------------------------


def test_extends_merges_detector_modes(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"mode": "redact", "detectors": ["email"], "detector_modes": {"email": "warn"}})
    )
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps(
            {
                "extends": "base.json",
                "mode": "redact",
                "detectors": ["api_key"],
                "detector_modes": {"api_key": "block"},
            }
        )
    )
    policy = load_policy(child)
    assert policy.detector_modes["email"] == "warn"
    assert policy.detector_modes["api_key"] == "block"


def test_extends_child_overrides_parent_detector_mode(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps({"mode": "redact", "detectors": ["email"], "detector_modes": {"email": "warn"}})
    )
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps(
            {
                "extends": "base.json",
                "mode": "redact",
                "detectors": [],
                "detector_modes": {"email": "block"},
            }
        )
    )
    policy = load_policy(child)
    assert policy.detector_modes["email"] == "block"


def test_extends_merges_allow_patterns(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(
        json.dumps(
            {
                "mode": "block",
                "detectors": ["email"],
                "allow_patterns": {"email": ["noreply@.*"]},
            }
        )
    )
    child = tmp_path / "child.json"
    child.write_text(
        json.dumps(
            {
                "extends": "base.json",
                "mode": "block",
                "detectors": [],
                "allow_patterns": {"email": ["alerts@.*\\.corp\\.com"]},
            }
        )
    )
    policy = load_policy(child)
    patterns = policy.allow_patterns["email"]
    assert "noreply@.*" in patterns
    assert "alerts@.*\\.corp\\.com" in patterns


# ---------------------------------------------------------------------------
# Real-world scenario: alert workflow
# ---------------------------------------------------------------------------


def test_alert_workflow_email_passes_other_secrets_blocked():
    """
    Creating an alert workflow — the destination email must pass through,
    but any API keys in the same file must be blocked.
    """
    policy = _policy(
        mode="block",
        detector_modes={"email": "redact"},
        allow_patterns={"email": ["alerts@healthtech\\.com", "noreply@.*"]},
    )
    text = (
        "Send alert to: alerts@healthtech.com\n"
        "Fallback: patient@hospital.com\n"
        "Auth: AKIA1234567890ABCDEF\n"
    )
    result = scan_text(text, policy)
    assert result.scan.blocked is True
    assert "aws_key" in result.scan.blocked_by
    assert "alerts@healthtech.com" in result.redacted_text
    assert "patient@hospital.com" not in result.redacted_text


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------


def test_policy_without_new_fields_still_works():
    """Old policies with no detector_modes or allow_patterns load cleanly."""
    policy = Policy(
        mode="redact",
        detectors={"email", "api_key"},
        custom_detectors={},
    )
    result = scan_text("user@example.com sk_live_ABCDEFGHIJ1234567890", policy)
    assert result.scan.findings_count == 2
    assert result.scan.blocked is False
