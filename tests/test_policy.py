"""Tests for policy loading, validation, and layering."""

from __future__ import annotations

import json
import pytest

from contextduty.policy import load_policy, unknown_detector_names


# ---------------------------------------------------------------------------
# Default policy
# ---------------------------------------------------------------------------

def test_default_policy_loads():
    policy = load_policy(None)
    assert policy.mode == "redact"
    assert "email" in policy.detectors
    assert "aws_key" in policy.detectors


# ---------------------------------------------------------------------------
# Policy from file
# ---------------------------------------------------------------------------

def test_load_policy_from_file(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({"mode": "block", "detectors": ["email"]}))
    policy = load_policy(f)
    assert policy.mode == "block"
    assert "email" in policy.detectors


def test_load_policy_invalid_mode(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({"mode": "explode", "detectors": ["email"]}))
    with pytest.raises(ValueError, match="mode"):
        load_policy(f)


def test_load_policy_invalid_regex(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({
        "mode": "redact",
        "detectors": ["email"],
        "custom_detectors": {"bad": "[unclosed"},
    }))
    with pytest.raises(ValueError, match="regex"):
        load_policy(f)


def test_load_policy_custom_conflicts_builtin(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({
        "mode": "redact",
        "detectors": ["email"],
        "custom_detectors": {"email": r"\bfoo\b"},
    }))
    with pytest.raises(ValueError, match="conflicts"):
        load_policy(f)


# ---------------------------------------------------------------------------
# Custom detectors auto-activated
# ---------------------------------------------------------------------------

def test_custom_detectors_auto_activated(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({
        "mode": "redact",
        "detectors": [],
        "custom_detectors": {"emp_id": r"\bEMP-[0-9]{6}\b"},
    }))
    policy = load_policy(f)
    assert "emp_id" in policy.detectors


# ---------------------------------------------------------------------------
# Policy layering via extends
# ---------------------------------------------------------------------------

def test_policy_extends_merges_detectors(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"mode": "warn", "detectors": ["email"]}))

    child = tmp_path / "child.json"
    child.write_text(json.dumps({
        "extends": "base.json",
        "mode": "block",
        "detectors": ["aws_key"],
    }))

    policy = load_policy(child)
    assert policy.mode == "block"          # child overrides
    assert "email" in policy.detectors     # from parent
    assert "aws_key" in policy.detectors   # from child


def test_policy_extends_child_custom_overrides_parent(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({
        "mode": "redact",
        "detectors": [],
        "custom_detectors": {"ticket": r"\bTKT-[0-9]{4}\b"},
    }))
    child = tmp_path / "child.json"
    child.write_text(json.dumps({
        "extends": "base.json",
        "mode": "redact",
        "detectors": [],
        "custom_detectors": {"ticket": r"\bTICKET-[0-9]{6}\b"},
    }))
    policy = load_policy(child)
    assert policy.custom_detectors["ticket"] == r"\bTICKET-[0-9]{6}\b"


def test_policy_extends_list(tmp_path):
    a = tmp_path / "a.json"
    a.write_text(json.dumps({"mode": "redact", "detectors": ["email"]}))
    b = tmp_path / "b.json"
    b.write_text(json.dumps({"mode": "redact", "detectors": ["phone"]}))
    child = tmp_path / "child.json"
    child.write_text(json.dumps({"extends": ["a.json", "b.json"], "mode": "block", "detectors": []}))

    policy = load_policy(child)
    assert "email" in policy.detectors
    assert "phone" in policy.detectors


def test_policy_extends_cycle_detected(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"extends": "b.json", "mode": "redact", "detectors": []}))
    b.write_text(json.dumps({"extends": "a.json", "mode": "redact", "detectors": []}))
    with pytest.raises(ValueError, match="cycle"):
        load_policy(a)


# ---------------------------------------------------------------------------
# unknown_detector_names
# ---------------------------------------------------------------------------

def test_unknown_detector_names_returns_unknown(tmp_path):
    f = tmp_path / ".contextduty.json"
    f.write_text(json.dumps({"mode": "redact", "detectors": ["email", "nonexistent_detector"]}))
    policy = load_policy(f)
    unknown = unknown_detector_names(policy)
    assert "nonexistent_detector" in unknown
    assert "email" not in unknown
