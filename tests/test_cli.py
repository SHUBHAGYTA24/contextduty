"""Tests for the CLI — exit codes, output shape, and flag behaviour."""

from __future__ import annotations

import json
import re
import subprocess
import sys


def run(*args, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "contextduty.cli", *args],
        capture_output=True,
        text=True,
        input=input_text,
    )


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------


def test_version_flag():
    result = run("--version")
    assert result.returncode == 0
    assert re.search(r"\d+\.\d+\.\d+", result.stdout), "should contain semver"


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_creates_policy(tmp_path):
    out = tmp_path / "policy.json"
    result = run("init", "--path", str(out))
    assert result.returncode == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert "mode" in data
    assert "detectors" in data


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def test_scan_clean_file_exits_zero(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("nothing sensitive here")
    result = run("scan", str(f))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["findings_count"] == 0


def test_scan_sensitive_file_reports_findings(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("key: AKIA1234567890ABCDEF\n")
    result = run("scan", str(f))
    assert result.returncode == 0  # warn/redact modes don't block
    data = json.loads(result.stdout)
    assert data["findings_count"] > 0


def test_scan_block_mode_exits_nonzero(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"mode": "block", "detectors": ["aws_key"]}))
    f = tmp_path / "secret.txt"
    f.write_text("AKIA1234567890ABCDEF\n")
    result = run("scan", str(f), "--policy", str(policy))
    assert result.returncode != 0


def test_scan_block_mode_clean_exits_zero(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"mode": "block", "detectors": ["aws_key"]}))
    f = tmp_path / "clean.txt"
    f.write_text("nothing sensitive\n")
    result = run("scan", str(f), "--policy", str(policy))
    assert result.returncode == 0


def test_scan_writes_report_file(tmp_path):
    f = tmp_path / "input.txt"
    f.write_text("user@example.com\n")
    report = tmp_path / "report.json"
    run("scan", str(f), "--report", str(report))
    assert report.exists()
    data = json.loads(report.read_text())
    assert "findings_count" in data


# ---------------------------------------------------------------------------
# redact
# ---------------------------------------------------------------------------


def test_redact_removes_sensitive_values(tmp_path):
    src = tmp_path / "in.txt"
    out = tmp_path / "out.txt"
    src.write_text("contact: user@example.com\n")
    result = run("redact", "--in", str(src), "--out", str(out))
    assert result.returncode == 0
    redacted = out.read_text()
    assert "user@example.com" not in redacted
    assert "<EMAIL_" in redacted


def test_redact_clean_file_unchanged(tmp_path):
    src = tmp_path / "in.txt"
    out = tmp_path / "out.txt"
    src.write_text("nothing sensitive\n")
    run("redact", "--in", str(src), "--out", str(out))
    assert out.read_text() == "nothing sensitive\n"


# ---------------------------------------------------------------------------
# policy validate
# ---------------------------------------------------------------------------


def test_policy_validate_valid(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"mode": "redact", "detectors": ["email"]}))
    result = run("policy", "validate", "--policy", str(p))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["valid"] is True


def test_policy_validate_strict_unknown_fails(tmp_path):
    p = tmp_path / "p.json"
    p.write_text(json.dumps({"mode": "redact", "detectors": ["totally_unknown"]}))
    result = run("policy", "validate", "--policy", str(p), "--strict")
    assert result.returncode != 0
