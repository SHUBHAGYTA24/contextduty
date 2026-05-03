"""Tests for audit logging and the report command."""

from __future__ import annotations

import json
import subprocess
import sys


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "contextduty.cli", *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# Audit log — written on scan
# ---------------------------------------------------------------------------


def test_audit_log_created_on_scan(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("user@example.com\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))

    assert log.exists()
    entry = json.loads(log.read_text().strip())
    assert entry["operation"] == "scan"
    assert entry["findings_count"] == 1
    assert entry["detector_counts"]["email"] == 1
    assert "ts" in entry
    assert "user" in entry
    assert "hostname" in entry


def test_audit_log_never_records_matched_values(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("secret: sk_live_ABCDEFGHIJ1234567890\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))

    raw = log.read_text()
    assert "sk_live_ABCDEFGHIJ1234567890" not in raw


def test_audit_log_appends_multiple_entries(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("user@example.com\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))
    run("scan", str(src), "--audit-log", str(log))
    run("scan", str(src), "--audit-log", str(log))

    lines = [line for line in log.read_text().splitlines() if line.strip()]
    assert len(lines) == 3


def test_audit_log_on_redact(tmp_path):
    src = tmp_path / "input.txt"
    out = tmp_path / "out.txt"
    src.write_text("AKIA1234567890ABCDEF\n")
    log = tmp_path / "audit.jsonl"

    run("redact", "--in", str(src), "--out", str(out), "--audit-log", str(log))

    entry = json.loads(log.read_text().strip())
    assert entry["operation"] == "redact"
    assert entry["findings_count"] == 1


def test_audit_log_clean_file_zero_findings(tmp_path):
    src = tmp_path / "clean.txt"
    src.write_text("nothing sensitive here\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))

    entry = json.loads(log.read_text().strip())
    assert entry["findings_count"] == 0
    assert entry["blocked"] is False


def test_audit_log_records_blocked(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"mode": "block", "detectors": ["aws_key"]}))
    src = tmp_path / "input.txt"
    src.write_text("AKIA1234567890ABCDEF\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--policy", str(policy), "--audit-log", str(log))

    entry = json.loads(log.read_text().strip())
    assert entry["blocked"] is True
    assert "aws_key" in entry["blocked_by"]


def test_audit_log_creates_parent_dirs(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("user@example.com\n")
    log = tmp_path / "logs" / "sub" / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))

    assert log.exists()


# ---------------------------------------------------------------------------
# contextduty report
# ---------------------------------------------------------------------------


def test_report_command_summarises_audit_log(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("user@example.com sk_live_ABCDEFGHIJ1234567890\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src), "--audit-log", str(log))
    run("scan", str(src), "--audit-log", str(log))

    result = run("report", "--audit-log", str(log))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["total_scans"] == 2
    assert data["total_findings"] == 4
    assert "email" in data["detector_totals"]
    assert "api_key" in data["detector_totals"]


def test_report_command_empty_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.write_text("")

    result = run("report", "--audit-log", str(log))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["total_scans"] == 0


def test_report_command_writes_to_file(tmp_path):
    src = tmp_path / "input.txt"
    src.write_text("user@example.com\n")
    log = tmp_path / "audit.jsonl"
    out = tmp_path / "report.json"

    run("scan", str(src), "--audit-log", str(log))
    run("report", "--audit-log", str(log), "--out", str(out))

    assert out.exists()
    data = json.loads(out.read_text())
    assert data["total_scans"] == 1


def test_report_missing_log(tmp_path):
    log = tmp_path / "nonexistent.jsonl"
    result = run("report", "--audit-log", str(log))
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "error" in data


def test_report_block_rate(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"mode": "block", "detectors": ["aws_key"]}))
    src_blocked = tmp_path / "blocked.txt"
    src_blocked.write_text("AKIA1234567890ABCDEF\n")
    src_clean = tmp_path / "clean.txt"
    src_clean.write_text("nothing\n")
    log = tmp_path / "audit.jsonl"

    run("scan", str(src_blocked), "--policy", str(policy), "--audit-log", str(log))
    run("scan", str(src_clean), "--policy", str(policy), "--audit-log", str(log))

    result = run("report", "--audit-log", str(log))
    data = json.loads(result.stdout)
    assert data["total_blocked"] == 1
    assert data["block_rate_pct"] == 50.0
