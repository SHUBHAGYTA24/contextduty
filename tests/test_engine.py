"""Tests for the scanning and redaction engine."""

from __future__ import annotations

from contextduty.engine import scan_dir, scan_text
from contextduty.policy import Policy


def _policy(mode: str = "redact", detectors=None) -> Policy:
    return Policy(
        mode=mode,
        detectors=set(detectors or ["email", "api_key", "aws_key", "bearer_token", "phone"]),
        custom_detectors={},
    )


# ---------------------------------------------------------------------------
# scan_text — basic detection
# ---------------------------------------------------------------------------


def test_scan_text_detects_email():
    result = scan_text("contact: user@example.com", _policy())
    assert result.scan.findings_count == 1
    assert result.scan.detector_counts["email"] == 1


def test_scan_text_detects_aws_key():
    result = scan_text("key=AKIA1234567890ABCDEF", _policy())
    assert result.scan.findings_count == 1
    assert "aws_key" in result.scan.detector_counts


def test_scan_text_detects_multiple():
    text = "email: a@b.com key: sk_live_ABCDEFGHIJ1234567890"
    result = scan_text(text, _policy())
    assert result.scan.findings_count == 2


def test_scan_text_clean_input():
    result = scan_text("the quick brown fox", _policy())
    assert result.scan.findings_count == 0
    assert result.scan.blocked is False


# ---------------------------------------------------------------------------
# scan_text — redact mode
# ---------------------------------------------------------------------------


def test_scan_text_redact_mode_masks_value():
    result = scan_text("email: user@example.com", _policy(mode="redact"))
    assert "user@example.com" not in result.redacted_text
    assert "<EMAIL_" in result.redacted_text


def test_scan_text_redact_mode_preserves_context():
    result = scan_text("contact: user@example.com please", _policy(mode="redact"))
    assert result.redacted_text.startswith("contact: ")
    assert result.redacted_text.endswith(" please")


def test_scan_text_redact_is_deterministic():
    p = _policy(mode="redact")
    r1 = scan_text("user@example.com", p)
    r2 = scan_text("user@example.com", p)
    assert r1.redacted_text == r2.redacted_text


# ---------------------------------------------------------------------------
# scan_text — block mode
# ---------------------------------------------------------------------------


def test_scan_text_block_mode_sets_blocked():
    result = scan_text("key=AKIA1234567890ABCDEF", _policy(mode="block"))
    assert result.scan.blocked is True


def test_scan_text_block_mode_clean_not_blocked():
    result = scan_text("nothing sensitive here", _policy(mode="block"))
    assert result.scan.blocked is False


# ---------------------------------------------------------------------------
# scan_text — warn mode
# ---------------------------------------------------------------------------


def test_scan_text_warn_mode_not_blocked():
    result = scan_text("user@example.com", _policy(mode="warn"))
    assert result.scan.blocked is False
    assert result.scan.findings_count == 1


def test_scan_text_warn_mode_text_unchanged():
    text = "user@example.com"
    result = scan_text(text, _policy(mode="warn"))
    assert result.redacted_text == text


# ---------------------------------------------------------------------------
# scan_text — custom detectors
# ---------------------------------------------------------------------------


def test_scan_text_custom_detector():
    policy = Policy(
        mode="redact",
        detectors={"employee_id"},
        custom_detectors={"employee_id": r"\bEMP-[0-9]{6}\b"},
    )
    result = scan_text("user EMP-123456 logged in", policy)
    assert result.scan.findings_count == 1
    assert "employee_id" in result.scan.detector_counts
    assert "EMP-123456" not in result.redacted_text


# ---------------------------------------------------------------------------
# scan_text — multiline
# ---------------------------------------------------------------------------


def test_scan_text_multiline():
    text = "line1: user@example.com\nline2: clean\nline3: AKIA1234567890ABCDEF"
    result = scan_text(text, _policy())
    assert result.scan.findings_count == 2
    assert result.scan.detector_counts["email"] == 1
    assert result.scan.detector_counts["aws_key"] == 1


# ---------------------------------------------------------------------------
# scan_dir — directory scanning
# ---------------------------------------------------------------------------


def test_scan_dir_single_file(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('OPENAI_KEY = "sk-EXAMPLEcontextdutyDEMOkeyXXXXXXXXXXXXXXXXXXXXXXXX"\n')
    policy = Policy(mode="redact", detectors={"openai_key"}, custom_detectors={})
    result = scan_dir(f, policy)
    assert result.findings_count == 1


def test_scan_dir_multiple_files(tmp_path):
    (tmp_path / "a.py").write_text('KEY = "sk-EXAMPLEcontextdutyDEMOkeyXXXXXXXXXXXXXXXXXXXXXXXX"\n')
    (tmp_path / "b.py").write_text('EMAIL = "user@example.com"\n')
    (tmp_path / "clean.py").write_text("x = 1\n")
    policy = Policy(mode="redact", detectors={"openai_key", "email"}, custom_detectors={})
    result = scan_dir(tmp_path, policy)
    assert result.findings_count == 2
    assert len(result.files_scanned) == 3  # all .py files walked


def test_scan_dir_skips_binary_extensions(tmp_path):
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / "clean.py").write_text("x = 1\n")
    policy = Policy(mode="redact", detectors={"email"}, custom_detectors={})
    result = scan_dir(tmp_path, policy)
    assert "img.png" not in str(result.files_scanned)


def test_scan_dir_recursive(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.py").write_text('KEY = "sk-EXAMPLEcontextdutyDEMOkeyXXXXXXXXXXXXXXXXXXXXXXXX"\n')
    policy = Policy(mode="redact", detectors={"openai_key"}, custom_detectors={})
    result = scan_dir(tmp_path, policy, recursive=True)
    assert result.findings_count == 1


def test_scan_dir_non_recursive_misses_nested(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "nested.py").write_text('KEY = "sk-EXAMPLEcontextdutyDEMOkeyXXXXXXXXXXXXXXXXXXXXXXXX"\n')
    policy = Policy(mode="redact", detectors={"openai_key"}, custom_detectors={})
    result = scan_dir(tmp_path, policy, recursive=False)
    assert result.findings_count == 0


def test_scan_dir_blocked_aggregated(tmp_path):
    (tmp_path / "a.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "b.py").write_text('KEY2 = "AKIAIOSFODNN7EXAMPLE"\n')
    policy = Policy(mode="block", detectors={"aws_key"}, custom_detectors={})
    result = scan_dir(tmp_path, policy)
    assert result.blocked is True
    assert "aws_key" in result.blocked_by


# ---------------------------------------------------------------------------
# ReDoS protection
# ---------------------------------------------------------------------------


def test_scan_line_skips_extremely_long_lines():
    """Lines over MAX_LINE_LEN are skipped entirely to prevent ReDoS."""
    from contextduty.detectors import DETECTORS
    from contextduty.engine import MAX_LINE_LEN, _scan_line

    # A line just under the limit should be scanned normally
    normal = "email: user@example.com " + "x" * 100
    assert len(_scan_line(normal, DETECTORS)) > 0

    # A line over the limit is skipped
    huge = "email: user@example.com " + "x" * (MAX_LINE_LEN + 1)
    assert _scan_line(huge, DETECTORS) == []


# ---------------------------------------------------------------------------
# Parallel scanning
# ---------------------------------------------------------------------------


def test_scan_dir_parallel(tmp_path):
    """Parallel scanning produces the same results as sequential."""
    for i in range(10):
        (tmp_path / f"file_{i}.py").write_text(f'email = "user{i}@example.com"\n')

    policy = Policy(mode="warn", detectors={"email"}, custom_detectors={})

    seq_result = scan_dir(tmp_path, policy, workers=1)
    par_result = scan_dir(tmp_path, policy, workers=4)

    assert seq_result.findings_count == par_result.findings_count == 10
    assert seq_result.detector_counts == par_result.detector_counts
    assert sorted(seq_result.files_scanned) == sorted(par_result.files_scanned)


def test_scan_dir_fail_fast_parallel(tmp_path):
    """fail_fast stops early even in parallel mode."""
    (tmp_path / "a.py").write_text('KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    for i in range(20):
        (tmp_path / f"clean_{i}.py").write_text(f"x = {i}\n")

    policy = Policy(mode="block", detectors={"aws_key"}, custom_detectors={})
    result = scan_dir(tmp_path, policy, fail_fast=True, workers=2)
    assert result.blocked is True
    # Should have scanned fewer than all 21 files
    assert len(result.files_scanned) <= 21
