"""Edge-case tests for the scanning and redaction engine."""

from __future__ import annotations

from contextduty.engine import redact_file, scan_dir, scan_text
from contextduty.policy import Policy


def _policy(
    mode: str = "redact",
    detectors=None,
    detector_modes=None,
    allow_patterns=None,
    custom_detectors=None,
) -> Policy:
    return Policy(
        mode=mode,
        detectors=set(detectors or ["email", "api_key", "aws_key", "bearer_token", "phone"]),
        custom_detectors=custom_detectors or {},
        detector_modes=detector_modes or {},
        allow_patterns=allow_patterns or {},
    )


# ---------------------------------------------------------------------------
# allow_patterns
# ---------------------------------------------------------------------------


def test_allow_patterns_bypass_redact():
    policy = _policy(
        mode="redact",
        detectors=["email"],
        allow_patterns={"email": [r"noreply@example\.com"]},
    )
    result = scan_text("contact: noreply@example.com", policy)
    assert result.scan.findings_count == 0
    assert result.redacted_text == "contact: noreply@example.com"


def test_allow_patterns_bypass_block():
    policy = _policy(
        mode="block",
        detectors=["email"],
        allow_patterns={"email": [r"noreply@.*"]},
    )
    result = scan_text("from: noreply@test.com", policy)
    assert result.scan.blocked is False


def test_allow_patterns_only_bypass_matching_value():
    policy = _policy(
        mode="redact",
        detectors=["email"],
        allow_patterns={"email": [r"noreply@.*"]},
    )
    # noreply allowed, real email still redacted
    result = scan_text("from: noreply@test.com to: user@example.com", policy)
    assert "user@example.com" not in result.redacted_text
    assert "noreply@test.com" in result.redacted_text


# ---------------------------------------------------------------------------
# Per-detector mode overrides
# ---------------------------------------------------------------------------


def test_per_detector_block_overrides_global_warn():
    policy = _policy(
        mode="warn",
        detectors=["email", "aws_key"],
        detector_modes={"aws_key": "block"},
    )
    result = scan_text("email: a@b.com key: AKIA1234567890ABCDEF", policy)
    assert result.scan.blocked is True
    assert "aws_key" in result.scan.blocked_by
    # email in warn mode — not blocked
    assert "email" not in result.scan.blocked_by


def test_per_detector_warn_overrides_global_block():
    policy = _policy(
        mode="block",
        detectors=["email"],
        detector_modes={"email": "warn"},
    )
    result = scan_text("user@example.com", policy)
    assert result.scan.blocked is False
    assert result.scan.findings_count == 1


def test_per_detector_mixed_modes_counts_all():
    policy = _policy(
        mode="redact",
        detectors=["email", "aws_key"],
        detector_modes={"aws_key": "warn"},
    )
    text = "a@b.com AKIA1234567890ABCDEF"
    result = scan_text(text, policy)
    assert result.scan.detector_counts.get("email", 0) == 1
    assert result.scan.detector_counts.get("aws_key", 0) == 1
    # email redacted, aws_key in warn so original value preserved
    assert "a@b.com" not in result.redacted_text
    assert "AKIA1234567890ABCDEF" in result.redacted_text


# ---------------------------------------------------------------------------
# Overlapping regex matches — longer wins
# ---------------------------------------------------------------------------


def test_overlapping_matches_longer_wins():
    # Custom detectors: one matches 8 chars, one matches 4 chars of the same prefix
    policy = Policy(
        mode="redact",
        detectors={"long_tok", "short_tok"},
        custom_detectors={
            "long_tok": r"\bTOK-[A-Z0-9]{8}\b",
            "short_tok": r"\bTOK-[A-Z0-9]{4}\b",
        },
    )
    result = scan_text("auth TOK-ABCD1234 done", policy)
    # Both detectors match but at same start; the value that's redacted should
    # cover the full token (both map to the same span — only one replacement)
    assert "TOK-ABCD1234" not in result.redacted_text
    # Exactly one redaction token in output
    assert result.redacted_text.count("<") == 1


# ---------------------------------------------------------------------------
# Duplicate identical secrets on the same line
# ---------------------------------------------------------------------------


def test_duplicate_identical_secrets_on_same_line_both_redacted():
    email = "user@example.com"
    text = f"from: {email} to: {email}"
    result = scan_text(text, _policy(mode="redact", detectors=["email"]))
    assert result.redacted_text.count(email) == 0
    # Two distinct replacement tokens (same hash, but two occurrences)
    assert result.redacted_text.count("<EMAIL_") == 2


# ---------------------------------------------------------------------------
# block mode — redacted_text still masks the value
# ---------------------------------------------------------------------------


def test_scan_text_block_mode_still_masks_redacted_text():
    key = "AKIA1234567890ABCDEF"
    result = scan_text(f"key={key}", _policy(mode="block", detectors=["aws_key"]))
    assert result.scan.blocked is True
    assert key not in result.redacted_text
    assert "<AWS_KEY_" in result.redacted_text


# ---------------------------------------------------------------------------
# redact_file with block-mode secrets
# ---------------------------------------------------------------------------


def test_redact_file_block_mode_secrets_are_masked(tmp_path):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    key = "AKIA1234567890ABCDEF"
    src.write_text(f"key = {key}\n")
    policy = _policy(mode="block", detectors=["aws_key"])
    result = redact_file(src, dst, policy)
    assert result.blocked is True
    assert key not in dst.read_text()
    assert "<AWS_KEY_" in dst.read_text()


# ---------------------------------------------------------------------------
# Corrupted .ipynb — fallback to plain text
# ---------------------------------------------------------------------------


def test_scan_file_corrupted_notebook_falls_back_to_plain_text(tmp_path):
    nb = tmp_path / "bad.ipynb"
    # Valid JSON but not a notebook structure — scan_file should not crash
    nb.write_text('{"not": "a notebook", "email": "user@example.com"}\n')
    from contextduty.engine import scan_file

    policy = _policy(mode="redact", detectors=["email"])
    result = scan_file(nb, policy)
    # Falls back to plain-text scan — email in the JSON string is found
    assert result.findings_count >= 1


def test_redact_file_corrupted_notebook_falls_back_to_plain_text(tmp_path):
    src = tmp_path / "bad.ipynb"
    dst = tmp_path / "dst.ipynb"
    src.write_text("NOT JSON AT ALL\nuser@example.com\n")
    policy = _policy(mode="redact", detectors=["email"])
    result = redact_file(src, dst, policy)
    assert result.findings_count >= 1
    assert "user@example.com" not in dst.read_text()


# ---------------------------------------------------------------------------
# Empty directory
# ---------------------------------------------------------------------------


def test_scan_dir_empty_directory(tmp_path):
    policy = _policy()
    result = scan_dir(tmp_path, policy)
    assert result.findings_count == 0
    assert result.blocked is False
    assert result.files_scanned == []


def test_scan_dir_directory_with_only_binary_files(tmp_path):
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / "archive.zip").write_bytes(b"PK\x03\x04")
    policy = _policy()
    result = scan_dir(tmp_path, policy)
    assert result.findings_count == 0
    assert result.files_scanned == []


# ---------------------------------------------------------------------------
# generate_report — mixed valid/corrupted JSONL
# ---------------------------------------------------------------------------


def test_generate_report_mixed_valid_corrupted_lines(tmp_path):
    from contextduty.audit import generate_report, write_audit_entry
    from contextduty.engine import ScanResult

    log = tmp_path / "audit.jsonl"
    scan = ScanResult(
        findings_count=1,
        detector_counts={"email": 1},
        blocked=False,
        blocked_by=[],
    )
    write_audit_entry(
        operation="scan",
        result=scan,
        policy_path=None,
        target="file.txt",
        audit_log_path=log,
    )
    # Inject a corrupted line
    with log.open("a") as f:
        f.write("NOT JSON\n")
    # Add a second valid line
    write_audit_entry(
        operation="scan",
        result=scan,
        policy_path=None,
        target="file2.txt",
        audit_log_path=log,
    )

    report = generate_report(log)
    # Corrupted line is skipped; 2 valid entries counted
    assert report["total_scans"] == 2
    assert report["total_findings"] == 2


# ---------------------------------------------------------------------------
# pre_commit_entrypoint — exception handling
# ---------------------------------------------------------------------------


def test_pre_commit_entrypoint_skips_missing_file(tmp_path):
    from contextduty.hooks import pre_commit_entrypoint

    result = pre_commit_entrypoint([str(tmp_path / "does_not_exist.txt")])
    assert result == 0  # no crash, no block


def test_pre_commit_entrypoint_clean_files(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("nothing sensitive here\n")
    from contextduty.hooks import pre_commit_entrypoint

    result = pre_commit_entrypoint([str(f)])
    assert result == 0


# ---------------------------------------------------------------------------
# hooks — shell special characters in path
# ---------------------------------------------------------------------------


def test_install_hook_path_with_dollar_sign(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    from contextduty.hooks import install_git_hook

    hook = install_git_hook(tmp_path, policy_path="/tmp/$HOME/policy.json")
    content = hook.read_text()
    # Dollar sign should be escaped so bash doesn't expand it
    assert r"\$HOME" in content or "\\$HOME" in content


def test_install_hook_path_with_backtick(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    from contextduty.hooks import install_git_hook

    hook = install_git_hook(tmp_path, policy_path="/tmp/`whoami`/policy.json")
    content = hook.read_text()
    assert r"\`whoami\`" in content or "\\`whoami\\`" in content


# ---------------------------------------------------------------------------
# stable_mask determinism
# ---------------------------------------------------------------------------


def test_stable_mask_deterministic_across_detectors():
    from contextduty.detectors import stable_mask

    m1 = stable_mask("email", "user@example.com")
    m2 = stable_mask("email", "user@example.com")
    assert m1 == m2


def test_stable_mask_different_values_produce_different_masks():
    from contextduty.detectors import stable_mask

    assert stable_mask("email", "a@b.com") != stable_mask("email", "x@y.com")


def test_stable_mask_different_detectors_produce_different_masks():
    from contextduty.detectors import stable_mask

    assert stable_mask("email", "val") != stable_mask("phone", "val")


# ---------------------------------------------------------------------------
# scan_text — empty string
# ---------------------------------------------------------------------------


def test_scan_text_empty_string():
    result = scan_text("", _policy())
    assert result.scan.findings_count == 0
    assert result.redacted_text == ""


# ---------------------------------------------------------------------------
# scan_text — text with no trailing newline
# ---------------------------------------------------------------------------


def test_scan_text_no_trailing_newline():
    result = scan_text("user@example.com", _policy(mode="redact", detectors=["email"]))
    assert "user@example.com" not in result.redacted_text
    assert not result.redacted_text.endswith("\n")
