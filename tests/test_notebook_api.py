"""Tests for contextduty.notebook — the data-scientist-friendly API."""

import pytest

from contextduty.notebook import SecretFoundError, guard, redact, scan


def test_scan_finds_aws_key():
    result = scan("key = AKIAIOSFODNN7EXAMPLE")
    assert result.scan.findings_count > 0
    assert "aws_key" in result.scan.detector_counts


def test_scan_clean_text():
    result = scan("hello world")
    assert result.scan.findings_count == 0


def test_redact_replaces_secret():
    clean = redact("key = AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in clean
    assert "<AWS_KEY_" in clean


def test_redact_clean_text_unchanged():
    text = "x = 42"
    assert redact(text) == text


def test_guard_returns_scan_result():
    result = guard("key = AKIAIOSFODNN7EXAMPLE")
    assert result.findings_count > 0


def test_guard_clean_text():
    result = guard("just some normal text")
    assert result.findings_count == 0


def test_guard_multiple_secrets():
    text = """
    aws_key = AKIAIOSFODNN7EXAMPLE
    email = user@example.com
    ssn = 123-45-6789
    """
    result = guard(text)
    assert result.findings_count >= 2


def test_redact_multiple_secrets():
    text = "db = postgres://admin:secret@prod:5432/app\nkey = AKIAIOSFODNN7EXAMPLE"
    clean = redact(text)
    assert "admin:secret" not in clean
    assert "AKIAIOSFODNN7EXAMPLE" not in clean


def test_guard_raise_on_block():
    from contextduty.policy import Policy

    policy = Policy(
        mode="block",
        detectors={"aws_key"},
        custom_detectors={},
    )
    with pytest.raises(SecretFoundError):
        guard("key = AKIAIOSFODNN7EXAMPLE", policy=policy, raise_on_block=True)


def test_guard_no_raise_when_not_blocked():
    result = guard("key = AKIAIOSFODNN7EXAMPLE", raise_on_block=True)
    # Default mode is "warn", not "block", so no exception
    assert result.findings_count > 0
