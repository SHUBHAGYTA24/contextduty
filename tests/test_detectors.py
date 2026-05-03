"""Tests for built-in detectors — each detector must catch what it claims."""

from __future__ import annotations

import pytest

from contextduty.detectors import DETECTORS, stable_mask

DETECTOR_MAP = {d.name: d for d in DETECTORS}


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "user@example.com",
        "jane.doe+tag@corp.co.uk",
        "admin@sub.domain.org",
    ],
)
def test_email_matches(value):
    assert DETECTOR_MAP["email"].pattern.search(value)


@pytest.mark.parametrize(
    "value",
    [
        "notanemail",
        "@missinglocal.com",
        "missing@",
    ],
)
def test_email_no_false_positives(value):
    assert not DETECTOR_MAP["email"].pattern.search(value)


# ---------------------------------------------------------------------------
# API key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "sk_live_ABCDEFGHIJ1234567890",
        "rk_test_abcdefghijklmnop",
        "pk_prod_XXXXXXXXXXXXXXXX",
    ],
)
def test_api_key_matches(value):
    assert DETECTOR_MAP["api_key"].pattern.search(value)


# ---------------------------------------------------------------------------
# AWS key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "AKIA1234567890ABCDEF",
        "AKIAIOSFODNN7EXAMPLE",
    ],
)
def test_aws_key_matches(value):
    assert DETECTOR_MAP["aws_key"].pattern.search(value)


def test_aws_key_wrong_prefix():
    assert not DETECTOR_MAP["aws_key"].pattern.search("BKIA1234567890ABCDEF")


# ---------------------------------------------------------------------------
# Bearer token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "bearer sometoken123",
        "BEARER UPPERCASETOKEN",
    ],
)
def test_bearer_token_matches(value):
    assert DETECTOR_MAP["bearer_token"].pattern.search(value)


# ---------------------------------------------------------------------------
# Stable mask
# ---------------------------------------------------------------------------


def test_stable_mask_is_deterministic():
    a = stable_mask("email", "user@example.com")
    b = stable_mask("email", "user@example.com")
    assert a == b


def test_stable_mask_different_values_differ():
    a = stable_mask("email", "alice@example.com")
    b = stable_mask("email", "bob@example.com")
    assert a != b


def test_stable_mask_format():
    mask = stable_mask("api_key", "sk_live_abc")
    assert mask.startswith("<API_KEY_")
    assert mask.endswith(">")
