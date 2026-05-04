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
# Phone
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "555-867-5309",
        "(800) 555-1212",
        "+1 415 555 2671",
    ],
)
def test_phone_matches(value):
    assert DETECTOR_MAP["phone"].pattern.search(value)


# ---------------------------------------------------------------------------
# API key (generic sk_/rk_/pk_ style)
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
# AWS key ID
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
# AWS secret access key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "secret_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
)
def test_aws_secret_matches(value):
    assert DETECTOR_MAP["aws_secret"].pattern.search(value)


def test_aws_secret_no_match_short():
    assert not DETECTOR_MAP["aws_secret"].pattern.search("AWS_SECRET_ACCESS_KEY=short")


# ---------------------------------------------------------------------------
# GCP service account
# ---------------------------------------------------------------------------


def test_gcp_service_account_matches():
    assert DETECTOR_MAP["gcp_service_account"].pattern.search('"type": "service_account"')
    assert DETECTOR_MAP["gcp_service_account"].pattern.search(
        '{"type":"service_account","project_id":"my-project"}'
    )


def test_gcp_service_account_no_false_positive():
    assert not DETECTOR_MAP["gcp_service_account"].pattern.search('"type": "user"')


# ---------------------------------------------------------------------------
# GitHub PAT
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "ghp_" + "A" * 36,  # classic PAT
        "gho_" + "B" * 36,  # OAuth
        "ghu_" + "C" * 36,  # user-to-server
        "ghs_" + "D" * 36,  # server-to-server
        "ghr_" + "E" * 36,  # refresh
        "github_pat_" + "F" * 82,  # fine-grained PAT
    ],
)
def test_github_pat_matches(value):
    assert DETECTOR_MAP["github_pat"].pattern.search(value)


@pytest.mark.parametrize(
    "value",
    [
        "ghp_short",
        "ghy_" + "A" * 36,  # unknown prefix
    ],
)
def test_github_pat_no_false_positives(value):
    assert not DETECTOR_MAP["github_pat"].pattern.search(value)


# ---------------------------------------------------------------------------
# OpenAI key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "sk-" + "a" * 48,
        "sk-proj-" + "b" * 48,
    ],
)
def test_openai_key_matches(value):
    assert DETECTOR_MAP["openai_key"].pattern.search(value)


def test_openai_key_no_match_short():
    assert not DETECTOR_MAP["openai_key"].pattern.search("sk-short")


# ---------------------------------------------------------------------------
# Anthropic key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "sk-ant-api03-" + "x" * 40,
        "sk-ant-" + "y" * 30,
    ],
)
def test_anthropic_key_matches(value):
    assert DETECTOR_MAP["anthropic_key"].pattern.search(value)


def test_anthropic_key_no_match_short():
    assert not DETECTOR_MAP["anthropic_key"].pattern.search("sk-ant-short")


# ---------------------------------------------------------------------------
# HuggingFace token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "hf_" + "a" * 37,
        "hf_" + "Z" * 40,
    ],
)
def test_huggingface_token_matches(value):
    assert DETECTOR_MAP["huggingface_token"].pattern.search(value)


def test_huggingface_token_no_match_short():
    assert not DETECTOR_MAP["huggingface_token"].pattern.search("hf_tooshort")


# ---------------------------------------------------------------------------
# Slack token
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "xoxb-1234567890-9876543210-" + "A" * 24,  # bot token
        "xoxp-1234567890-9876543210-1234567890-" + "a" * 32,  # user token
    ],
)
def test_slack_token_matches(value):
    assert DETECTOR_MAP["slack_token"].pattern.search(value)


def test_slack_token_no_match_wrong_prefix():
    assert not DETECTOR_MAP["slack_token"].pattern.search("xoxz-1234567890-notaslacktoken")


# ---------------------------------------------------------------------------
# Stripe webhook
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "whsec_" + "a" * 32,
        "whsec_" + "X" * 48,
    ],
)
def test_stripe_webhook_matches(value):
    assert DETECTOR_MAP["stripe_webhook"].pattern.search(value)


def test_stripe_webhook_no_match_short():
    assert not DETECTOR_MAP["stripe_webhook"].pattern.search("whsec_tooshort")


# ---------------------------------------------------------------------------
# SendGrid key
# ---------------------------------------------------------------------------


def test_sendgrid_key_matches():
    key = "SG." + "A" * 22 + "." + "B" * 43
    assert DETECTOR_MAP["sendgrid_key"].pattern.search(key)


def test_sendgrid_key_no_match_wrong_format():
    assert not DETECTOR_MAP["sendgrid_key"].pattern.search("SG.tooshort.alsoShort")


# ---------------------------------------------------------------------------
# Mailchimp key
# ---------------------------------------------------------------------------


def test_mailchimp_key_matches():
    assert DETECTOR_MAP["mailchimp_key"].pattern.search("a" * 32 + "-us1")
    assert DETECTOR_MAP["mailchimp_key"].pattern.search("b" * 32 + "-us21")


def test_mailchimp_key_no_match_wrong_format():
    assert not DETECTOR_MAP["mailchimp_key"].pattern.search("tooshort-us1")


# ---------------------------------------------------------------------------
# npm token
# ---------------------------------------------------------------------------


def test_npm_token_matches():
    assert DETECTOR_MAP["npm_token"].pattern.search("npm_" + "a" * 36)


def test_npm_token_no_match_short():
    assert not DETECTOR_MAP["npm_token"].pattern.search("npm_tooshort")


# ---------------------------------------------------------------------------
# Twilio SID
# ---------------------------------------------------------------------------


def test_twilio_sid_matches():
    assert DETECTOR_MAP["twilio_sid"].pattern.search("AC" + "a" * 32)


def test_twilio_sid_no_match_wrong_prefix():
    assert not DETECTOR_MAP["twilio_sid"].pattern.search("BC" + "a" * 32)


# ---------------------------------------------------------------------------
# Azure storage key
# ---------------------------------------------------------------------------


def test_azure_storage_key_matches():
    key = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "A" * 86 + "==;"
    assert DETECTOR_MAP["azure_storage_key"].pattern.search(key)


def test_azure_storage_key_no_match_incomplete():
    assert not DETECTOR_MAP["azure_storage_key"].pattern.search(
        "DefaultEndpointsProtocol=https;AccountName=myaccount;"
    )


# ---------------------------------------------------------------------------
# Google OAuth token
# ---------------------------------------------------------------------------


def test_google_oauth_token_matches():
    token = "ya29." + "a" * 60
    assert DETECTOR_MAP["google_oauth_token"].pattern.search(token)


def test_google_oauth_token_no_match_short():
    assert not DETECTOR_MAP["google_oauth_token"].pattern.search("ya29.short")


# ---------------------------------------------------------------------------
# Database DSN
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "postgresql://user:password@localhost:5432/mydb",
        "postgres://admin:s3cr3t@db.example.com/prod",
        "mysql://root:hunter2@127.0.0.1:3306/app",
        "mongodb://user:pass@cluster.example.com/db",
        "mongodb+srv://user:pass@cluster.example.mongodb.net/",
        "redis://user:password@redis.example.com:6379/0",
    ],
)
def test_db_dsn_matches(value):
    assert DETECTOR_MAP["db_dsn"].pattern.search(value)


@pytest.mark.parametrize(
    "value",
    [
        "postgresql://localhost/mydb",  # no credentials
        "redis://redis.example.com:6379",  # no credentials
        "https://user:pass@example.com",  # HTTP, not DB
    ],
)
def test_db_dsn_no_false_positives(value):
    assert not DETECTOR_MAP["db_dsn"].pattern.search(value)


# ---------------------------------------------------------------------------
# SSH private key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_ssh_private_key_matches(header):
    # ssh_private_key catches RSA/DSA/EC/OPENSSH; private_key_pem catches bare PKCS#8
    det = "private_key_pem" if header == "-----BEGIN PRIVATE KEY-----" else "ssh_private_key"
    assert DETECTOR_MAP[det].pattern.search(header)


def test_ssh_private_key_no_match_public_key():
    assert not DETECTOR_MAP["ssh_private_key"].pattern.search("-----BEGIN RSA PUBLIC KEY-----")


# ---------------------------------------------------------------------------
# PGP private key
# ---------------------------------------------------------------------------


def test_pgp_private_key_matches():
    assert DETECTOR_MAP["pgp_private_key"].pattern.search("-----BEGIN PGP PRIVATE KEY BLOCK-----")


def test_pgp_private_key_no_match_public():
    assert not DETECTOR_MAP["pgp_private_key"].pattern.search(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    )


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------


def test_jwt_matches():
    # well-formed JWT: header.payload.signature all base64url
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert DETECTOR_MAP["jwt"].pattern.search(token)


def test_jwt_no_match_plain_text():
    assert not DETECTOR_MAP["jwt"].pattern.search("not.a.jwt")


# ---------------------------------------------------------------------------
# .env secret
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "PASSWORD=supersecret123",
        "SECRET_KEY=abc123def456ghi",
        "API_KEY=some-long-api-key-value",
        "ACCESS_TOKEN=mytoken12345678",
        "CLIENT_SECRET=clientsecretvalue",
    ],
)
def test_env_secret_matches(value):
    assert DETECTOR_MAP["env_secret"].pattern.search(value)


@pytest.mark.parametrize(
    "value",
    [
        "PASSWORD=short",  # too short (< 8 chars)
        "NOT_A_SECRET=value",  # key not in allowlist
    ],
)
def test_env_secret_no_false_positives(value):
    assert not DETECTOR_MAP["env_secret"].pattern.search(value)


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


# ---------------------------------------------------------------------------
# Detector coverage sanity check
# ---------------------------------------------------------------------------


def test_detector_count_at_least_25():
    """Ensure we have meaningful coverage — fail loudly if someone deletes patterns."""
    assert len(DETECTORS) >= 25, f"Expected ≥25 detectors, got {len(DETECTORS)}"


def test_all_detectors_have_unique_names():
    names = [d.name for d in DETECTORS]
    assert len(names) == len(set(names)), "Duplicate detector names found"
