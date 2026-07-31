"""Tests for built-in detectors — each detector must catch what it claims
without firing on ordinary text.

Driven by ``_CASES``: one entry per detector with positive samples (must
match) and negative samples (must NOT match).  This keeps the 60-detector
set honest — adding a detector without a test entry fails
``test_every_detector_is_covered``.
"""

from __future__ import annotations

import pytest

from contextduty.detectors import DETECTORS, stable_mask

DETECTOR_MAP = {d.name: d for d in DETECTORS}

# detector -> (positives, negatives)
_CASES: dict[str, tuple[list[str], list[str]]] = {
    # ── Cloud / Infrastructure ──────────────────────────────────────────────
    "aws_key": (["AKIA1234567890ABCDEF"], ["BKIA1234567890ABCDEF", "AKIA123"]),
    "aws_secret": (
        ["AWS_SECRET_ACCESS_KEY=" + "a" * 40],
        ["AWS_SECRET_ACCESS_KEY=short"],
    ),
    "aws_mfa_serial": (["arn:aws:iam::123456789012:mfa/jdoe"], ["arn:aws:s3:::bucket"]),
    "gcp_service_account": (['"type": "service_account"'], ['"type": "user"']),
    "gcp_api_key": (["AIza" + "B" * 35], ["AIzashort"]),
    "azure_client_secret": (
        ["azure_client_secret=" + "x" * 40],
        ["azure_client_secret=short"],
    ),
    "azure_storage_key": (
        ["DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=" + "B" * 86 + "=="],
        ["DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=short"],
    ),
    # ── VCS / CI ────────────────────────────────────────────────────────────
    "github_pat": (["ghp_" + "a" * 36], ["ghp_short", "ghx_" + "a" * 36]),
    "github_oauth": (["gho_" + "a" * 36], ["gho_short"]),
    "github_app_token": (["ghs_" + "a" * 36], ["ghs_short"]),
    "github_refresh_token": (["ghr_" + "a" * 40], ["ghr_short"]),
    "gitlab_pat": (["glpat-" + "a" * 20], ["glpat-short"]),
    "gitlab_runner_token": (["glrt-" + "a" * 20], ["glrt-short"]),
    # ── Payment / Fintech ───────────────────────────────────────────────────
    "stripe_secret": (["sk_live_" + "a" * 24], ["sk_live_short"]),
    "stripe_restricted": (["rk_test_" + "a" * 24], ["rk_test_short"]),
    "stripe_publishable": (["pk_live_" + "a" * 24], ["pk_live_short"]),
    "stripe_webhook": (["whsec_" + "a" * 32], ["whsec_short"]),
    "paypal_secret": (["paypal_client_secret=" + "a" * 32], ["paypal_client_secret=short"]),
    "credit_card": (["4111111111111111", "378282246310005"], ["1234567890123456"]),
    # ── Messaging / Comms ───────────────────────────────────────────────────
    "slack_bot_token": (
        ["xoxb-1234567890-1234567890-" + "a" * 24],
        ["xoxz-1234567890-notaslacktoken"],
    ),
    "slack_user_token": (["xoxp-1234567890-1234567890-1234567890-" + "a" * 32], ["xoxp-short"]),
    "slack_workspace_token": (
        ["xoxa-2-1234567890-1234567890-1234567890-" + "a" * 16],
        ["xoxa-2-short"],
    ),
    "slack_config_token": (["xoxe.xoxb-1-" + "A" * 120], ["xoxe.xoxb-1-short"]),
    "twilio_account_sid": (["AC" + "a" * 32], ["BC" + "a" * 32]),
    "twilio_auth_token": (["twilio_auth_token=" + "a" * 32], ["twilio_auth_token=short"]),
    "sendgrid_key": (["SG." + "a" * 22 + "." + "b" * 43], ["SG.tooshort.alsoShort"]),
    "mailgun_key": (["key-" + "a1b2c3d4" * 4], ["key-short"]),
    # ── AI / ML ─────────────────────────────────────────────────────────────
    "openai_key": (["sk-" + "a" * 32, "sk-proj-" + "b" * 32], ["sk-short"]),
    "anthropic_key": (["sk-ant-" + "a" * 30], ["sk-ant-short"]),
    "huggingface_token": (["hf_" + "a" * 34], ["hf_tooshort"]),
    "cohere_key": (["cohere_api_key=" + "a" * 40], ["cohere_api_key=short"]),
    "replicate_key": (["r8_" + "a" * 40], ["r8_short"]),
    # ── Database DSNs ───────────────────────────────────────────────────────
    "postgres_dsn": (["postgresql://user:pass@host:5432/db"], ["postgresql://host/db"]),
    "mysql_dsn": (["mysql://user:pass@host:3306/db"], ["mysql://host/db"]),
    "mongodb_dsn": (["mongodb+srv://user:pass@cluster.mongodb.net"], ["mongodb://host"]),
    "redis_dsn": (["redis://user:pass@host:6379"], ["redis://host:6379"]),
    "elasticsearch_dsn": (["https://user:pass@es-host:9200"], ["https://es-host:9200"]),
    "sqlserver_dsn": (
        ["Server=tcp:host,1433;Database=db;User Id=sa;Password=secret;"],
        ["Server=tcp:host,1433;Database=db;"],
    ),
    # ── Generic secrets ─────────────────────────────────────────────────────
    "api_key": (
        ["sk_" + "a" * 16, 'api_key="' + "a" * 20 + '"', "apikey=" + "b" * 16],
        ["api_key=short", "just a sentence with sixteen letters here"],
    ),
    "generic_secret": (['password="hunter2hunter2"'], ["password=unquotedvalue"]),
    "private_key_block": (["-----BEGIN RSA PRIVATE KEY-----"], ["-----BEGIN RSA PUBLIC KEY-----"]),
    "certificate_block": (["-----BEGIN CERTIFICATE-----"], ["-----BEGIN PUBLIC KEY-----"]),
    "pgp_private": (["-----BEGIN PGP PRIVATE KEY BLOCK-----"], ["-----BEGIN PGP PUBLIC KEY-----"]),
    "bearer_token": (["Authorization: Bearer abc123.def456"], ["Authorization: Basic abc"]),
    "jwt_token": (
        ["eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12],
        ["eyJshort.abc"],
    ),
    "basic_auth_url": (["https://user:pass@example.com"], ["https://example.com"]),
    "env_secret": (["API_TOKEN=supersecretvalue", "export DB_PASSWORD=hunter2"], ["NAME=alice"]),
    # ── Infrastructure as Code ──────────────────────────────────────────────
    "terraform_state_secret": (
        ['"sensitive_attributes": ["password"]'],
        ['"sensitive_attributes": []'],
    ),
    "docker_auth": (['"auth": "' + "a" * 24 + '"'], ['"auth": "short"']),
    "k8s_secret_data": (
        ["kind: Secret\nmetadata:\n  name: db\ndata:\n  password: " + "a" * 12 + "\n"],
        ["kind: ConfigMap\ndata:\n  key: value\n"],
    ),
    # ── PII ─────────────────────────────────────────────────────────────────
    "email": (["user@example.com", "jane.doe+tag@corp.co.uk"], ["notanemail", "missing@"]),
    "phone": (["+1 (555) 123-4567", "555-123-4567"], ["12345"]),
    "ssn": (["123-45-6789"], ["000-12-3456", "123-456-789"]),
    "passport": (["passport: AB1234567"], ["AB1234567"]),
    # ── Healthcare ──────────────────────────────────────────────────────────
    "npi_number": (["NPI: 1234567890", "provider 1234567890 (NPI)"], ["1234567890"]),
    # AB1234563 has a valid DEA checksum; AB1234567 fits the shape but fails it.
    "dea_number": (["AB1234563"], ["A1234567", "AB1234567"]),
    "icd10_code": (["ICD-10: E11.9", "icd10 J45"], ["E11.9"]),
    # ── Crypto / Web3 ─────────────────────────────────────────────────────────
    # Must have an "eth/private key =" context; a bare 0x<64hex> no longer matches.
    "ethereum_private_key": (
        ["eth_private_key=0x" + "a" * 64, "private key: 0x" + "b" * 64],
        ["0xshort", "0x" + "a" * 64],
    ),
    "bitcoin_private_key_wif": (["5" + "K" * 51], ["5short"]),
    "mnemonic_phrase": (["abandon ability able about above absent zone"], ["just normal words"]),
}


def _fires(name: str, sample: str) -> bool:
    """True if the detector produces a finding — pattern match that also passes
    any checksum validator (Luhn, DEA)."""
    d = DETECTOR_MAP[name]
    for m in d.pattern.finditer(sample):
        if d.validator is None or d.validator(m.group(0)):
            return True
    return False


@pytest.mark.parametrize("name", sorted(_CASES))
def test_detector_positive_samples(name):
    positives, _ = _CASES[name]
    for sample in positives:
        assert _fires(name, sample), f"{name} failed to match: {sample!r}"


@pytest.mark.parametrize("name", sorted(_CASES))
def test_detector_negative_samples(name):
    _, negatives = _CASES[name]
    for sample in negatives:
        assert not _fires(name, sample), f"{name} false-positive on: {sample!r}"


def test_every_detector_is_covered():
    """Every built-in detector must have a test case (no silent gaps)."""
    covered = set(_CASES)
    actual = {d.name for d in DETECTORS}
    missing = sorted(actual - covered)
    extra = sorted(covered - actual)
    assert not missing, f"detectors with no test case: {missing}"
    assert not extra, f"test cases for missing detectors: {extra}"


def test_detector_count_is_sixty():
    assert len(DETECTORS) == 60


def test_detector_names_unique():
    names = [d.name for d in DETECTORS]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# stable_mask
# ---------------------------------------------------------------------------


def test_stable_mask_format():
    mask = stable_mask("aws_key", "AKIA1234567890ABCDEF")
    assert mask.startswith("<AWS_KEY_") and mask.endswith(">")


def test_stable_mask_deterministic():
    assert stable_mask("email", "a@b.com") == stable_mask("email", "a@b.com")


def test_stable_mask_distinct_values():
    assert stable_mask("email", "a@b.com") != stable_mask("email", "x@y.com")


# ---------------------------------------------------------------------------
# Checksum validators (precision fixes)
# ---------------------------------------------------------------------------


def test_luhn_rejects_invalid_credit_card():
    # Same shape as a Visa (starts with 4, 16 digits) but fails Luhn.
    pat = DETECTOR_MAP["credit_card"].pattern
    assert pat.search("4111111111111112")  # regex matches the shape
    from contextduty.detectors import _luhn_valid

    assert not _luhn_valid("4111111111111112")  # but Luhn rejects it
    assert _luhn_valid("4111111111111111")


def test_dea_checksum():
    from contextduty.detectors import _dea_valid

    assert _dea_valid("AB1234563")  # valid check digit
    assert not _dea_valid("AB1234567")  # wrong check digit


def test_engine_suppresses_luhn_invalid_card():
    from contextduty.engine import scan_text
    from contextduty.policy import Policy

    p = Policy(mode="warn", detectors={"credit_card"}, custom_detectors={})
    assert scan_text("card 4111111111111111", p).scan.findings_count == 1  # valid
    assert scan_text("id 4111111111111112", p).scan.findings_count == 0  # invalid Luhn
