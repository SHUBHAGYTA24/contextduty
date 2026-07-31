"""Built-in detectors for secrets and PII.

Each detector is a named, compiled regex applied line-by-line by the scan
engine.  Patterns are intentionally bounded (anchored, length-limited, or
context-gated) to keep precision high — a detector that fires on ordinary
identifiers is worse than no detector at all because it trains users to
ignore findings.

The set is grouped by category below.  To add a detector, add one entry to
``_PATTERNS`` (and a matching row in the README detector table).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Detector:
    """A named regex pattern used by the scan engine.

    *name* identifies the finding type (e.g. ``"aws_key"``).
    *pattern* is a compiled regex applied line-by-line to source text.
    *validator*, if set, is called with the matched text; when it returns
    ``False`` the match is discarded. Used for checksum-verifiable formats
    (e.g. Luhn for credit cards) to suppress false positives on ordinary
    numbers that merely fit the shape.
    """

    name: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


# ---------------------------------------------------------------------------
# Checksum validators — applied after a regex match to cut false positives.
# ---------------------------------------------------------------------------


def _luhn_valid(value: str) -> bool:
    """Return True if the digits in *value* pass the Luhn checksum (credit cards)."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _dea_valid(value: str) -> bool:
    """Return True if *value* is a checksum-valid US DEA registration number.

    Format: two letters + seven digits; the 7th digit is a check digit equal to
    ``((d1+d3+d5) + 2*(d2+d4+d6)) mod 10``.
    """
    nums = [int(c) for c in value if c.isdigit()]
    if len(nums) != 7:
        return False
    check = (nums[0] + nums[2] + nums[4]) + 2 * (nums[1] + nums[3] + nums[5])
    return check % 10 == nums[6]


_VALIDATORS: dict[str, Callable[[str], bool]] = {
    "credit_card": _luhn_valid,
    "dea_number": _dea_valid,
}


# ---------------------------------------------------------------------------
# Pattern library — (name, regex, flags).  Compiled into DETECTORS below.
#
# Precision notes for the broad categories:
#   * api_key / generic_secret require an explicit key= context or a known
#     vendor prefix — never a bare alphanumeric run.
#   * passport / icd10_code / npi_number require a nearby context keyword so
#     they don't fire on ordinary identifiers.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, int]] = [
    # ── Cloud / Infrastructure ──────────────────────────────────────────────
    ("aws_key", r"\bAKIA[0-9A-Z]{16}\b", 0),
    (
        "aws_secret",
        r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9+/]{40})['\"]?",
        0,
    ),
    ("aws_mfa_serial", r"\barn:aws:iam::\d{12}:mfa/\S+", 0),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"', 0),
    ("gcp_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0),
    (
        "azure_client_secret",
        r"(?i)(?:azure|az)[_\-\s]?(?:client|app)[_\-\s]?secret\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9+/=_\-]{32,})['\"]?",
        0,
    ),
    (
        "azure_storage_key",
        r"DefaultEndpointsProtocol=https;AccountName=[^;]{1,64};"
        r"AccountKey=[A-Za-z0-9+/=]{86}==",
        0,
    ),
    # ── VCS / CI tokens ─────────────────────────────────────────────────────
    ("github_pat", r"\bghp_[A-Za-z0-9]{36}\b", 0),
    ("github_oauth", r"\bgho_[A-Za-z0-9]{36}\b", 0),
    ("github_app_token", r"\bghs_[A-Za-z0-9]{36}\b", 0),
    ("github_refresh_token", r"\bghr_[A-Za-z0-9]{36,76}\b", 0),
    ("gitlab_pat", r"\bglpat-[A-Za-z0-9\-_]{20}\b", 0),
    ("gitlab_runner_token", r"\bglrt-[A-Za-z0-9\-_]{20}\b", 0),
    # ── Payment / Fintech ───────────────────────────────────────────────────
    ("stripe_secret", r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b", 0),
    ("stripe_restricted", r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b", 0),
    ("stripe_publishable", r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b", 0),
    ("stripe_webhook", r"\bwhsec_[A-Za-z0-9]{32,}\b", 0),
    (
        "paypal_secret",
        r"(?i)paypal[_\-\s]?(?:client|app)[_\-\s]?secret\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9\-_]{32,})['\"]?",
        0,
    ),
    (
        "credit_card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?"  # Visa
        r"|5[1-5][0-9]{14}"  # Mastercard
        r"|3[47][0-9]{13}"  # Amex
        r"|6(?:011|5[0-9]{2})[0-9]{12})\b",  # Discover
        0,
    ),
    # ── Messaging / Comms ───────────────────────────────────────────────────
    ("slack_bot_token", r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b", 0),
    (
        "slack_user_token",
        r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b",
        0,
    ),
    (
        "slack_workspace_token",
        r"\bxoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{16}\b",
        0,
    ),
    ("slack_config_token", r"\bxoxe\.xox[bp]-1-[A-Za-z0-9]{100,}\b", 0),
    ("twilio_account_sid", r"\bAC[a-f0-9]{32}\b", 0),
    (
        "twilio_auth_token",
        r"(?i)twilio[_\-\s]?auth[_\-\s]?token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",
        0,
    ),
    ("sendgrid_key", r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b", 0),
    ("mailgun_key", r"\bkey-[a-f0-9]{32}\b", 0),
    # ── LLM / AI service keys ───────────────────────────────────────────────
    ("openai_key", r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b", 0),
    ("anthropic_key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", 0),
    ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b", 0),
    (
        "cohere_key",
        r"(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9\-_]{40,})['\"]?",
        0,
    ),
    ("replicate_key", r"\br8_[A-Za-z0-9]{40}\b", 0),
    # ── Database DSNs ───────────────────────────────────────────────────────
    ("postgres_dsn", r"postgres(?:ql)?://[^:\s]{1,64}:[^@\s]{1,128}@[^/\s]+/\S+", 0),
    ("mysql_dsn", r"mysql(?:\+\w+)?://[^:\s]{1,64}:[^@\s]{1,128}@[^/\s]+/\S+", 0),
    ("mongodb_dsn", r"mongodb(?:\+srv)?://[^:\s]{1,64}:[^@\s]{1,128}@[^\s]+", 0),
    ("redis_dsn", r"rediss?://(?:[^:\s]{1,64}:[^@\s]{1,128}@)[^\s]+", 0),
    (
        "elasticsearch_dsn",
        r"https?://[^:\s]{1,64}:[^@\s]{1,128}@[^\s]*(?:9200|9300)[^\s]*",
        0,
    ),
    (
        "sqlserver_dsn",
        r"(?i)(?:data source|server)\s*=\s*[^;]{1,128};"
        r".{0,200}?(?:password|pwd)\s*=\s*[^;\s]+",
        0,
    ),
    # ── Generic secrets in code ─────────────────────────────────────────────
    # api_key: a known vendor prefix OR an explicit api_key= assignment.
    (
        "api_key",
        r"\b(?:sk|rk|pk)_[A-Za-z0-9_]{16,}\b"
        r"|(?i:(?:api[_\-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{16,}['\"]?)",
        0,
    ),
    # generic_secret: keyword + quoted value (quotes required to avoid noise).
    (
        "generic_secret",
        r"(?i)(?:secret|password|passwd|pwd|token|auth)\s*[=:]\s*"
        r"['\"]([A-Za-z0-9!@#$%^&*()\-_=+]{8,})['\"]",
        0,
    ),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0),
    ("certificate_block", r"-----BEGIN CERTIFICATE-----", 0),
    ("pgp_private", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 0),
    (
        "bearer_token",
        r"(?i)bearer\s+([A-Za-z0-9\-_=]+(?:\.[A-Za-z0-9\-_=]+)*)",
        0,
    ),
    (
        "jwt_token",
        r"\beyJ[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_=]{10,}\.[A-Za-z0-9\-_.+/=]{10,}\b",
        0,
    ),
    ("basic_auth_url", r"https?://[^:\s/@]{1,64}:[^@\s/]{1,128}@", 0),
    (
        "env_secret",
        r"^(?:export\s+)?[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|PASS)[A-Z_]*\s*=\s*\S+",
        re.MULTILINE,
    ),
    # ── Infrastructure as Code ──────────────────────────────────────────────
    ("terraform_state_secret", r'"sensitive_attributes":\s*\[(?:[^\]]*"[^"]*"[^\]]*)+\]', 0),
    ("docker_auth", r'"auth"\s*:\s*"[A-Za-z0-9+/=]{16,}"', 0),
    (
        "k8s_secret_data",
        r"(?i)kind:\s*Secret[\s\S]{0,200}?data:\s*\n(?:\s+\S+:\s+[A-Za-z0-9+/=]{8,}\n?)+",
        0,
    ),
    # ── PII ─────────────────────────────────────────────────────────────────
    ("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0),
    (
        "phone",
        r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
        0,
    ),
    ("ssn", r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", 0),
    # passport: number must follow a "passport" context keyword.
    (
        "passport",
        r"(?i)passport\s*(?:no\.?|number|#)?\s*[:=]?\s*([A-Z]{1,2}\d{6,9})\b",
        0,
    ),
    # ── Healthcare ──────────────────────────────────────────────────────────
    # npi_number: a 10-digit number with "NPI" present on the same line.
    ("npi_number", r"(?i)\bnpi\b[^\n]{0,20}?\b\d{10}\b|\b\d{10}\b(?=[^\n]{0,20}?\bnpi\b)", 0),
    ("dea_number", r"\b[A-Z][A-Z9]\d{7}\b", 0),
    # icd10_code: code must follow an "ICD" / "ICD-10" context keyword.
    (
        "icd10_code",
        r"(?i)icd[-\s]?(?:10)?[\s:]{0,3}([A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?)\b",
        0,
    ),
    # ── Crypto / Web3 ───────────────────────────────────────────────────────
    # ethereum_private_key: require an "eth/private key =" context. The bare
    # 0x<64 hex> form was dropped — it fired on ordinary 32-byte hashes.
    (
        "ethereum_private_key",
        r"(?i)(?:eth|ethereum|private)[_\-\s]?key\s*[=:]\s*['\"]?(0x[a-fA-F0-9]{64})['\"]?",
        0,
    ),
    ("bitcoin_private_key_wif", r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b", 0),
    (
        "mnemonic_phrase",
        r"(?i)\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd"
        r"|abuse|access|accident)\b.{0,200}\b(?:zone|zoo)\b",
        0,
    ),
]


DETECTORS: list[Detector] = [
    Detector(name=name, pattern=re.compile(pattern, flags), validator=_VALIDATORS.get(name))
    for name, pattern, flags in _PATTERNS
]


def stable_mask(detector_name: str, value: str) -> str:
    """Return a deterministic redaction token for *value*.

    The same value always produces the same token across runs and machines
    (SHA-256, first 10 hex digits), enabling consistent de-duplication in diff
    output and audit trails.  Example: ``<AWS_KEY_3d4f9c1a2b>``.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"<{detector_name.upper()}_{digest}>"
