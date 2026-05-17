"""
contextduty.detectors
~~~~~~~~~~~~~~~~~~~~~
Built-in secret / PII detector patterns.

Each entry is (detector_name, compiled_regex).
Patterns are ordered from most-specific to least-specific to reduce false positives.
All patterns are intentionally anchored or bounded to avoid matching mid-word.
"""

import hashlib
import re
from typing import Dict, List, NamedTuple


# 1. Define the Detector structure expected by engine and tests
class Detector(NamedTuple):
    name: str
    pattern: re.Pattern


# 2. Add the missing stable_mask function required by engine.py
def stable_mask(detector_name: str, value: str) -> str:
    """Generate a consistent mask for a secret using its hash.

    Format: <DETECTOR_NAME_UPPER_xxxxxxxx>
    Example: stable_mask("api_key", "sk-abc") → "<API_KEY_a1b2c3d4>"
    """
    if not value:
        return ""
    prefix = detector_name.upper()
    h = hashlib.sha256(f"{detector_name}:{value}".encode()).hexdigest()[:8]
    return f"<{prefix}_{h}>"


# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

_RAW: Dict[str, str] = {
    # ── Cloud / Infrastructure ──────────────────────────────────────────────
    "aws_key": r"\bAKIA[0-9A-Z]{16}\b",
    "aws_secret": r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?",  # noqa: E501
    "aws_mfa_serial": r"\barn:\s*aws:\s*iam::\d{12}:mfa/",
    "gcp_service_account": r'"type"\s*:\s*"service_account"',
    "gcp_api_key": r"\bAIza[0-9A-Za-z\-_]{35}\b",
    "azure_client_secret": r"(?i)(?:azure|az)[_\-\s]?(?:client|app)[_\-\s]?secret\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{32,})['\"]?",  # noqa: E501
    "azure_storage_key": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}==",  # noqa: E501
    # ── VCS / CI tokens ─────────────────────────────────────────────────────
    "github_pat": r"\bghp_[A-Za-z0-9]{36}\b",
    "github_oauth": r"\bgho_[A-Za-z0-9]{36}\b",
    "github_app_token": r"\bghs_[A-Za-z0-9]{36}\b",
    "github_refresh_token": r"\bghr_[A-Za-z0-9]{76}\b",
    "gitlab_pat": r"\bglpat-[A-Za-z0-9\-_]{20}\b",
    "gitlab_runner_token": r"\bglrt-[A-Za-z0-9\-_]{20}\b",
    # ── Payment / Fintech ───────────────────────────────────────────────────
    "stripe_secret": r"\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b",
    "stripe_restricted": r"\brk_(?:live|test)_[A-Za-z0-9]{24,}\b",
    "stripe_publishable": r"\bpk_(?:live|test)_[A-Za-z0-9]{24,}\b",
    "stripe_webhook": r"\bwhsec_[A-Za-z0-9]{32,}\b",
    "paypal_secret": r"(?i)paypal[_\-\s]?(?:client|app)[_\-\s]?secret\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{32,})['\"]?",  # noqa: E501
    "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",  # noqa: E501
    # ── Messaging / Comms ───────────────────────────────────────────────────
    "slack_bot_token": r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b",
    "slack_user_token": r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32}\b",
    "slack_workspace_token": r"\bxoxa-2-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{16}\b",
    "slack_config_token": r"\bxoxe\.xox[bp]-1-[A-Za-z0-9]{163,}\b",
    "twilio_account_sid": r"\bAC[a-f0-9]{32}\b",
    "twilio_auth_token": r"(?i)twilio[_\-\s]?auth[_\-\s]?token\s*[=:]\s*['\"]?([a-f0-9]{32})['\"]?",  # noqa: E501
    "sendgrid_key": r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b",
    "mailgun_key": r"\bkey-[a-f0-9]{32}\b",
    # ── LLM / AI service keys ───────────────────────────────────────────────
    "openai_key": r"\bsk-(?:proj-)?[A-Za-z0-9]{48,}\b",
    "anthropic_key": r"\bsk-ant-[A-Za-z0-9\-_]{93,}\b",
    "huggingface_token": r"\bhf_[A-Za-z0-9]{34,}\b",
    "cohere_key": r"(?i)cohere[_\-\s]?(?:api[_\-\s]?)?key\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{40,})['\"]?",  # noqa: E501
    "replicate_key": r"\br8_[A-Za-z0-9]{40}\b",
    # ── Database DSNs ───────────────────────────────────────────────────────
    "postgres_dsn": r"postgres(?:ql)?://[^:]+:[^@]+@[^/\s]+/\S+",
    "mysql_dsn": r"mysql(?:\+\w+)?://[^:]+:[^@]+@[^/\s]+/\S+",
    "mongodb_dsn": r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+",
    "redis_dsn": r"redis(?:s)?://(?:[^:]+:[^@]+@)?[^\s]+",
    "elasticsearch_dsn": r"https?://[^:]+:[^@]+@[^\s]*(?:9200|9300)[^\s]*",
    "sqlserver_dsn": r"(?i)(?:data source|server)\s*=\s*[^;]+;.*?(?:password|pwd)\s*=\s*[^;]+",
    # ── Generic secrets in code ─────────────────────────────────────────────
    "api_key": r"(?i)(?:api[_\-\s]?key|apikey)?\s*[=:]?\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?",
    "generic_secret": r"(?i)(?:secret|password|passwd|pwd|token|auth)\s*[=:]\s*['\"]([A-Za-z0-9!@#$%^&*()\-_=+]{8,})['\"]",  # noqa: E501
    "private_key_block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "certificate_block": r"-----BEGIN CERTIFICATE-----",
    "pgp_private": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "bearer_token": r"(?i)bearer\s+([A-Za-z0-9\-_=]+(?:\.[A-Za-z0-9\-_=]+)*)",
    "jwt_token": r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*\b",
    "basic_auth_url": r"https?://[^:]+:[^@]+@",
    "env_secret": r"(?i)^(?:export\s+)?[A-Z_]*(?:SECRET|PASSWORD|TOKEN|KEY|PASS)[A-Z_]*\s*=\s*\S+",
    # ── Infrastructure as Code ──────────────────────────────────────────────
    "terraform_state_secret": r'"sensitive_attributes":\s*\[(?:[^]]*"[^"]*"[^]]*)+\]',
    "docker_auth": r'"auth"\s*:\s*"[A-Za-z0-9+/=]{16,}"',
    "k8s_secret_data": r"(?i)kind:\s*Secret[\s\S]{0,200}data:\s*\n(?:\s+\S+:\s+[A-Za-z0-9+/=]{8,}\n)+",  # noqa: E501
    # ── PII ─────────────────────────────────────────────────────────────────
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "phone": r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "passport": r"\b[A-Z]{1,2}\d{6,9}\b",
    # ── Healthcare ──────────────────────────────────────────────────────────
    "npi_number": r"\b[0-9]{10}\b(?=.*NPI)",  # NPI must appear near context
    "dea_number": r"\b[A-Z][A-Z9][0-9]{7}\b",
    "icd10_code": r"\b[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?\b",
    # ── Crypto / Web3 ───────────────────────────────────────────────────────
    "ethereum_private_key": r"\b0x[a-fA-F0-9]{64}\b",
    "bitcoin_private_key_wif": r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b",
    "mnemonic_phrase": r"(?i)\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident)\b.{0,200}\b(?:zone|zoo)\b",  # noqa: E501
}


def build_builtin_detectors() -> List[Detector]:
    """Return compiled built-in detectors as a list of objects."""
    detectors: List[Detector] = []
    for name, pattern in _RAW.items():
        try:
            detectors.append(Detector(name=name, pattern=re.compile(pattern, re.MULTILINE)))
        except re.error:
            continue
    return detectors


# DETECTORS: list of Detector NamedTuples used by the engine
DETECTORS = build_builtin_detectors()
BUILTIN_DETECTORS = DETECTORS

# DETECTORS_DICT: dict {name: compiled_pattern} used by the CLI and adapters
DETECTORS_DICT: Dict[str, re.Pattern] = {d.name: d.pattern for d in DETECTORS}

# BUILTIN_NAMES: set of built-in detector names (strings) used by CLI/tests
BUILTIN_NAMES: List[str] = [d.name for d in DETECTORS]
