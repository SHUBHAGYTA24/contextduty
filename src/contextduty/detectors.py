"""Built-in detectors for secrets and PII."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern[str]


DETECTORS: list[Detector] = [
    # ── PII ──────────────────────────────────────────────────────────────────
    Detector("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector(
        "phone",
        re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    ),
    # ── Generic API / bearer tokens ──────────────────────────────────────────
    # Catches Stripe (sk_live_, rk_, pk_), generic service keys with _ separator
    Detector("api_key", re.compile(r"\b(?:sk|rk|pk)_[A-Za-z0-9_]{16,}\b")),
    Detector("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE)),
    # ── AWS ──────────────────────────────────────────────────────────────────
    Detector("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # AWS secret access key (bare 40-char base64, must follow a context keyword)
    Detector(
        "aws_secret",
        re.compile(
            r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*"
            r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
    ),
    # ── GCP ──────────────────────────────────────────────────────────────────
    Detector(
        "gcp_service_account",
        re.compile(r'"type"\s*:\s*"service_account"'),
    ),
    # ── GitHub ───────────────────────────────────────────────────────────────
    Detector(
        "github_pat",
        re.compile(
            r"\b(?:"
            r"ghp_[A-Za-z0-9]{36}"  # classic personal access token
            r"|gho_[A-Za-z0-9]{36}"  # OAuth token
            r"|ghu_[A-Za-z0-9]{36}"  # user-to-server token
            r"|ghs_[A-Za-z0-9]{36}"  # server-to-server token
            r"|ghr_[A-Za-z0-9]{36}"  # refresh token
            r"|github_pat_[A-Za-z0-9_]{82}"  # fine-grained PAT
            r")\b"
        ),
    ),
    # ── AI / ML service keys ─────────────────────────────────────────────────
    Detector(
        "openai_key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
    ),
    Detector(
        "anthropic_key",
        re.compile(r"\bsk-ant-[a-zA-Z0-9\-_]{20,}\b"),
    ),
    Detector(
        "huggingface_token",
        re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
    ),
    # ── Communication platforms ───────────────────────────────────────────────
    Detector(
        "slack_token",
        re.compile(
            r"\b(?:"
            r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}"  # bot token
            r"|xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32}"  # user token
            r"|xoxa-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32}"  # legacy auth
            r"|xoxs-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32}"  # session
            r"|xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{13}-[a-f0-9]{64}"  # app-level
            r")\b"
        ),
    ),
    # ── Payment platforms ─────────────────────────────────────────────────────
    Detector(
        "stripe_webhook",
        re.compile(r"\bwhsec_[a-zA-Z0-9]{32,}\b"),
    ),
    # ── Email / marketing ─────────────────────────────────────────────────────
    Detector(
        "sendgrid_key",
        re.compile(r"\bSG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\b"),
    ),
    Detector(
        "mailchimp_key",
        re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
    ),
    # ── Package registries ────────────────────────────────────────────────────
    Detector(
        "npm_token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    # ── Twilio ────────────────────────────────────────────────────────────────
    Detector(
        "twilio_sid",
        re.compile(r"\bAC[a-fA-F0-9]{32}\b"),
    ),
    # ── Azure ─────────────────────────────────────────────────────────────────
    Detector(
        "azure_storage_key",
        re.compile(
            r"DefaultEndpointsProtocol=https;AccountName=[^;]{3,};AccountKey=[A-Za-z0-9+/]{86}==;"
        ),
    ),
    # ── Database connection strings ───────────────────────────────────────────
    Detector(
        "db_dsn",
        re.compile(
            r"\b(?:postgres(?:ql?)?|mysql(?:\+[a-z]+)?|mongodb(?:\+srv)?|redis(?:s)?|mssql(?:\+[a-z]+)?)"
            r"://[^:\s@]{1,64}:[^@\s]{1,128}@[^\s'\">]{4,}\b",
            re.IGNORECASE,
        ),
    ),
    # ── Cryptographic material ────────────────────────────────────────────────
    Detector(
        "ssh_private_key",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    Detector(
        "pgp_private_key",
        re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ),
    # Generic PKCS#8 / PKCS#1 PEM private key not covered by the specific patterns above
    Detector(
        "private_key_pem",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
    ),
    # ── Google OAuth access token ─────────────────────────────────────────────
    Detector(
        "google_oauth_token",
        re.compile(r"\bya29\.[A-Za-z0-9\-_]{60,}\b"),
    ),
    # ── JWT ───────────────────────────────────────────────────────────────────
    # eyJ prefix = base64url-encoded JSON header, followed by two more segments
    Detector(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
    # ── .env / config file secrets ────────────────────────────────────────────
    # Catches KEY=value or KEY="value" patterns for common secret variable names
    Detector(
        "env_secret",
        re.compile(
            r"(?i)(?:^|[\s;])"
            r"(?:PASSWORD|PASSWD|DB_PASS|DB_PASSWORD|SECRET(?:_KEY)?|TOKEN"
            r"|API_KEY|API_SECRET|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY"
            r"|CLIENT_SECRET|MASTER_KEY|ENCRYPTION_KEY)"
            r"\s*=\s*['\"]?[A-Za-z0-9\-_@#$%^&*]{8,}['\"]?",
            re.MULTILINE,
        ),
    ),
]


def stable_mask(detector_name: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"<{detector_name.upper()}_{digest}>"
