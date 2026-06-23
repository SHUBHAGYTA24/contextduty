"""
ContextDuty — Live Demo
=======================
Shows the full protection pipeline for a developer using AI coding tools.

Scenario: A backend engineer debugging a production issue pastes code
containing API keys, database credentials, and customer PII into their
AI assistant. ContextDuty intercepts at every layer.

Run with:
    python demo/contextduty_demo.py
"""

from __future__ import annotations

import sys
import time


def _print(msg: str = "", color: str = "") -> None:
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    if not sys.stdout.isatty():
        print(msg)
        return
    print(f"{COLORS.get(color, '')}{msg}{COLORS['reset']}")


def _sep(title: str = "") -> None:
    width = 70
    if title:
        pad = (width - len(title) - 2) // 2
        _print(f"\n{'─' * pad} {title} {'─' * pad}", "dim")
    else:
        _print("─" * width, "dim")


def _pause(ms: int = 400) -> None:
    time.sleep(ms / 1000)


# ---------------------------------------------------------------------------
# Generic demo code snippet — realistic but not tied to any company
# ---------------------------------------------------------------------------

CODE_SNIPPET = '''\
# === Payment Service — Debug Session ===
# Investigating: webhook delivery failures in production
# Engineer: dev@example.com | Ticket: ENG-1042

import requests
import psycopg2

# Service credentials
PAYMENT_API_KEY    = "sk_live_9fX2mK8pL3nQ7wR4yT6uI0oA1b2c3d"
PAYMENT_API_SECRET = "zX1cV2bN3mQ4wE5rT6yU7iO8pA9sD0eF"
WEBHOOK_SECRET     = "whsec_K9mN2pL8qR3wT7yU4iO1aS5dF6g"

# Infrastructure
DB_URL  = "postgres://svc_app:p@ssw0rd_prod@prod-db.internal:5432/payments"
REDIS_URL = "redis://:r3d1sP@ss@cache.internal:6379/0"

# Customer record being investigated
CUSTOMER = {
    "name":  "Jane Smith",
    "email": "jane.smith@example.com",
    "phone": "+1-415-555-0199",
    "dob":   "1985-03-22",
    "ssn":   "123-45-6789",
    "card":  "4111-1111-1111-1111",
}

# Cloud credentials for log access
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
'''


def run_demo() -> None:
    _print()
    _print("╔══════════════════════════════════════════════════════════════════╗", "bold")
    _print("║              ContextDuty — AI Security Demo                     ║", "bold")
    _print("║         Local-First Prompt Firewall for AI Tools                ║", "bold")
    _print("╚══════════════════════════════════════════════════════════════════╝", "bold")
    _print()

    _sep("SCENARIO")
    _print("A backend engineer is debugging a production webhook failure.", "cyan")
    _print("They paste their debugging context into Cursor / Claude Code.", "cyan")
    _print("The context contains API keys, DB credentials, and customer PII.", "cyan")
    _pause(600)

    _sep("CODE THE ENGINEER WANTS TO SHARE WITH AI")
    _print(CODE_SNIPPET, "dim")
    _pause(800)

    # ── Layer 1: Pre-commit hook ──────────────────────────────────────────────
    _sep("LAYER 1 — Pre-Commit Hook")
    _print("$ git add payment_debug.py && git commit -m 'debug: webhook failure'", "yellow")
    _print()
    _print("🔍 [ContextDuty] Scanning payment_debug.py ...", "bold")
    _pause(500)

    precommit_findings = [
        ("email",      "dev@example.com",                "line 4"),
        ("api_key",    "sk_live_9fX2mK8pL3nQ7wR...",    "line 9"),
        ("api_key",    "zX1cV2bN3mQ4wE5rT6yU7i...",     "line 10"),
        ("api_key",    "whsec_K9mN2pL8qR3wT7yU...",      "line 11"),
        ("db_url",     "postgres://svc_app:p@ssw...",    "line 14"),
        ("db_url",     "redis://:r3d1sP@ss@cache...",    "line 15"),
        ("email",      "jane.smith@example.com",          "line 19"),
        ("phone",      "+1-415-555-0199",                 "line 20"),
        ("ssn",        "123-45-6789",                     "line 22"),
        ("credit_card","4111-1111-1111-1111",             "line 23"),
        ("aws_key",    "AKIAIOSFODNN7EXAMPLE",            "line 27"),
        ("aws_secret", "wJalrXUtnFEMI/K7MDENG/...",      "line 28"),
    ]

    for detector, value, loc in precommit_findings:
        _pause(70)
        _print(f"  ⚠️  [{detector:12s}] {value:38s} @ {loc}", "red")

    _print()
    _print("❌ BLOCKED — 12 finding(s). Commit rejected.", "red")
    _print(
        "   Fix: contextduty redact --in payment_debug.py --out payment_debug.py",
        "yellow",
    )
    _pause(800)

    # ── Layer 2: HTTPS Proxy ─────────────────────────────────────────────────
    _sep("LAYER 2 — HTTPS Proxy (Cursor / Claude Code / ChatGPT)")
    _print("Engineer skips commit and pastes directly into their AI tool.", "cyan")
    _print("ContextDuty's local proxy intercepts the outbound request.", "cyan")
    _pause(500)
    _print()
    _print("🔒 [ContextDuty Proxy] Intercepting → api.anthropic.com", "bold")
    _print("   Scanning prompt body (2,341 tokens) ...")
    _pause(600)
    _print("   12 patterns detected. Applying deterministic redaction ...")
    _pause(400)
    _print()
    _print("✅ What the AI model actually receives:", "green")
    _print()
    _print(
        "   PAYMENT_API_KEY    = '[REDACTED:api_key:a3f7]'\n"
        "   PAYMENT_API_SECRET = '[REDACTED:api_key:b1e9]'\n"
        "   WEBHOOK_SECRET     = '[REDACTED:api_key:c2d4]'\n"
        "   DB_URL  = 'postgres://[REDACTED:db_url:d5f6]'\n"
        "   email:  '[REDACTED:email:e7a1]'\n"
        "   ssn:    '[REDACTED:ssn:f8b2]'\n"
        "   card:   '[REDACTED:credit_card:g9c3]'\n"
        "   AWS_ACCESS_KEY_ID = '[REDACTED:aws_key:h0d4]'",
        "green",
    )
    _pause(500)
    _print()
    _print("💡 AI sees the code structure and helps debug — secrets stay local.", "bold")
    _pause(800)

    # ── Layer 3: NLP (Presidio) ───────────────────────────────────────────────
    _sep("LAYER 3 — NLP Detection (Presidio Backend)")
    _print("Catches PII that regex misses: names, dates, context-dependent data.", "cyan")
    _pause(400)
    _print()
    _print("$ contextduty scan payment_debug.py --nlp --nlp-backend presidio", "yellow")
    _print()
    _print("🧠 NLP-detected PII (backend: presidio):", "bold")
    _pause(300)

    nlp_findings = [
        ("nlp_person",   "Jane Smith",              0.93),
        ("nlp_email",    "jane.smith@example.com",  0.97),
        ("nlp_phone",    "+1-415-555-0199",          0.85),
        ("nlp_datetime", "1985-03-22",               0.74),
        ("nlp_credit_card", "4111-1111-1111-1111",  0.99),
    ]
    for name, value, conf in nlp_findings:
        _pause(90)
        _print(
            f"  • {name:18s}: {value:32s} [confidence: {conf:.2f}]",
            "green",
        )

    _print()
    _print("  5 NLP finding(s), 1 suppressed by context scoring", "dim")
    _pause(800)

    # ── Layer 4: Audit Dashboard ──────────────────────────────────────────────
    _sep("LAYER 4 — Audit Dashboard")
    _print("Security team opens the real-time dashboard: http://localhost:7042", "cyan")
    _print()
    _print("  📊 Today's Summary:", "bold")
    _pause(300)
    _print("     Files scanned:        31")
    _print("     Total findings:      247")
    _print("     Secrets intercepted:  12  (this session)")
    _print("     Top detector:         api_key  (78 hits)")
    _print("     PII blocked from AI:   7  (this session)")
    _print("     Sensitive data to AI:  0 bytes")
    _pause(800)

    # ── Impact ────────────────────────────────────────────────────────────────
    _sep("IMPACT")
    _print()
    _print("  WITHOUT ContextDuty:", "red")
    _print("  • API keys sent to 3rd-party AI provider's servers", "red")
    _print("  • Customer PII (name, SSN, card) in AI request logs", "red")
    _print("  • DB passwords potentially indexed in model training", "red")
    _print("  • GDPR / HIPAA / PCI violation on every AI query", "red")
    _print()
    _print("  WITH ContextDuty:", "green")
    _print("  • Zero sensitive data left the developer's machine", "green")
    _print("  • AI still helped — structure preserved, secrets masked", "green")
    _print("  • Full JSONL audit trail for compliance teams", "green")
    _print("  • No code change needed — works with any AI tool", "green")
    _print()

    _sep()
    _print()
    _print("  🔐 ContextDuty — AI Security. Local First. Zero Trust.", "bold")
    _print("     pip install contextduty[presidio]", "dim")
    _print("     github.com/SHUBHAGYTA24/contextduty", "dim")
    _print()


if __name__ == "__main__":
    run_demo()
