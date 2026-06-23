"""
ContextDuty — Live Demo: Coinbase Engineer Scenario
====================================================
Simulates a real-world scenario where a backend engineer at a crypto
company accidentally exposes secrets, PII, and wallet addresses in
their AI-assisted coding workflow.

Run with:
    python demo/coinbase_demo.py
"""

from __future__ import annotations

import sys
import time


def _print(msg: str = "", color: str = "") -> None:
    COLORS = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "reset": "\033[0m",
    }
    if not sys.stdout.isatty():
        print(msg)
        return
    print(f"{COLORS.get(color,'')}{msg}{COLORS['reset']}")


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
# Demo data — realistic Coinbase engineer context
# ---------------------------------------------------------------------------

COINBASE_CODE_SNIPPET = '''
# === CoinbasePro Trading Service — Debug Session ===
# Investigating: order execution timeout on high-volume trades
# Engineer: alex.chen@coinbase.com | Ticket: ENG-48291

import coinbasepro
import psycopg2

# Production API credentials — rotating after this debug session
CBPRO_API_KEY    = "sk_live_9fX2mK8pL3nQ7wR4yT6uI0oA1b2c3d"
CBPRO_API_SECRET = "zX1cV2bN3mQ4wE5rT6yU7iO8pA9sD0eF"
CBPRO_PASSPHRASE = "C0inb@se2024!trading"

# Internal infrastructure
DB_URL = "postgres://svc_trading:p@ssw0rd_prod_99@prod-db.coinbase.internal:5432/orders"
INTERNAL_API = "https://internal-trading-api.coinbase.com/v2"

# Customer account being debugged (with consent)
CUSTOMER = {
    "email": "satoshi.nakamoto@gmail.com",
    "ssn_last4": "6789",
    "wallet_btc": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
    "wallet_eth": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
    "phone": "+1-415-555-0123",
    "dob": "1975-04-05",
}

# AWS credentials for CloudWatch log access
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

client = coinbasepro.AuthenticatedClient(
    CBPRO_API_KEY, CBPRO_API_SECRET, CBPRO_PASSPHRASE
)
'''

WHAT_AI_GETS_WITHOUT_CONTEXTDUTY = """
WITHOUT ContextDuty, the developer pastes this into Cursor/Claude Code.
Every secret above is now in Anthropic's API request, logged, and potentially
stored in training data. The engineer doesn't even notice — they just want
help debugging an order timeout.
"""


def run_demo() -> None:
    _print()
    _print("╔══════════════════════════════════════════════════════════════════╗", "bold")
    _print("║         ContextDuty — AI Security Demo: Coinbase Scenario       ║", "bold")
    _print("╚══════════════════════════════════════════════════════════════════╝", "bold")
    _print()

    _sep("SCENARIO")
    _print("A Coinbase backend engineer is debugging an order timeout bug.", "cyan")
    _print("They paste their code context into Cursor (powered by Claude).", "cyan")
    _print("The context contains production secrets, PII, and crypto wallets.", "cyan")
    _pause(600)

    _sep("WHAT THE ENGINEER PASTES")
    _print(COINBASE_CODE_SNIPPET, "dim")
    _pause(800)

    _sep("STEP 1: ContextDuty Pre-Commit Hook Fires")
    _print("$ git add trading_debug.py && git commit -m 'debug: order timeout'", "yellow")
    _print()
    _print("🔍 [ContextDuty] Scanning trading_debug.py...", "bold")
    _pause(500)

    findings_precommit = [
        ("email",         "alex.chen@coinbase.com",         "line 5"),
        ("api_key",       "sk_live_9fX2mK8pL3nQ7wR...",    "line 9"),
        ("api_key",       "zX1cV2bN3mQ4wE5rT6yU7i...",    "line 10"),
        ("password",      "C0inb@se2024!trading",           "line 11"),
        ("db_url",        "postgres://svc_trading:p@ssw...", "line 14"),
        ("aws_key",       "AKIAIOSFODNN7EXAMPLE",           "line 27"),
        ("aws_secret",    "wJalrXUtnFEMI/K7MDENG/...",     "line 28"),
        ("email",         "satoshi.nakamoto@gmail.com",     "line 20"),
        ("phone",         "+1-415-555-0123",                "line 24"),
        ("crypto_btc",    "1A1zP1eP5QGefi2DMPTfTL5...",   "line 21"),
        ("crypto_eth",    "0xde0B295669a9FD93d5F28D...",   "line 22"),
    ]

    for detector, value, loc in findings_precommit:
        _pause(80)
        _print(f"  ⚠️  [{detector:12s}] {value:40s} @ {loc}", "red")

    _print()
    _print(f"❌ BLOCKED — 11 finding(s) detected. Commit rejected.", "red")
    _print("   Fix: run `contextduty redact --in trading_debug.py --out trading_debug.py`", "yellow")
    _pause(800)

    _sep("STEP 2: ContextDuty HTTPS Proxy (Cursor / Claude Code)")
    _print("Developer bypasses commit, pastes directly into Cursor chat.", "cyan")
    _print("ContextDuty's HTTPS proxy intercepts the outbound API request...", "cyan")
    _pause(500)
    _print()
    _print("🔒 [ContextDuty Proxy] Intercepting request to api.anthropic.com", "bold")
    _print("   → Scanning prompt body (2,847 tokens)...")
    _pause(600)
    _print("   → 11 patterns detected. Applying redaction...")
    _pause(400)
    _print()
    _print("✅ REDACTED PROMPT sent to Anthropic (what Claude actually sees):", "green")
    _print()
    _print(
        "   CBPRO_API_KEY    = '[REDACTED:api_key:a3f7]'\n"
        "   CBPRO_API_SECRET = '[REDACTED:api_key:b1e9]'\n"
        "   CBPRO_PASSPHRASE = '[REDACTED:password:c2d4]'\n"
        "   DB_URL = 'postgres://[REDACTED:db_url:d5f6]'\n"
        "   email: '[REDACTED:email:e7a1]'\n"
        "   wallet_btc: '[REDACTED:crypto:f8b2]'\n"
        "   AWS_ACCESS_KEY_ID = '[REDACTED:aws_key:g9c3]'",
        "green"
    )
    _pause(600)
    _print()
    _print("💡 Claude sees the structure and helps debug — but NEVER sees the secrets.", "bold")
    _pause(800)

    _sep("STEP 3: Audit Dashboard")
    _print("CISO opens the ContextDuty dashboard: http://localhost:7042", "cyan")
    _print()
    _print("  📊 Today's AI Security Summary (alex.chen@coinbase.com):", "bold")
    _pause(300)
    _print("     Scans today:          47")
    _print("     Findings blocked:    183")
    _print("     Top detector:        api_key (61 hits)")
    _print("     Secrets intercepted: 11 (this session)")
    _print("     Data sent to AI:     0 bytes of sensitive data")
    _pause(800)

    _sep("STEP 4: NLP-based PII (Presidio Backend)")
    _print("Even without explicit patterns, ContextDuty catches contextual PII:", "cyan")
    _pause(400)
    _print()
    _print("$ contextduty scan trading_debug.py --nlp --nlp-backend presidio", "yellow")
    _print()
    _print("🧠 NLP-detected PII (backend: presidio):", "bold")
    _pause(300)
    nlp_findings = [
        ("nlp_person",   "Satoshi Nakamoto",  0.91),
        ("nlp_email",    "satoshi.nakamoto@gmail.com", 0.97),
        ("nlp_phone",    "+1-415-555-0123",   0.85),
        ("nlp_datetime", "1975-04-05",         0.72),
        ("nlp_crypto",   "1A1zP1eP5QGefi2D...", 0.95),
    ]
    for name, value, conf in nlp_findings:
        _pause(100)
        _print(f"  • {name:15s}: {value:35s} [confidence: {conf:.2f}]", "green")

    _print()
    _print("  5 NLP finding(s), 2 suppressed by context scoring", "dim")
    _pause(800)

    _sep("IMPACT")
    _print()
    _print("  WITHOUT ContextDuty:", "red")
    _print("  • Production API keys → Anthropic's training pipeline", "red")
    _print("  • Customer PII (KYC data) → 3rd-party AI vendor", "red")
    _print("  • Crypto wallet addresses → AI logs (GDPR violation)", "red")
    _print("  • AWS keys → potentially indexed in model weights", "red")
    _print()
    _print("  WITH ContextDuty:", "green")
    _print("  • Zero sensitive data left the developer's machine", "green")
    _print("  • AI still helped debug the timeout — just with redacted context", "green")
    _print("  • Full audit trail for compliance team (JSONL log)", "green")
    _print("  • No code change required by the engineer", "green")
    _print()

    _sep()
    _print()
    _print("  🔐 ContextDuty — AI Security. Local First. Zero Trust.", "bold")
    _print("     pip install contextduty[presidio]", "dim")
    _print("     github.com/SHUBHAGYTA24/contextduty", "dim")
    _print()


if __name__ == "__main__":
    run_demo()
