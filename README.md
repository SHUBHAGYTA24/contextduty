# ContextDuty

> **Stop secrets from reaching AI tools — before the prompt is assembled.**  
> Pre-commit hook. MCP interception. CI/CD enforcement. Local-first, zero dependencies.

[![PyPI version](https://img.shields.io/pypi/v/contextduty.svg)](https://pypi.org/project/contextduty/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml/badge.svg)](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)

---

## See it in 20 seconds

```
pip install contextduty
contextduty demo
```

```
▶ Scene 1 — Developer creates config.py with real credentials

  DATABASE_URL = "postgresql://admin:Sup3rS3cr3t!@prod-db.internal:5432/customers"
  AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
  OPENAI_API_KEY = "sk-proj-EXAMPLEcontextdutyDEMO..."
  STRIPE_SECRET_KEY = "sk_live_EXAMPLE..."

▶ Scene 2 — Scanning config.py

  {
    "findings_count": 6,
    "detector_counts": {
      "db_dsn": 1,
      "aws_key": 1,
      "aws_secret": 1,
      "openai_key": 1,
      "api_key": 1,
      "email": 1
    }
  }

▶ Scene 3 — Redacting config.py (safe to pass to AI)

  DATABASE_URL = "<DB_DSN_33213ab6f0>"
  AWS_ACCESS_KEY_ID     = "<AWS_KEY_1a5d44a2dc>"
  OPENAI_API_KEY = "<OPENAI_KEY_5f04681e46>"
  STRIPE_SECRET_KEY = "<API_KEY_242fa29ccc>"

✓ Real values replaced with deterministic masks — safe to paste into any AI tool

▶ Scene 4 — Pre-commit hook blocks the commit

  $ git add config.py && git commit -m 'add config'

  [ContextDuty] BLOCKED: config.py
    aws_key: 1 finding(s)
    openai_key: 1 finding(s)

  ╔══════════════════════════════════════════════════════════════╗
  ║  ContextDuty blocked this commit.                           ║
  ║  Sensitive values were found in staged files.               ║
  ╚══════════════════════════════════════════════════════════════╝

✓ Commit rejected — secrets never entered git history

▶ Scene 5 — Directory scan finds PII in test fixtures

  $ contextduty scan tests/

  {
    "findings_count": 4,
    "detector_counts": {"email": 3, "phone": 1},
    "files_scanned": 1
  }

⚠ 4 PII values found — if Cursor indexes this directory, all of it goes to OpenAI
```

---

## The problem it solves

Your developers use Cursor, GitHub Copilot, and Claude every day. These tools **automatically pull context** from your codebase — every open file, config, test fixture. No copy-paste required. The developer asks "why is this function slow?" and Cursor silently sends `config.py`, `.env.local`, and `tests/fixtures/customers.json` to OpenAI as context.

If those files contain secrets or customer data:

- The enterprise agreement with OpenAI says they won't **train** on your data. It says nothing about what happens if OpenAI is breached.
- HIPAA and PCI-DSS don't have a "we didn't know" exemption. The fine lands on you.
- There is zero audit trail. You cannot prove it happened or didn't happen.

ContextDuty intercepts at three layers **before** data reaches any AI tool.

---

## Install

```bash
pip install contextduty
```

---

## Layer 1 — Pre-commit hook

Scans every staged file before `git commit` completes. Blocks if secrets are found.

```bash
contextduty install-hooks
```

```
$ git add config.py
$ git commit -m "add deployment config"

[ContextDuty] BLOCKED: config.py
  aws_key: 1 finding(s)
  openai_key: 1 finding(s)
  → aws_key is set to block mode

╔══════════════════════════════════════════════════════════════╗
║  ContextDuty blocked this commit.                           ║
║  Remove or redact them before committing.                   ║
║  To redact: contextduty redact --in config.py --out config.py ║
╚══════════════════════════════════════════════════════════════╝
```

The secret never enters git history. Cursor can never index it. OpenAI can never receive it.

---

## Layer 2 — MCP interception (Cursor / Claude / VS Code)

ContextDuty runs as an MCP server. When an AI agent fetches a file or database result, ContextDuty intercepts the response and redacts it before the agent sees it.

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
```

Add to `~/.claude/claude_desktop_config.json` for Claude Desktop:

```json
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
```

The agent calls your tools. ContextDuty intercepts what they return:

```
Agent: read_file("customers.json")
Tool returns: {"name": "Jane Smith", "ssn": "123-45-6789", "email": "jane@example.com"}
ContextDuty intercepts →
Agent receives: {"name": "<PERSON_a3f2>", "ssn": "<SSN_b7c1>", "email": "<EMAIL_d4e5>"}
```

The real values never enter the prompt. Never reach OpenAI.

---

## Layer 3 — CI/CD (blocks merge if secrets slip through)

```yaml
# .github/workflows/contextduty.yml
- name: ContextDuty scan
  run: |
    pip install contextduty
    contextduty scan src/ --policy .contextduty.json
```

Add `"mode": "block"` to your policy and the pipeline exits non-zero on any finding. PR cannot merge.

---

## Scan and redact

```bash
# Scan a file — get a JSON findings report
contextduty scan config.py

# Scan an entire directory recursively
contextduty scan src/

# Redact a file — replace secrets with deterministic masks
contextduty redact --in config.py --out config.safe.py

# The same secret always gets the same mask — auditable, correlatable
# AKIAIOSFODNN7EXAMPLE → <AWS_KEY_1a5d44a2dc> (always, everywhere)
```

---

## Audit dashboard

```bash
contextduty dashboard --demo    # try it now with synthetic data
contextduty dashboard           # reads ~/.contextduty/audit.jsonl
```

![ContextDuty audit dashboard](demo/dashboard-preview.png)

Local web UI. Dark theme. Findings by detector, 30-day timeline, blocked commits tracker, developer activity table, CSV export. Zero dependencies, no external services. All data stays on your machine.

---

## Policy

Create `.contextduty.json` in your repo root:

```bash
contextduty init
```

```json
{
  "mode": "redact",
  "detectors": [
    "email", "phone",
    "aws_key", "aws_secret",
    "openai_key", "anthropic_key",
    "github_pat",
    "db_dsn", "bearer_token", "jwt",
    "stripe_webhook", "slack_token"
  ],
  "custom_detectors": {}
}
```

**Three modes:**

| Mode | What happens |
|---|---|
| `redact` | Replace matched values with deterministic masks |
| `warn` | Log findings, don't block, don't change content |
| `block` | Exit non-zero — use in CI or pre-commit to enforce hard stops |

**Per-detector modes** — e.g. block on API keys but warn on emails:

```json
{
  "mode": "warn",
  "detector_modes": {
    "aws_key": "block",
    "openai_key": "block",
    "anthropic_key": "block"
  }
}
```

**Custom detectors** — add your own regex, no code changes needed:

```json
{
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "patient_mrn": "\\bMRN-[0-9]{8}\\b"
  }
}
```

**Allow patterns** — whitelist known-safe values:

```json
{
  "allow_patterns": {
    "email": ["@example\\.com$", "@testdata\\.internal$"]
  }
}
```

**Policy layering** — team baseline + repo override:

```json
{
  "extends": "../../policies/org-baseline.json",
  "mode": "block",
  "detector_modes": {
    "email": "warn"
  }
}
```

---

## Detection coverage — 25 built-in detectors

| Category | Detectors |
|---|---|
| PII | `email`, `phone` |
| Generic tokens | `api_key`, `bearer_token` |
| Cloud | `aws_key`, `aws_secret`, `gcp_service_account`, `google_oauth_token` |
| VCS | `github_pat` |
| AI/ML services | `openai_key`, `anthropic_key`, `huggingface_token` |
| SaaS | `slack_token`, `stripe_webhook`, `sendgrid_key`, `mailchimp_key`, `npm_token`, `twilio_sid`, `azure_storage_key` |
| Databases | `db_dsn` (postgres, mysql, mongodb, redis — only when credentials embedded) |
| Crypto material | `ssh_private_key`, `pgp_private_key`, `private_key_pem`, `jwt`, `env_secret` |

Masks are **deterministic**: `AKIAIOSFODNN7EXAMPLE` always becomes `<AWS_KEY_1a5d44a2dc>` — same value, same mask, everywhere. Audit logs stay correlatable without ever storing raw secrets.

---

## Commands

| Command | Description |
|---|---|
| `contextduty demo` | Interactive 5-scene demo — see it catch secrets in real time |
| `contextduty scan <file\|dir>` | Scan file or directory, print JSON findings |
| `contextduty redact --in <f> --out <f>` | Redact file, write clean copy |
| `contextduty install-hooks` | Install pre-commit hook in current git repo |
| `contextduty uninstall-hooks` | Remove the hook |
| `contextduty dashboard [--demo]` | Open local audit dashboard in browser |
| `contextduty report --audit-log <f>` | Summarise an audit log |
| `contextduty policy validate` | Validate and resolve a layered policy file |
| `contextduty init` | Create default `.contextduty.json` |

---

## Why not LLM gateways or MCP gateways?

LLM gateways (Portkey, LiteLLM, Helicone) and MCP gateways intercept at the **inference call** — after the prompt has been assembled and sent over the wire. They cannot catch a secret already in git history, already in a staged file, or already assembled into a context window by Cursor.

ContextDuty enforces earlier, at the layers where leakage actually originates:

| Enforcement layer | LLM/MCP Gateway | ContextDuty |
|---|---|---|
| Git pre-commit (before history) | ❌ | ✅ |
| MCP tool result (before context window) | ❌ | ✅ |
| CI/CD (before merge) | ❌ | ✅ |
| Runtime API call | ✅ | ✅ |
| Runs locally, no proxy hop | ❌ | ✅ |
| Air-gap / regulated environment | ❌ | ✅ |
| Your data sent to third-party infra | Yes | Never |

> *Gateways guard the inference call. ContextDuty guards everything upstream of it.*

---

## Why not Presidio?

Presidio is a detection library — it tells you what PII exists, enforcement is your problem. It has no git hooks, no block mode, no audit log, no CI integration. Its MCP wrapper explicitly notes the LLM has already seen the data by the time Presidio runs.

ContextDuty is the enforcement shell. Presidio integration (for name/location NLP detection) is on the roadmap.

---

## Compliance

Ready-made policy baselines:

```json
{ "extends": "policies/soc2-baseline.json", "mode": "block" }
{ "extends": "policies/hipaa-baseline.json", "mode": "block" }
```

The JSONL audit log ContextDuty writes contains timestamp, operation, target, findings count, detector names, and whether the scan was blocked — but **never raw secret values**. That log is what you show auditors.

---

## Local development

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
pip install -e ".[dev]"
make check    # format + lint + 199 tests
```

---

## Roadmap

- [x] 25 built-in detectors
- [x] Pre-commit hook (`contextduty install-hooks`)
- [x] MCP server (Cursor, Claude, VS Code)
- [x] Directory scanning (`contextduty scan src/`)
- [x] Audit dashboard (`contextduty dashboard`)
- [x] Per-detector modes and allow patterns
- [x] Policy layering with `extends`
- [x] Interactive demo (`contextduty demo`)
- [ ] VS Code / Cursor extension (workspace pre-flight scanner)
- [ ] Local HTTPS proxy (intercepts Cursor/Copilot native context)
- [ ] Presidio integration for name/location NLP detection
- [ ] PyPI publish

---

Issues and PRs welcome. [Open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues) if a detector is missing or misfiring.
