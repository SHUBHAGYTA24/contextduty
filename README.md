# ContextDuty

> **The AI context firewall. Stop secrets from reaching any AI tool — before the prompt is assembled.**

[![PyPI version](https://img.shields.io/pypi/v/contextduty.svg)](https://pypi.org/project/contextduty/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml/badge.svg)](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)
[![258 Tests](https://img.shields.io/badge/tests-258%20passing-brightgreen.svg)](#)

---

## What is ContextDuty?

ContextDuty is a **local-first security product** that prevents secrets, API keys, and PII from leaking into AI coding assistants. It works with every AI tool — Cursor, GitHub Copilot, Claude, Windsurf, Cody, Amazon Q — current and future.

**One install. Every AI tool. Zero cloud dependencies.**

```
pip install contextduty
contextduty protect        # blocks secrets from ALL AI tools at once
contextduty proxy start    # intercepts HTTPS traffic to 21 AI APIs
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR WORKSPACE                                │
│                                                                     │
│  .env  config.py  fixtures/  keys/  terraform.tfvars               │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
            ▼               ▼               ▼
┌─────────────────��┐ ┌────────────┐ ┌──────────────────┐
│  LAYER 1         │ │  LAYER 2   │ │  LAYER 3         │
│  Upstream Block  │ │  Git Hook  │ │  HTTPS Proxy     │
│                  │ │            │ │                   │
│ .cursorignore    │ │ pre-commit │ │ Intercepts 21    │
│ .copilotignore   │ │ blocks     │ │ AI API endpoints │
│ .codeiumignore   │ │ commits    │ │ Redacts secrets  │
│ .tabnine_ignore  │ │ with       │ │ in-flight before │
│ .amazonq/ignore  │ │ secrets    │ │ they reach any   │
│ .cody/ignore     │ │            │ │ AI model         │
└──────────────────┘ └────────────┘ └──────────────────┘
            │               │               │
            ▼               ▼               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   AI TOOLS (all protected)                           │
│  Cursor  ·  Copilot  ·  Claude  ·  Windsurf  ·  Cody  ·  Amazon Q │
│  + any future tool that reads workspaces or calls AI APIs           │
└─────────────────────────────────────────────────────────────────────┘
```

**Layer 1 — Upstream Block:** Generates ignore files for 6 AI tools so they never index sensitive files.  
**Layer 2 — Git Hook:** Pre-commit scan blocks secrets from entering version history.  
**Layer 3 — HTTPS Proxy:** Intercepts all AI API traffic and redacts secrets from the request body in real-time.

Plus: **MCP server** for Cursor/Claude tool-call interception, **CI/CD integration**, and **audit dashboard**.

---

## Quick start

```bash
pip install contextduty

# Try the interactive demo (20 seconds)
contextduty demo

# Protect your workspace from ALL AI tools
cd your-project/
contextduty protect

# Install git pre-commit hook
contextduty install-hooks

# Start the HTTPS proxy (intercepts Cursor, Copilot, Claude API calls)
pip install 'contextduty[proxy]'
contextduty proxy setup
contextduty proxy start
```

---

## See it in 20 seconds

```
$ contextduty demo

▶ Scene 1 — Developer creates config.py with real credentials

  DATABASE_URL = "postgresql://admin:Sup3rS3cr3t!@prod-db.internal:5432/customers"
  AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"
  OPENAI_API_KEY = "sk-proj-EXAMPLEcontextdutyDEMO..."

▶ Scene 2 — Scanning → 6 findings detected

▶ Scene 3 — Redacting (safe to pass to AI)

  DATABASE_URL = "<DB_DSN_33213ab6f0>"
  AWS_ACCESS_KEY_ID     = "<AWS_KEY_1a5d44a2dc>"
  OPENAI_API_KEY = "<OPENAI_KEY_5f04681e46>"

✓ Real values replaced with deterministic masks — safe to paste into any AI tool

▶ Scene 4 — Pre-commit hook blocks the commit

  [ContextDuty] BLOCKED: config.py
    aws_key: 1 finding(s)
    openai_key: 1 finding(s)

✓ Commit rejected — secrets never entered git history
```

---

## Layer 1 — Universal workspace protection

One command generates ignore files for **every** AI tool:

```bash
$ contextduty protect

────────────────────────────────────────────────────────
  ContextDuty — Universal AI Workspace Protection
────────────────────────────────────────────────────────

  ⚠  12 file(s) contain secrets/PII

  ✓  Written 6 ignore files:

     ✓  .cursorignore        Cursor
     ✓  .copilotignore       GitHub Copilot
     ✓  .codeiumignore       Codeium / Windsurf
     ✓  .tabnine_ignore      Tabnine
     ✓  .amazonq/ignore      Amazon Q
     ✓  .cody/ignore         Sourcegraph Cody
```

**Watch mode** — auto-updates when files change:

```bash
contextduty protect watch   # runs continuously, updates all 6 ignore files
```

**Future-proof:** When a new AI tool launches, we add 3 lines to the registry. Your workspace is instantly protected.

---

## Layer 2 — Pre-commit hook

```bash
contextduty install-hooks
```

Every `git commit` is scanned. If secrets are found, the commit is rejected:

```
$ git commit -m "add deployment config"

[ContextDuty] BLOCKED: config.py
  aws_key: 1 finding(s)
  openai_key: 1 finding(s)

╔══════════════════════════════════════════════════════════════╗
║  ContextDuty blocked this commit.                           ║
║  Remove or redact them before committing.                   ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Layer 3 — HTTPS proxy (real-time interception)

The proxy sits between your AI tools and their API endpoints. It intercepts requests to **21 AI API hosts** and redacts secrets from the request body before they leave your machine.

```bash
pip install 'contextduty[proxy]'
contextduty proxy setup    # one-time: install CA cert
contextduty proxy start    # start intercepting

──────────────────────────────────────────────────────
  ContextDuty Proxy
──────────────────────────────────────────────────────

  Listening on   127.0.0.1:8080
  Intercepting   21 AI API endpoints
  Policy         .contextduty.json
```

**What it intercepts:**

| Provider | Endpoints |
|---|---|
| OpenAI | `api.openai.com` |
| Anthropic (Claude) | `api.anthropic.com` |
| Cursor | `cursor.sh`, `api2.cursor.sh` |
| GitHub Copilot | `copilot.github.com`, `api.githubcopilot.com` |
| Google (Gemini) | `generativelanguage.googleapis.com`, `aiplatform.googleapis.com` |
| Azure OpenAI | `openai.azure.com` |
| Codeium / Windsurf | `server.codeium.com` |
| Amazon Q | `codewhisperer.us-east-1.amazonaws.com` |
| Sourcegraph Cody | `sourcegraph.com` |
| Others | Cohere, Mistral, Groq, Together, Perplexity, DeepSeek, Fireworks, Tabnine |

**Declarative field walker** — the proxy knows exactly where each provider puts user content in their JSON payload (messages, context, system prompts) and only scans those fields. Adding a new provider = adding field paths, zero code changes.

---

## Layer 4 — MCP server (Cursor / Claude / VS Code)

ContextDuty runs as an MCP server. When AI agents fetch files or database results via tools, ContextDuty intercepts the response:

```json
// ~/.cursor/mcp.json or ~/.claude/claude_desktop_config.json
{
  "mcpServers": {
    "contextduty": { "command": "contextduty-mcp" }
  }
}
```

```
Agent calls:  read_file("customers.json")
Tool returns: {"name": "Jane Smith", "ssn": "123-45-6789"}
ContextDuty:  {"name": "<PERSON_a3f2>", "ssn": "<SSN_b7c1>"}

→ Real values never enter the prompt. Never reach the AI model.
```

---

## Layer 5 — CI/CD enforcement

```yaml
# .github/workflows/contextduty.yml
- name: ContextDuty scan
  run: |
    pip install contextduty
    contextduty scan src/ --policy .contextduty.json
```

With `"mode": "block"`, the pipeline exits non-zero. PR cannot merge.

---

## Detection: 25 built-in detectors

| Category | Detectors |
|---|---|
| **PII** | `email`, `phone` |
| **Generic tokens** | `api_key`, `bearer_token`, `env_secret` |
| **Cloud** | `aws_key`, `aws_secret`, `gcp_service_account`, `azure_storage_key`, `google_oauth_token` |
| **VCS** | `github_pat` |
| **AI/ML** | `openai_key`, `anthropic_key`, `huggingface_token` |
| **SaaS** | `slack_token`, `stripe_webhook`, `sendgrid_key`, `mailchimp_key`, `npm_token`, `twilio_sid` |
| **Databases** | `db_dsn` (postgres, mysql, mongodb, redis — only when credentials present) |
| **Crypto** | `ssh_private_key`, `pgp_private_key`, `private_key_pem`, `jwt` |

**Deterministic masks:** `AKIAIOSFODNN7EXAMPLE` always becomes `<AWS_KEY_1a5d44a2dc>` — same value, same mask, everywhere. Audit logs stay correlatable without storing raw secrets.

**Custom detectors** — add your own regex patterns:

```json
{
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "patient_mrn": "\\bMRN-[0-9]{8}\\b"
  }
}
```

---

## Policy system

```bash
contextduty init   # creates .contextduty.json
```

```json
{
  "mode": "redact",
  "detectors": ["email", "phone", "aws_key", "openai_key", "github_pat", "db_dsn"],
  "custom_detectors": {},
  "detector_modes": { "aws_key": "block", "openai_key": "block" },
  "allow_patterns": { "email": ["@example\\.com$", "@test\\.internal$"] }
}
```

| Mode | Behavior |
|---|---|
| `redact` | Replace matched values with deterministic masks |
| `warn` | Log findings, don't modify, don't block |
| `block` | Exit non-zero — for CI and pre-commit hard stops |

**Policy layering** — team baseline + repo override:

```json
{ "extends": "../../policies/org-baseline.json", "mode": "block" }
```

**Compliance baselines** included: `policies/soc2-baseline.json`, `policies/hipaa-baseline.json`

---

## Audit dashboard

```bash
contextduty dashboard --demo    # try it with synthetic data
contextduty dashboard           # reads ~/.contextduty/audit.jsonl
```

Local web UI with dark theme: findings by detector, 30-day timeline, blocked commits, developer activity, CSV export. Zero dependencies, all data stays on your machine.

---

## All commands

| Command | Description |
|---|---|
| `contextduty demo` | Interactive demo — catches secrets in 20 seconds |
| `contextduty protect` | Write ignore files for ALL 6 AI tools at once |
| `contextduty protect watch` | Background daemon, auto-update on file changes |
| `contextduty protect status` | Show what's protected and what's not |
| `contextduty proxy setup` | One-time CA cert install |
| `contextduty proxy start` | Start HTTPS interception proxy |
| `contextduty proxy stop` | Stop the proxy |
| `contextduty proxy status` | Check if proxy is running |
| `contextduty cursor setup` | Cursor-specific workspace protection |
| `contextduty cursor watch` | Cursor-specific watch mode |
| `contextduty scan <file\|dir>` | Scan and print JSON findings |
| `contextduty redact --in <f> --out <f>` | Redact file, write clean copy |
| `contextduty install-hooks` | Install git pre-commit hook |
| `contextduty uninstall-hooks` | Remove the hook |
| `contextduty dashboard` | Open local audit dashboard |
| `contextduty report` | Summarize an audit log |
| `contextduty policy validate` | Validate and resolve policy file |
| `contextduty init` | Create default `.contextduty.json` |

---

## Project structure

```
src/contextduty/
├── config.py              # Centralized paths, env vars, constants
├── engine.py              # Core scan/redact engine (25 detectors)
├── detectors.py           # Regex detector definitions
├── policy.py              # Policy loading, validation, inheritance
├── cli.py                 # CLI entry point (18 commands)
├── protect.py             # Universal workspace protection
├── cursor.py              # Cursor-specific shortcut
├── demo.py                # Interactive demo
├── dashboard.py           # Local audit web UI
├── core/
│   ├── __init__.py        # Public API (lazy imports)
│   └── exceptions.py      # Typed exception hierarchy
├── ui/
│   └── output.py          # NO_COLOR-compliant terminal formatting
├── adapters/
│   └── ide.py             # AI tool registry + ignore file generation
└── proxy/
    ├── scope.py           # 21 AI API hosts (single source of truth)
    ├── interceptor.py     # Declarative JSON field walker
    ├── addon.py           # mitmproxy request handler
    ├── server.py          # Proxy lifecycle (start/stop/daemon)
    ├── ca.py              # CA certificate management
    ├── system.py          # OS proxy configuration
    └── feed.py            # Live terminal feed for interceptions
```

---

## How it compares

| | ContextDuty | LLM Gateways | .gitignore |
|---|---|---|---|
| Blocks AI indexing (Cursor, Copilot, etc.) | ✅ 6 tools | ❌ | ❌ |
| Pre-commit secret scanning | ✅ | ❌ | ❌ |
| HTTPS proxy (intercepts any AI API) | ✅ 21 endpoints | ✅ (different purpose) | ❌ |
| MCP tool-call interception | ✅ | ❌ | ❌ |
| Runs 100% locally | ✅ | ❌ | ✅ |
| Policy-as-code | ✅ | Partial | ❌ |
| Works offline / air-gapped | ✅ | ❌ | ✅ |
| Your data sent to third parties | Never | Sometimes | N/A |

---

## Local development

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
pip install -e ".[dev]"
make check    # format + lint + 258 tests
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
- [x] Universal workspace protection (`contextduty protect`) — 6 AI tools
- [x] HTTPS proxy intercepting 21 AI API endpoints
- [x] Declarative field walker (new AI provider = add paths, zero code)
- [x] Enterprise architecture (config, exceptions, UI, adapters)
- [ ] VS Code / Cursor extension
- [ ] Presidio integration for NLP-based PII detection
- [ ] PyPI publish
- [ ] Prometheus metrics endpoint

---

## License

MIT. Issues and PRs welcome. [Open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues) if a detector is missing or misfiring.
