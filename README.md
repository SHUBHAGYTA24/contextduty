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

```mermaid
flowchart TD
    WS["🗂️  YOUR WORKSPACE\n.env · config.py · keys/ · terraform.tfvars"]

    WS --> L1 & L2 & L3 & L4 & L5

    L1["🛡️  Layer 1 — Workspace Ignore\n────────────────────────\n.cursorignore\n.copilotignore\n.codeiumignore\n.tabnine_ignore\n.amazonq/ignore\n.cody/ignore\n\nBlocks 6 AI tools from\never indexing secret files"]

    L2["🔒  Layer 2 — Git Hook\n────────────────────────\npre-commit scan\n\nBlocks commits that\ncontain secrets before\nthey enter git history"]

    L3["🌐  Layer 3 — HTTPS Proxy\n────────────────────────\n21 AI API endpoints\n\nRedacts secrets from\nrequest bodies in-flight\nbefore they leave machine"]

    L4["🤖  Layer 4 — MCP Server\n────────────────────────\nCursor · Claude · VS Code\n\nScans tool-call responses\nbefore they enter the\nAI context window"]

    L5["⚙️  Layer 5 — CI/CD\n────────────────────────\nGitHub Actions\n\nBlocks PRs that contain\nsecrets — policy-as-code\nenforcement in pipeline"]

    L1 & L2 & L3 & L4 & L5 --> AI

    AI["✅  AI TOOLS — ALL PROTECTED\nCursor · Copilot · Claude · Windsurf · Cody · Amazon Q\nOpenAI · Anthropic · Gemini · Azure OpenAI · and 11 more"]

    style WS fill:#1e1e2e,stroke:#6c6f85,color:#cdd6f4
    style L1 fill:#1e3a5f,stroke:#89b4fa,color:#cdd6f4
    style L2 fill:#1e3a5f,stroke:#89b4fa,color:#cdd6f4
    style L3 fill:#1e3a5f,stroke:#89b4fa,color:#cdd6f4
    style L4 fill:#1e3a5f,stroke:#89b4fa,color:#cdd6f4
    style L5 fill:#1e3a5f,stroke:#89b4fa,color:#cdd6f4
    style AI fill:#1a3a1a,stroke:#a6e3a1,color:#cdd6f4
```

| Layer | What it does |
|---|---|
| **1 — Workspace Ignore** | Generates ignore files for 6 AI tools — secrets never get indexed |
| **2 — Git Hook** | Pre-commit scan blocks secrets from entering version history |
| **3 — HTTPS Proxy** | Intercepts 21 AI API endpoints, redacts secrets in-flight |
| **4 — MCP Server** | Scans tool-call responses before they enter the AI context window |
| **5 — CI/CD** | Policy-as-code enforcement — PRs with secrets cannot merge |

---

## Quick start

```bash
# 1. Install
pip install contextduty

# 2. Go to your project root (where .git lives) — all commands run from here
cd your-project/

# 3. Try the interactive demo (20 seconds)
contextduty demo

# 4. Create a policy file
contextduty init

# 5. Block ALL AI tools from reading your secrets
contextduty protect

# 6. Block secrets from entering git history
contextduty install-hooks

# 7. Intercept live AI API calls (requires separate install)
pip install 'contextduty[proxy]'
contextduty proxy setup          # one-time: installs CA cert (needs sudo)
contextduty proxy start          # start intercepting
```

> **Note:** `contextduty install-hooks` must be run from your project root (the folder that contains `.git/`). It will fail if run from a subdirectory.

---

## See it in action

![ContextDuty demo — scan, redact, protect, block](demo/contextduty-demo.gif)

> Secrets detected → redacted with deterministic masks → commit blocked → AI tools protected.  
> Run it yourself: `contextduty demo`

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
# Run from your project root (the folder that contains .git/)
cd your-project/
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
# Step 1 — install proxy dependencies (mitmproxy, ~50 packages)
pip install 'contextduty[proxy]'

# Step 2 — one-time CA cert setup (needs sudo, run once per machine)
contextduty proxy setup

# Step 3 — start intercepting
contextduty proxy start

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
- [x] Published on PyPI (`pip install contextduty`)
- [ ] VS Code / Cursor extension
- [ ] Presidio integration for NLP-based PII detection
- [ ] Prometheus metrics endpoint

---

## License

MIT. Issues and PRs welcome. [Open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues) if a detector is missing or misfiring.
