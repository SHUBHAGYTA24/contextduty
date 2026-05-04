# ContextDuty

> A policy-driven context firewall for AI workflows. Scan and redact sensitive data before prompts, logs, or traces leave your environment — locally, with no cloud calls.

[![PyPI version](https://img.shields.io/pypi/v/contextduty.svg)](https://pypi.org/project/contextduty/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml/badge.svg)](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)

---

> **Status: early alpha — built over a weekend, rough edges expected.**
> Works end-to-end. Not yet battle-tested in production. Ideas, issues,
> and PRs very welcome.

---

## Why ContextDuty

AI coding assistants and agent workflows are spreading fast. So is accidental data leakage — API keys, emails, and PII flowing into prompts, logs, and traces that may be stored or sent to third-party services.

ContextDuty is a **local-first, policy-layered firewall** that sits at the exact moment data moves from your environment into an LLM — before it is too late.

- **CLI** — pipe files through it in CI or pre-commit hooks
- **MCP server** — Cursor, VS Code, and any MCP client get automatic interception
- **Policy inheritance** — teams extend org-wide baselines without copying rules

---

## Why not Presidio?

Presidio is a data pipeline tool — it processes documents after the fact, and its MCP wrapper [explicitly warns](https://github.com/Szowesgad/mcp-server-presidio) that by the time it runs, the LLM has already seen your data. ContextDuty is an enforcement primitive **at the prompt boundary**, which is where leakage actually occurs.

| | ContextDuty | Presidio |
|---|---|---|
| Intercepts before LLM sees data | ✅ | ❌ (LLM calls it as a tool — data already sent) |
| Person names, locations (NLP) | ❌ | ✅ |
| Structured secrets and API keys | ✅ | ✅ |
| MCP enforcement layer | ✅ | ❌ |
| Policy layering + `block` mode | ✅ | ❌ |
| Zero dependencies, instant startup | ✅ | ❌ (downloads spaCy model) |
| Deterministic, auditable masks | ✅ | ❌ (ML confidence scores vary) |

For structured secrets and API keys — the most common AI workflow leaks — ContextDuty catches them with zero latency and full auditability. For unstructured PII like names and locations, Presidio's ML recognizers are the right tool. They are complementary, not competing, and Presidio integration is on the roadmap.

---

## Detection coverage

25 built-in detectors across 8 categories, all enabled by default.

### PII

| Detector | Catches |
|---|---|
| `email` | `jane@corp.com` |
| `phone` | `+1 415-555-1212` |

### Generic tokens

| Detector | Catches |
|---|---|
| `api_key` | `sk_live_…`, `rk_…`, `pk_…` (Stripe-style underscore keys) |
| `bearer_token` | `Bearer eyJhbGci…` |

### Cloud provider keys

| Detector | Catches |
|---|---|
| `aws_key` | `AKIA…` (AWS Access Key ID) |
| `aws_secret` | `AWS_SECRET_ACCESS_KEY=…` in env files / config |
| `gcp_service_account` | `"type": "service_account"` in GCP JSON key blobs |
| `google_oauth_token` | `ya29.…` Google OAuth access tokens |

### VCS platform tokens

| Detector | Catches |
|---|---|
| `github_pat` | `ghp_…`, `gho_…`, `ghu_…`, `ghs_…`, `ghr_…`, `github_pat_…` |

### AI / ML service keys

| Detector | Catches |
|---|---|
| `openai_key` | `sk-…` and `sk-proj-…` OpenAI API keys |
| `anthropic_key` | `sk-ant-…` Anthropic API keys |
| `huggingface_token` | `hf_…` HuggingFace tokens |

### Communication & SaaS platforms

| Detector | Catches |
|---|---|
| `slack_token` | `xoxb-…`, `xoxp-…`, `xoxa-…`, `xoxs-…`, `xapp-…` |
| `stripe_webhook` | `whsec_…` Stripe webhook signing secrets |
| `sendgrid_key` | `SG.….…` SendGrid API keys |
| `mailchimp_key` | `<32-hex>-us<n>` Mailchimp API keys |
| `npm_token` | `npm_…` npm automation tokens |
| `twilio_sid` | `AC<32-hex>` Twilio Account SIDs |
| `azure_storage_key` | Azure storage connection strings (`DefaultEndpointsProtocol=…`) |

### Database connection strings

| Detector | Catches |
|---|---|
| `db_dsn` | `postgres://user:pass@host`, `mysql://…`, `mongodb://…`, `redis://…`, etc. — only matches DSNs that embed credentials |

### Cryptographic material

| Detector | Catches |
|---|---|
| `ssh_private_key` | `-----BEGIN RSA/EC/DSA/OPENSSH PRIVATE KEY-----` |
| `pgp_private_key` | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| `private_key_pem` | `-----BEGIN PRIVATE KEY-----` (PKCS#8) |
| `jwt` | Three-part base64url tokens starting with `eyJ` |
| `env_secret` | `PASSWORD=…`, `SECRET_KEY=…`, `API_KEY=…`, `ACCESS_TOKEN=…`, etc. in config files |

Masks are **deterministic** — the same value always produces the same mask token, so you can correlate findings across log lines and audit trails without ever exposing the raw secret.

---

## Quickstart

```bash
pip install contextduty
contextduty init
```

Try it immediately:

```bash
cat > /tmp/test.txt << 'EOF'
From: priya@healthtech.com
Auth: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig
AWS Key: AKIA1234567890ABCDEF
API: sk_live_9Xk2mPqRvL8nJwTdYcBe3F
Phone: +1 415-555-1212
Error: SMTP timeout on port 587
EOF

contextduty scan /tmp/test.txt
contextduty redact --in /tmp/test.txt --out /tmp/clean.txt
cat /tmp/clean.txt
```

Or run the full demo:

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty && bash demo/demo.sh
```

---

## Commands

| Command | Description |
|---|---|
| `contextduty init` | Create `.contextduty.json` in the current directory |
| `contextduty scan <file>` | Scan file, print JSON findings report |
| `contextduty redact --in <f> --out <f>` | Redact matches, write clean file |
| `contextduty policy validate --policy <f> [--strict]` | Validate and resolve a layered policy |
| `contextduty --version` | Print installed version |

---

## MCP server (Cursor / VS Code / any MCP client)

ContextDuty runs as an MCP stdio server — drop it into your editor config and every file your agent touches is scanned **before** it reaches the LLM.

```bash
contextduty-mcp
```

**Cursor** — add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "contextduty": {
      "command": "contextduty-mcp"
    }
  }
}
```

Exposed tools:

| Tool | Arguments | Use case |
|---|---|---|
| `contextduty_scan_text` | `text`, optional `policyPath` | Scan an in-memory string — **use this for prompt interception** |
| `contextduty_scan` | `path`, optional `policyPath` | Scan a file on disk |
| `contextduty_redact` | `inputPath`, `outputPath`, optional `policyPath` | Redact a file on disk |

> `contextduty_scan_text` is the primary tool for MCP use. It intercepts the prompt string before the LLM receives it — not after.

---

## Policy file

Default `.contextduty.json` (all 25 built-in detectors are enabled out of the box):

```json
{
  "mode": "redact",
  "detectors": [
    "email", "phone",
    "api_key", "bearer_token",
    "aws_key", "aws_secret", "gcp_service_account", "google_oauth_token",
    "github_pat",
    "openai_key", "anthropic_key", "huggingface_token",
    "slack_token", "stripe_webhook", "sendgrid_key", "mailchimp_key",
    "npm_token", "twilio_sid", "azure_storage_key",
    "db_dsn",
    "ssh_private_key", "pgp_private_key", "private_key_pem", "jwt", "env_secret"
  ],
  "custom_detectors": {}
}
```

**Add a custom detector without touching code:**

```json
{
  "mode": "redact",
  "detectors": ["email"],
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "internal_ticket": "\\bTICKET-[A-Z]{3}-[0-9]{4}\\b"
  }
}
```

`custom_detectors` are auto-enabled — just add the regex entry.

**Policy layering for teams and enterprises:**

```json
{
  "extends": "../../policies/org-baseline.json",
  "mode": "block",
  "detectors": ["internal_ticket"],
  "custom_detectors": {
    "internal_ticket": "\\bTICKET-[A-Z]{3}-[0-9]{4}\\b"
  }
}
```

Rules:
- `extends` can be a string or list (relative file paths)
- `detectors` are merged (parent + child)
- `custom_detectors` are merged (child overrides same key)
- `mode` is overridden by the child policy
- Cycles in `extends` are rejected with a clear error

**Modes:**

| Mode | Behaviour |
|---|---|
| `redact` | Replace matched values with deterministic masks |
| `warn` | Report findings, do not change content |
| `block` | Exit non-zero if findings exist (CI enforcement) |

---

## Compliance policy packs

Ready-made baselines for SOC 2 and HIPAA — extend them in your own policy file:

| Pack | File | Detectors included |
|---|---|---|
| SOC 2 | `policies/soc2-baseline.json` | email, phone, api_key, aws_key, bearer_token, github_pat, openai_key, db_dsn, jwt |
| HIPAA | `policies/hipaa-baseline.json` | email, phone + SSN, NPI, DEA, ICD-10, MRN |

Usage:

```json
{
  "extends": "policies/soc2-baseline.json",
  "mode": "block"
}
```

---

## CI integration

Use `block` mode to fail a pipeline if secrets are found in a specific file:

```yaml
# .github/workflows/contextduty.yml
- name: Scan for secrets
  run: |
    pip install contextduty
    contextduty scan src/my_module.py --policy .contextduty.json
```

---

## Local development

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
make install    # pip install -e ".[dev]"
make check      # fmt + lint + tests — run before every push
bash demo/demo.sh
```

---
## Roadmap

- [x] PyPI publish (`pip install contextduty`)
- [x] 25 built-in detectors across 8 categories (AWS, GCP, GitHub, OpenAI, Anthropic, Slack, DB DSNs, crypto material, and more)
- [ ] Directory scanning (`contextduty scan src/`)
- [ ] `contextduty install-hook` — one command installs the pre-push git hook
- [ ] `contextduty scan-history` — scan git history for already-committed secrets
- [ ] Audit log (`~/.contextduty/audit.jsonl`) for compliance trail
- [ ] Presidio integration as optional NLP backend for names/locations

Have an idea? [Open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues).

---

## Open source

| File | Purpose |
|---|---|
| `LICENSE` | MIT |
| `SECURITY.md` | Vulnerability reporting |
| `CONTRIBUTING.md` | How to contribute |
| `CODE_OF_CONDUCT.md` | Community standards |
| `CHANGELOG.md` | Version history |

Issues, PRs, and policy pack contributions are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
