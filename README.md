# ContextDuty

> A policy-driven context firewall for AI workflows. Scan and redact sensitive data before prompts, logs, or traces leave your environment — locally, with no cloud calls.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)

---

## Why ContextDuty

AI coding assistants and agent workflows are spreading fast. So is accidental data leakage — API keys, emails, and PII flowing into prompts, logs, and traces that may be stored or sent to third-party services.

ContextDuty is a **local-first, policy-layered primitive** that fits into any workflow:
- **CLI** — pipe files through it in CI or pre-commit hooks
- **MCP server** — Cursor, VS Code, and any MCP client get automatic redaction
- **Policy inheritance** — teams extend org-wide baselines without copying rules

---

## Why not Presidio?

[Microsoft Presidio](https://github.com/microsoft/presidio) is great for NER-based PII detection in data pipelines. ContextDuty solves a different problem:

| | ContextDuty | Presidio |
|---|---|---|
| Target use case | AI prompts, logs, agent traces | Data pipelines, analytics |
| MCP-native | ✅ | ❌ |
| Policy layering (`extends`) | ✅ | ❌ |
| `block` mode for CI | ✅ | ❌ |
| Zero dependencies | ✅ | ❌ (heavy NLP stack) |
| Custom detectors (no code) | ✅ (regex in JSON) | Partial |
| Deployment | Local CLI / subprocess | Service / SDK |

Use Presidio when you need ML-based entity recognition at scale. Use ContextDuty when you need a lightweight, policy-enforceable firewall close to your AI toolchain.

---

## Detection coverage

| Detector | Example input | Masked as |
|---|---|---|
| `email` | `jane@corp.com` | `<EMAIL_a1b2c3d4e5>` |
| `phone` | `+1 415-555-1212` | `<PHONE_f6g7h8i9j0>` |
| `api_key` | `sk_live_ABC123...` | `<API_KEY_k1l2m3n4o5>` |
| `aws_key` | `AKIA1234567890ABCDEF` | `<AWS_KEY_p6q7r8s9t0>` |
| `bearer_token` | `Bearer eyJhbGci...` | `<BEARER_TOKEN_u1v2w3x4y5>` |

Masks are **deterministic** — the same value always produces the same mask, so you can correlate across log lines without exposing the raw value.

---

## Quickstart

```bash
pip install contextduty
contextduty init
```

Then scan and redact:

```bash
contextduty scan sample.txt --report report.json
contextduty redact --in sample.txt --out clean.txt --report report.json
```

---

## Commands

| Command | Description |
|---|---|
| `contextduty init` | Create `.contextduty.json` in the current directory |
| `contextduty scan <file>` | Scan file, print JSON findings report |
| `contextduty redact --in <f> --out <f>` | Redact matches, write clean file |
| `contextduty policy validate --policy <f> [--strict]` | Validate and resolve a layered policy |

---

## MCP server (Cursor / VS Code / any MCP client)

ContextDuty runs as an MCP stdio server — drop it into your editor config and every file your agent touches is scanned automatically.

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
- `contextduty_scan` (`path`, optional `policyPath`)
- `contextduty_redact` (`inputPath`, `outputPath`, optional `policyPath`)

---

## Policy file

Default `.contextduty.json`:

```json
{
  "mode": "redact",
  "detectors": ["email", "phone", "api_key", "aws_key", "bearer_token"],
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

Ready-made baselines for common frameworks — extend them in your own policy file:

| Pack | Path | Detectors included |
|---|---|---|
| SOC 2 | `policies/soc2-baseline.json` | email, phone, api_key, aws_key, bearer_token |
| HIPAA | `policies/hipaa-baseline.json` | email, phone + PHI custom patterns |

Usage:
```json
{
  "extends": "./node_modules/contextduty/policies/soc2-baseline.json",
  "mode": "block"
}
```

---

## CI integration

Add a pre-push check to block accidental secret commits:

```yaml
# .github/workflows/contextduty.yml
- name: Scan for secrets
  run: |
    pip install contextduty
    contextduty scan . --policy .contextduty.json
```

Or use `mode: block` in your policy to make `contextduty scan` exit non-zero on any finding.

---

## Roadmap

- [ ] PyPI publish (`pip install contextduty`)
- [ ] Streaming JSONL mode for multi-GB datasets
- [ ] VS Code extension
- [ ] Policy packs for PCI-DSS
- [ ] GitHub Action (`uses: contextduty/action@v1`)

---

## Open source

| File | Purpose |
|---|---|
| `LICENSE` | MIT |
| `SECURITY.md` | Vulnerability reporting |
| `CONTRIBUTING.md` | How to contribute |
| `CODE_OF_CONDUCT.md` | Community standards |
| `CHANGELOG.md` | Version history |

---

## Contributing

Issues, PRs, and policy pack contributions are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.
