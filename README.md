# ContextDuty

ContextDuty is a policy-driven context firewall for AI workflows. It scans text for sensitive data and can redact it before logs, prompts, or traces leave your environment.

## Why now

AI coding and agent workflows are spreading quickly, while enterprises increasingly require policy controls and data minimization. ContextDuty provides a local-first, OSS primitive for that gap.

## 2-command quickstart

```bash
python -m pip install -e .
contextduty init
```

Then run:

```bash
contextduty scan sample.txt --report report.json
contextduty redact --in sample.txt --out clean.txt --report report.json
```

## Commands

- `contextduty init` - create `.contextduty.json`
- `contextduty scan <file>` - scan file and print JSON report
- `contextduty redact --in <file> --out <file>` - redact matches and print JSON report
- `contextduty policy validate --policy <file> [--strict]` - validate and resolve layered policy

## MCP server (for Cursor / VS Code / other MCP clients)

ContextDuty can run as an MCP stdio server.

Run:

```bash
contextduty-mcp
```

Exposed tools:
- `contextduty_scan` (`path`, optional `policyPath`)
- `contextduty_redact` (`inputPath`, `outputPath`, optional `policyPath`)

## Policy file

Default `.contextduty.json`:

```json
{
  "mode": "redact",
  "detectors": ["email", "phone", "api_key", "aws_key", "bearer_token"],
  "custom_detectors": {}
}
```

Add your own detector without changing code:

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

`custom_detectors` are auto-enabled, so users only add regex entries.

Policy layering for enterprise:

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
- `extends` can be a string or list of strings (relative file paths)
- detector lists are merged (parent + child)
- `custom_detectors` are merged (child overrides same key)
- `mode` is overridden by the child policy
- cycle in `extends` is rejected with a clear error

Modes:
- `redact`: replace matched values with deterministic masks
- `warn`: report findings but do not change content
- `block`: exit non-zero if findings exist

## Roadmap

- streaming JSONL mode for multi-GB datasets
- plugin adapters for Cursor/VS Code/other clients
- policy packs for SOC2/HIPAA/PCI

## Open source

- License: MIT (`LICENSE`)
- Security policy: `SECURITY.md`
- Contributing guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
