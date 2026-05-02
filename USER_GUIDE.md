# ContextDuty User Guide

This guide shows how to install, run, and verify ContextDuty locally.

## What ContextDuty does

ContextDuty scans text for sensitive values and then:
- reports findings (`scan`)
- optionally redacts values (`redact`)

By default, it detects:
- `email`
- `phone`
- `api_key`
- `aws_key`
- `bearer_token`

You can also add your own regex detectors directly in policy (no Python changes required).

## Prerequisites

- Python 3.10+
- Terminal access in this project folder

## Quickstart (recommended: virtual environment)

From the project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

Create a policy file:

```bash
.venv/bin/python -m contextduty.cli init
```

This creates `.contextduty.json`.

## Demo run (using included sample file)

Run a scan:

```bash
.venv/bin/python -m contextduty.cli scan sample.txt --report demo-report.json
```

Run redaction:

```bash
.venv/bin/python -m contextduty.cli redact --in sample.txt --out demo-clean.txt --report demo-redact-report.json
```

Inspect outputs:

- Input: `sample.txt`
- Redacted output: `demo-clean.txt`
- Scan report: `demo-report.json`
- Redact report: `demo-redact-report.json`

Expected report shape:

```json
{
  "findings_count": 4,
  "detector_counts": {
    "email": 1,
    "bearer_token": 1,
    "aws_key": 1,
    "phone": 1
  },
  "blocked": false
}
```

## Policy configuration

Default policy (`.contextduty.json`):

```json
{
  "mode": "redact",
  "detectors": ["email", "phone", "api_key", "aws_key", "bearer_token"],
  "custom_detectors": {}
}
```

Add custom detectors (auto-enabled):

```json
{
  "mode": "redact",
  "detectors": ["email"],
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "project_code": "\\bPRJ-[A-Z]{2}[0-9]{4}\\b"
  }
}
```

Notes:
- `custom_detectors` must be an object of `{detector_name: regex}`.
- Detector names must be unique and cannot reuse built-in names.
- Invalid regex patterns return a clear policy validation error.

### Enterprise policy layering (`extends`)

You can stack policies (org -> team -> user) without copying everything.

`org-baseline.json`:

```json
{
  "mode": "warn",
  "detectors": ["email", "aws_key"],
  "custom_detectors": {
    "internal_ticket": "\\bTICKET-[A-Z]{3}-[0-9]{4}\\b"
  }
}
```

`team-policy.json`:

```json
{
  "extends": "org-baseline.json",
  "detectors": ["phone"],
  "mode": "block"
}
```

`user-policy.json`:

```json
{
  "extends": "team-policy.json",
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b"
  }
}
```

Merge behavior:
- `extends` accepts a string or list of strings (relative paths).
- `detectors` are merged across parent + child.
- `custom_detectors` are merged; child value wins on duplicate key.
- `mode` is overridden by the child policy.
- Cycles in `extends` are rejected with a clear error.

Modes:
- `redact`: replace matched values with stable masks
- `warn`: report findings only
- `block`: return non-zero exit when findings exist

Use a custom policy path:

```bash
.venv/bin/python -m contextduty.cli scan sample.txt --policy .contextduty.json
```

## Command reference

- Initialize policy:
  - `.venv/bin/python -m contextduty.cli init [--path <policy-file>]`
- Scan file:
  - `.venv/bin/python -m contextduty.cli scan <file> [--policy <policy-file>] [--report <report-file>]`
- Redact file:
  - `.venv/bin/python -m contextduty.cli redact --in <input-file> --out <output-file> [--policy <policy-file>] [--report <report-file>]`
- Validate policy:
  - `.venv/bin/python -m contextduty.cli policy validate [--policy <policy-file>] [--strict]`

Example output:

```json
{
  "valid": true,
  "source": ".contextduty.json",
  "mode": "redact",
  "detectors": ["aws_key", "email", "phone"],
  "custom_detectors": ["employee_id"]
}
```

Use `--strict` to fail when policy contains unknown detector names that are neither built-in nor defined under `custom_detectors`.

## MCP server mode

ContextDuty can run as an MCP stdio server:

```bash
.venv/bin/contextduty-mcp
```

Exposed tools:
- `contextduty_scan(path, policyPath?)`
- `contextduty_redact(inputPath, outputPath, policyPath?)`

## Troubleshooting

- `externally-managed-environment` during install:
  - Use a local venv (commands in Quickstart) instead of system-wide pip install.
- No findings when you expect matches:
  - Check your policy `detectors` list includes the needed detector.
- Command exits with code `2`:
  - Policy is likely in `block` mode and findings were detected.
