# ContextDuty — User Manual

> Complete guide for getting ContextDuty running from scratch, in the correct order.

---

## Prerequisites

- Python 3.10 or later
- pip
- git (for the pre-commit hook)

---

## Step 1 — Install ContextDuty

```bash
pip install contextduty
```

This installs the `contextduty` command and gives you:

- `contextduty scan` — scan files and directories
- `contextduty redact` — write a clean copy with secrets replaced
- `contextduty protect` — generate ignore files for all AI tools
- `contextduty install-hooks` — install git pre-commit hook
- `contextduty dashboard` — local audit UI
- `contextduty-mcp` — MCP server for Claude / Cursor

---

## Step 2 — Go to your project root

**All commands must be run from your project root** — the folder that contains `.git/`.

```bash
cd ~/your-project
```

Running from a subfolder (or a git worktree) will cause `install-hooks` to fail with:
```
Error: No .git directory found at .. Is this a git repo?
```

---

## Step 3 — Create a policy file

```bash
contextduty init
```

Creates `.contextduty.json` in the current directory with sensible defaults:

```json
{
  "mode": "redact",
  "detectors": ["email", "phone", "aws_key", "openai_key", "github_pat", "db_dsn"],
  "custom_detectors": {},
  "detector_modes": {},
  "allow_patterns": {}
}
```

**Modes:**

| Mode | What it does |
|---|---|
| `redact` | Replaces matched values with deterministic masks |
| `warn` | Logs findings, does not modify anything |
| `block` | Exits non-zero — use for CI and hard stops in pre-commit |

You can set a different mode per detector:

```json
{
  "mode": "redact",
  "detector_modes": {
    "aws_key": "block",
    "openai_key": "block"
  }
}
```

---

## Step 4 — Try the demo

```bash
contextduty demo
```

Runs through a 20-second walkthrough: fake credentials get scanned, redacted, and a commit gets blocked. Good way to confirm everything is installed correctly.

---

## Step 5 — Protect your workspace from AI tools

```bash
contextduty protect
```

Scans your workspace for files containing secrets and writes ignore files for every major AI coding tool so they never index those files:

| File written | Protects |
|---|---|
| `.cursorignore` | Cursor |
| `.copilotignore` | GitHub Copilot |
| `.codeiumignore` | Codeium / Windsurf |
| `.tabnine_ignore` | Tabnine |
| `.amazonq/ignore` | Amazon CodeWhisperer |
| `.cody/ignore` | Sourcegraph Cody |

Re-run whenever you add new sensitive files. Or run it continuously:

```bash
contextduty protect watch
```

---

## Step 6 — Install the git pre-commit hook

```bash
contextduty install-hooks
```

After this, every `git commit` automatically scans staged files. If secrets are found in `block` mode, the commit is rejected before it touches history.

**Must be run from your project root** (the folder with `.git/`).

To remove:

```bash
contextduty uninstall-hooks
```

---

## Step 7 — Install proxy support (optional)

The HTTPS proxy intercepts all traffic from AI tools (Cursor, Copilot, Claude, etc.) and redacts secrets from prompts in real-time, before they leave your machine.

### 7a — Install proxy dependencies

```bash
pip install 'contextduty[proxy]'
```

This installs mitmproxy (~50 packages, ~100 MB). Only needed for proxy interception.

### 7b — Set up the CA certificate (one-time, per machine)

```bash
contextduty proxy setup
```

Generates a local CA certificate and installs it into your OS trust store. Requires `sudo`. Only needs to be done once.

### 7c — Start the proxy

```bash
contextduty proxy start
```

Output when working correctly:

```
──────────────────────────────────────────────────
  ContextDuty Proxy
──────────────────────────────────────────────────

  Listening on   127.0.0.1:8080
  Intercepting   21 AI API endpoints
  Policy         .contextduty.json

  Press Ctrl+C to stop.
```

Set your system HTTP proxy to `127.0.0.1:8080` or run:

```bash
contextduty proxy start --set-system-proxy
```

---

## Step 8 — Add to Claude / Cursor as an MCP server (optional)

ContextDuty can run as an MCP server so it intercepts every file or database result that an AI agent reads via tools — before that data enters the prompt.

**For Claude Desktop** — create `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "contextduty": { "command": "contextduty-mcp" }
  }
}
```

**For Cursor** — create `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "contextduty": { "command": "contextduty-mcp" }
  }
}
```

Restart the app after saving. ContextDuty will scan every tool call response before the AI sees it.

---

## Step 9 — Add to CI/CD (optional)

Create `.github/workflows/contextduty.yml`:

```yaml
name: ContextDuty — secrets & PII scan

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["main"]

jobs:
  scan:
    name: Scan for secrets and PII
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install ContextDuty
        run: pip install contextduty
      - name: Scan source
        run: contextduty scan src/ --policy .contextduty.json
```

With `"mode": "block"` in your policy, the pipeline fails and the PR cannot merge if secrets are found.

---

## Complete install order (summary)

| Step | Command | Notes |
|---|---|---|
| 1 | `pip install contextduty` | Core install |
| 2 | `cd your-project/` | Must be at project root |
| 3 | `contextduty init` | Creates `.contextduty.json` |
| 4 | `contextduty demo` | Verify install works |
| 5 | `contextduty protect` | Block AI tools from reading secrets |
| 6 | `contextduty install-hooks` | Block secrets from git history |
| 7a | `pip install 'contextduty[proxy]'` | Optional — proxy dependencies |
| 7b | `contextduty proxy setup` | Optional — one-time CA cert (needs sudo) |
| 7c | `contextduty proxy start` | Optional — start HTTPS interception |
| 8 | Add MCP config | Optional — intercept AI tool calls |
| 9 | Add CI/CD workflow | Optional — block secrets in PRs |

---

## Scanning and redacting manually

```bash
# Scan a single file
contextduty scan secrets.py

# Scan an entire directory
contextduty scan src/

# Output JSON report
contextduty scan src/ --format json

# Scan with a specific policy
contextduty scan src/ --policy team-policy.json

# Redact a file (original unchanged, clean copy written)
contextduty redact --in secrets.py --out secrets.clean.py
```

---

## Audit log and dashboard

Every interception can be recorded to a JSONL audit log:

```bash
contextduty scan src/ --audit-log ~/.contextduty/audit.jsonl
```

Open the dashboard to browse findings:

```bash
contextduty dashboard                  # reads ~/.contextduty/audit.jsonl
contextduty dashboard --demo           # try with synthetic data
```

---

## Custom detectors

Add your own regex patterns to `.contextduty.json`:

```json
{
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "patient_mrn": "\\bMRN-[0-9]{8}\\b",
    "internal_token": "\\bINT-[A-Z0-9]{24}\\b"
  }
}
```

Set a mode per custom detector:

```json
{
  "detector_modes": {
    "patient_mrn": "block"
  }
}
```

---

## Allow patterns

Suppress specific false positives without disabling a whole detector:

```json
{
  "allow_patterns": {
    "email": ["@example\\.com$", "@test\\.internal$"],
    "phone": ["555-0[0-9]{3}"]
  }
}
```

---

## Policy inheritance

Share a baseline policy across all repos:

```json
{
  "extends": "../../policies/org-baseline.json",
  "mode": "block",
  "detector_modes": {
    "email": "warn"
  }
}
```

The repo-level policy overrides the base. Included baselines: `policies/soc2-baseline.json`, `policies/hipaa-baseline.json`.

---

## Troubleshooting

### `install-hooks` fails with "No .git directory found"
You are not in your project root. Run:
```bash
cd /path/to/your/project    # the folder that contains .git/
contextduty install-hooks
```

### `proxy start` fails with `ModuleNotFoundError`
You have not installed the proxy extra. Run:
```bash
pip install 'contextduty[proxy]'
```

### `proxy start` shows "CA cert not installed yet"
Run the one-time setup first:
```bash
contextduty proxy setup     # requires sudo
```

### Proxy starts but AI tool still sends unredacted requests
Your system proxy is not set. Either:
```bash
contextduty proxy start --set-system-proxy
```
Or manually set HTTP/HTTPS proxy to `127.0.0.1:8080` in your OS network settings.

### A detector is producing false positives
Add an allow pattern in `.contextduty.json`:
```json
{
  "allow_patterns": {
    "email": ["@yourdomain\\.com$"]
  }
}
```

---

## Getting help

- [GitHub Issues](https://github.com/SHUBHAGYTA24/contextduty/issues) — bug reports and feature requests
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to add a detector, AI tool, or API endpoint
- `contextduty --help` — full command reference
- `contextduty <command> --help` — help for a specific command
