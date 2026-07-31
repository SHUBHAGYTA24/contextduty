# Architecture

This document describes the actors, components, data flows, and external
interfaces of ContextDuty. It is the design reference for contributors and for
security review.

## Purpose

ContextDuty is a **local-first prompt firewall**: it detects and redacts secrets
and PII before they leave a developer's machine for an AI tool. Detection is
performed by 60 built-in regex detectors plus an NLP engine
([Microsoft Presidio](https://github.com/microsoft/presidio), with a spaCy
fallback). Everything runs locally; no scanned content is transmitted to the
project or any third party.

## Actors

| Actor | Description | Trust |
|---|---|---|
| **Developer / user** | Runs the CLI, installs the hook/proxy, configures policy. | Trusted operator of their own machine. |
| **AI tool / client** | Cursor, Copilot, Claude, an SDK, etc. that sends prompts to an AI API. | Untrusted with respect to data egress — the thing we filter. |
| **AI API endpoint** | OpenAI, Anthropic, etc. | External; receives only redacted content. |
| **Contributor** | Submits code via PR. | Untrusted until reviewed; see [SECURITY.md](SECURITY.md). |
| **CI/CD (GitHub Actions)** | Builds, tests, signs, and publishes releases. | Trusted pipeline; privileged jobs run only on maintainer tag pushes. |

## Components

| Component | Module | Responsibility |
|---|---|---|
| Detectors | `detectors.py` | 60 named regex patterns + deterministic masking. |
| Engine | `engine.py` | Scan/redact text and files; apply policy modes. |
| Policy | `policy.py` | Load/validate JSON policy, per-detector modes, allow lists, `extends` inheritance. |
| NLP | `nlp/` | Presidio/spaCy NER for free-form PII; confidence scoring. |
| CLI | `cli.py` | User-facing commands. |
| Git hook | `hooks.py` | Pre-commit scan of **staged** content; blocks commits with secrets. |
| Proxy | `proxy/` | Local mitmproxy addon intercepting AI-API traffic; redacts request bodies in-flight. |
| MCP server | `mcp_server.py` | Sanitizes tool-call results before they enter an agent's context. |
| IDE adapters | `adapters/ide.py` | Generates ignore files for 6 AI tools. |
| Dashboard | `dashboard.py` | Local audit-log web UI (localhost only). |
| Audit | `audit.py` | Appends **metadata-only** JSONL entries (never matched content). |

## Data flows (actions)

1. **CLI scan/redact** — user runs `contextduty scan|redact`; the engine reads a
   file/text locally, produces findings and/or a redacted copy. Nothing leaves
   the machine.
2. **Git pre-commit** — on `git commit`, the hook reads the **staged blob** of
   each text file (`git show :file`), scans it, and blocks the commit if a
   block-mode detector fires.
3. **Proxy interception** — the local proxy (127.0.0.1) intercepts requests to
   21 AI-API hosts, parses the provider's JSON body, redacts secrets/PII in the
   user-content fields, and forwards the **redacted** request upstream over
   verified TLS. Blocked requests get a 403 without leaving the machine.
4. **MCP** — when an agent calls a tool, ContextDuty scans the tool result and
   returns a redacted version to the model.
5. **Audit** — any of the above may append a metadata-only entry (timestamp,
   detector names, counts, action) to a local JSONL log; the dashboard reads it.

## External interfaces

These are the released software's external interfaces:

- **CLI commands** — `scan`, `redact`, `protect`, `install-hooks`,
  `uninstall-hooks`, `proxy` (setup/start/stop/status), `dashboard`, `report`,
  `policy validate`, `init`, `demo`. Documented in
  [docs/USER_MANUAL.md](docs/USER_MANUAL.md) and the README.
- **Console entry points** — `contextduty`, `contextduty-mcp`,
  `contextduty-dashboard`, `contextduty-pre-commit` (declared in
  `pyproject.toml`).
- **Python API** — `contextduty.engine` (`scan_text`, `scan_file`,
  `redact_file`), `contextduty.notebook` (`guard`, `redact`, `scan`),
  `contextduty.policy.load_policy`.
- **MCP tools** — `contextduty_scan`, `contextduty_redact` over MCP stdio.
- **Policy file** — `.contextduty.json` schema (mode, detectors,
  custom_detectors, detector_modes, allow_patterns, extends).
- **Audit log** — append-only JSONL, metadata only.
- **Proxy** — local HTTP proxy on `127.0.0.1:8080` (configurable).

## Trust boundaries

- The **machine** is the trust boundary. Unredacted content never crosses it.
- The **proxy** verifies upstream TLS (it does not disable certificate
  verification) so it cannot be used as an interception downgrade.
- The **audit log** and any future centralized telemetry are **metadata only** —
  never matched values — preserving the "we never see your data" property.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the security assessment of these
flows.
