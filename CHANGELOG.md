# Changelog

All notable changes to ContextDuty are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
ContextDuty uses [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-06-24

First stable release. Supersedes the unreleased 0.3.0 work (never published to
PyPI) — everything below ships together as 1.0.0, the first version after 0.2.6.

### Added
- **Microsoft Presidio** as the primary NLP detection backend (spaCy fallback retained) — local, hybrid regex + NLP PII recognition
- **NLP-based PII detection** (`pip install contextduty[nlp]` / `[presidio]`) — catches person names, organisations, locations, dates, and financial entities that regex cannot; context-aware confidence scoring suppresses false positives in code contexts
- **35 new detectors** (total: 60) — full coverage across Cloud/Infra, VCS/CI, Payment, Messaging, AI/ML, Databases, IaC, PII, Healthcare, and Crypto/Web3
- **Audit dashboard v2** — light/dark theme toggle with localStorage persistence, sticky activity table header, detection-method breakdown (Regex vs NLP), top hotspot files chart, client-side filter bar, auto-refresh, JSON API + CSV export
- **Jupyter / Colab / Databricks notebook API** — `guard()`, `redact()`, `scan()` with rich HTML warnings in Jupyter and plain-text fallback in terminals
- **`.ipynb` file scanning** — cell sources, markdown cells, outputs, `display_data`, and `execute_result` blocks all covered
- Local **100k-row NLP benchmark** (`benchmarks/`) measuring latency (p99 ~13 ms) and quality (precision 1.000, F1 0.94 / 0.99 at threshold 0.4)
- Hosted **try-it demo** (Gradio Space, `demo/space/`)

### Changed
- **README fully revamped** — repositioned as a local-first *prompt firewall* built on Presidio, with an honest moat/comparison table (Presidio / GitGuardian / cloud DLP); removed stale and duplicated sections
- Detection brain credited explicitly to Microsoft Presidio; ContextDuty positioned as the enforcement fabric (IDE + git + proxy + MCP + policy), not a new detector
- Dashboard dark theme is now the default; light theme available via toggle
- `_aggregate()` now returns `detection_methods` (regex/nlp split) and `target_totals` (top 10 files by finding count)
- Test count: 258 → 383

### Stats
- 383 tests · 60 built-in detectors · 21 AI API endpoints · 6 AI tool ignore files · 18 CLI commands

---

## [0.2.0] — 2026-05-16

### Added
- **Universal workspace protection** (`contextduty protect`) — one command generates ignore files for 6 AI tools: Cursor, GitHub Copilot, Codeium/Windsurf, Tabnine, Amazon Q, Sourcegraph Cody
- **HTTPS proxy** (`contextduty proxy start`) — intercepts traffic to 21 AI API endpoints, redacts secrets from request bodies in real-time
- **Declarative field walker** — knows where each AI provider puts user content in their JSON; adding a new provider = add field paths, zero code changes
- **Watch mode** (`contextduty protect watch`) — background daemon auto-updates all ignore files when workspace changes
- **Pre-commit hooks** (`contextduty install-hooks`) — blocks commits containing secrets
- **Interactive demo** (`contextduty demo`) — 5-scene walkthrough in 20 seconds
- **Audit dashboard** (`contextduty dashboard`) — local web UI with timeline, detector breakdown, CSV export
- **Per-detector modes** — block on API keys, warn on emails, redact everything else
- **Allow patterns** — whitelist known-safe values per detector
- **20 new detectors** (total: 25) — anthropic_key, openai_key, github_pat, gcp_service_account, huggingface_token, slack_token, stripe_webhook, sendgrid_key, mailchimp_key, npm_token, twilio_sid, azure_storage_key, db_dsn, ssh_private_key, pgp_private_key, private_key_pem, google_oauth_token, jwt, env_secret, aws_secret
- **Enterprise architecture** — centralized config, typed exception hierarchy, NO_COLOR-compliant UI, adapters layer

### Changed
- Restructured into domain packages: `core/`, `ui/`, `adapters/`, `proxy/`
- Policy errors now raise typed `PolicyValidationError`/`PolicyCycleError` (backward-compatible with `ValueError`)
- Engine uses centralized `BINARY_EXTENSIONS` and `SKIP_DIRECTORIES` from config

### Stats
- 258 tests (up from ~30 in v0.1.0)
- 18 CLI commands
- 21 AI API endpoints intercepted
- 6 AI tool ignore files generated

---

## [0.1.0] — 2026-05-02

### Added
- `contextduty scan` — scan a file and emit a JSON findings report
- `contextduty redact` — redact sensitive values and write a clean output file
- `contextduty init` — scaffold a `.contextduty.json` policy file
- `contextduty policy validate` — validate and resolve a layered policy, with optional `--strict` mode
- Five built-in detectors: `email`, `phone`, `api_key`, `aws_key`, `bearer_token`
- Custom detector support via `custom_detectors` in the policy file (regex, no code changes)
- Policy layering via `extends` (string or list of relative paths, cycle detection included)
- Three enforcement modes: `redact`, `warn`, `block`
- Deterministic masking — same input value always produces the same mask token
- MCP stdio server (`contextduty-mcp`) exposing `contextduty_scan` and `contextduty_redact` tools
- SOC 2 and HIPAA compliance policy pack baselines (`policies/`)
- MIT license, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
