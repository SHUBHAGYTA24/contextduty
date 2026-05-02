# Changelog

All notable changes to ContextDuty are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
ContextDuty uses [Semantic Versioning](https://semver.org/).

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
