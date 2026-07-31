# ContextDuty

> **The local-first prompt firewall — stop secrets and PII from reaching any AI tool, before the prompt ever leaves your machine.**

[![PyPI version](https://img.shields.io/pypi/v/contextduty.svg)](https://pypi.org/project/contextduty/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml/badge.svg)](https://github.com/SHUBHAGYTA24/contextduty/actions/workflows/ci.yml)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/tests-407%20passing-brightgreen.svg)](#)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13902/badge)](https://www.bestpractices.dev/projects/13902)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/13902/baseline)](https://www.bestpractices.dev/projects/13902)

**Try it live:** [ContextDuty demo on Hugging Face Spaces](https://huggingface.co/spaces/shubhagyta-24/contextduty) · **Detection brain:** [Microsoft Presidio](https://github.com/microsoft/presidio)

```bash
pip install contextduty
contextduty protect          # stop all AI tools from indexing your secrets
contextduty install-hooks    # block commits that contain secrets
```

![ContextDuty — git hook, live AI-traffic proxy, IDE block, and MCP in action](demo/contextduty-firewall.gif)

> Presidio detects PII in a string. ContextDuty **enforces** it on the wire —
> a paste-box can't block your commit, redact your live `api.openai.com`
> traffic, or sanitize an MCP tool call. This is what that looks like.

---

## Why

By 2026, **34.8% of data developers paste into AI tools is sensitive** (Cyberhaven). A secret leaks the moment it's typed into a prompt — long before it ever reaches a repo. Traditional DLP can't see that flow, and enterprise AI plans don't stop an engineer pasting a key into Cursor.

ContextDuty closes every door a developer leaks through — the IDE, a git commit, live AI-API traffic, and MCP tool calls — with **one install, one policy, zero cloud**.

## What it is (and what it isn't)

ContextDuty is **not** a new PII detector. Detection is hard and already solved — so the NLP layer is powered by **[Microsoft Presidio](https://github.com/microsoft/presidio)** (with a spaCy fallback), plus 60 deterministic regex detectors for secrets.

ContextDuty is the **enforcement fabric around that detection**: it wires it into the four places developers actually leak, governs everything with a portable block/warn/redact policy, and runs **100% locally** — no data leaves your machine, no SaaS, MIT-licensed.

> **Presidio is the brain. ContextDuty is the firewall.**

| | Microsoft Presidio | GitGuardian `ggshield` | Cloud DLP (Aona/Lasso/Nightfall) | **ContextDuty** |
|---|---|---|---|---|
| PII detection | ✅ (we use it) | ❌ | ✅ | ✅ via Presidio |
| Secret detection | partial | ✅ (secrets only) | ✅ | ✅ 60 detectors |
| Git pre-commit hook | ❌ | ✅ | ❌ | ✅ |
| IDE indexing block (`.cursorignore`…) | ❌ | ❌ | ❌ | ✅ |
| Live HTTPS proxy over AI-API traffic | ❌ | ❌ | network/browser | ✅ |
| MCP server | ❌ | ❌ | ❌ | ✅ |
| Portable block/warn/redact policy | operators only | limited | cloud console | ✅ one JSON, all surfaces |
| Local-first — nothing leaves the machine | ✅ | cloud engine | ❌ SaaS | ✅ |
| Fleet visibility without shipping content | ❌ | partial (cloud) | ❌ raw data in SaaS | ✅ metadata-only |
| Open-source | ✅ | ❌ | ❌ | ✅ MIT |

---

## The five enforcement surfaces

```mermaid
flowchart LR
    WS["🗂️ Your workspace\n.env · keys/ · config"] --> CD

    subgraph CD["ContextDuty — 60 regex detectors + Presidio NLP"]
        L1["IDE ignore files"]
        L2["git pre-commit hook"]
        L3["HTTPS proxy (21 AI APIs)"]
        L4["MCP server"]
        L5["CI / CD"]
    end

    CD --> AI["✅ AI tools protected\nCursor · Copilot · Claude · Windsurf · Cody · Amazon Q · …"]
```

| Surface | What it does | Command |
|---|---|---|
| **IDE ignore** | Generates ignore files for 6 AI tools so secrets are never indexed | `contextduty protect` |
| **Git hook** | Pre-commit scan blocks secrets from entering history | `contextduty install-hooks` |
| **HTTPS proxy** | Intercepts 21 AI API hosts, redacts secrets from request bodies in-flight | `contextduty proxy start` |
| **MCP server** | Redacts tool-call results before they enter the AI context window | `contextduty-mcp` |
| **CI/CD** | Policy-as-code gate — PRs with secrets exit non-zero | `contextduty scan src/` |

---

## Quick start

```bash
pip install contextduty          # core (regex detectors, hooks, CLI)
cd your-project/                 # run from your git root

contextduty init                 # create .contextduty.json policy
contextduty protect              # write ignore files for all 6 AI tools
contextduty install-hooks        # block secret-bearing commits

# Optional extras
pip install 'contextduty[presidio]'   # NLP PII detection (recommended)
pip install 'contextduty[proxy]'      # live HTTPS interception
```

Scan or redact anything:

```bash
contextduty scan src/                          # JSON findings report
contextduty scan --nlp src/                    # add Presidio NLP PII detection
contextduty redact --in raw.txt --out clean.txt
```

---

## Detection

**60 built-in regex detectors** across Cloud/Infra, VCS/CI, Payment, Messaging, AI/ML, Databases, Generic secrets, IaC, PII, Healthcare, and Crypto/Web3 — including `aws_key`, `github_pat`, `stripe_secret`, `openai_key`, `postgres_dsn`, `ssh`/`pgp` keys, `credit_card`, `ssn`, `jwt_token`, and more. See [`detectors.py`](src/contextduty/detectors.py) for the full list.

**Presidio NLP** catches unstructured PII regex can't — person names, organizations, locations, dates — running entirely locally:

```bash
pip install 'contextduty[presidio]'
python -m spacy download en_core_web_sm
contextduty scan --nlp src/
```

**Live-key verification** (`--verify`, opt-in) — for the keys that support it (GitHub, OpenAI, Stripe, Slack), ContextDuty can make a single read-only call to the credential's *own* provider to tell an active secret from a revoked one, so you triage the real leaks first. It never phones home to ContextDuty — the check goes straight to the issuer.

```bash
contextduty scan --verify src/config.py   # 🔴 LIVE vs ⚪ inactive per finding
```

**Deterministic masks:** `AKIAIOSFODNN7EXAMPLE` always becomes `<AWS_KEY_1a5d44a2dc>` — same value, same mask, everywhere — so audit logs stay correlatable without storing raw secrets.

**Custom detectors** (no code, no redeploy):

```json
{ "custom_detectors": { "employee_id": "\\bEMP-[0-9]{6}\\b" } }
```

**Detector plugins** (for packaged, distributable detector sets) — a separately
installed package can contribute detectors without editing the core, by
registering a factory under the `contextduty.detectors` entry-point group:

```toml
# in the plugin package's pyproject.toml
[project.entry-points."contextduty.detectors"]
my_pack = "my_package.detectors:load"   # load() -> list[Detector]
```

They're discovered automatically and merged with the built-ins. With no plugin
installed, behavior is unchanged.

> 📊 **Benchmarked:** 100k prompts, fully local — p99 latency ~13 ms, precision 1.000, F1 0.94 (0.99 at threshold 0.4). See [benchmarks/README.md](benchmarks/README.md).

---

## Policy

```jsonc
{
  "mode": "redact",                                  // redact | warn | block
  "detectors": ["email", "aws_key", "openai_key", "postgres_dsn"],
  "detector_modes": { "aws_key": "block" },          // per-detector override
  "allow_patterns": { "email": ["@example\\.com$"] },// known-safe values
  "extends": "../../policies/org-baseline.json"      // team baseline + repo override
}
```

| Mode | Behavior |
|---|---|
| `redact` | Replace matches with deterministic masks |
| `warn` | Log findings, don't modify or block |
| `block` | Exit non-zero — for CI and pre-commit hard stops |

Compliance baselines included: [`policies/soc2-baseline.json`](policies/soc2-baseline.json), [`policies/hipaa-baseline.json`](policies/hipaa-baseline.json).

**Central policy distribution** — `extends` also takes an HTTPS URL, so every repo can inherit one org baseline from a single source of truth. Remote policies are integrity-pinned with a SHA-256 hash and plain `http://` is rejected, so a tampered or man-in-the-middled baseline can't silently loosen everyone's rules:

```jsonc
{ "extends": { "url": "https://policies.acme.com/org-baseline.json",
               "sha256": "9f2c…" } }
```

---

## Notebooks, MCP & dashboard

**Jupyter / Colab / Databricks** — one import, zero config:

```python
from contextduty.notebook import guard, redact
guard("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")  # prints a warning
clean = redact("db = postgres://admin:secret@prod:5432/app")               # → <POSTGRES_DSN_…>
```

**MCP server** — redacts tool-call results before they enter the model's context:

```json
{ "mcpServers": { "contextduty": { "command": "contextduty-mcp" } } }
```

**Audit dashboard** — local web UI, all data stays on your machine:

```bash
contextduty dashboard --demo   # synthetic data
contextduty dashboard          # reads ~/.contextduty/audit.jsonl
```

---

## Teams — fleet visibility, metadata only

Everything above runs per-developer. For a team, ContextDuty adds a **self-hosted control plane** that answers "is the whole fleet actually protected?" — *without ever collecting the sensitive data itself*.

Each endpoint reports only **counts and metadata** — how many secrets were caught, which detectors fired, whether the pre-commit hook was bypassed with `--no-verify` — never the matched values, file contents, or masked tokens. The sanitizer allow-lists a fixed set of fields and drops everything else, so the metadata-only guarantee is enforced in code, not policy.

```bash
contextduty team serve --demo         # spin up the fleet dashboard on a synthetic fleet
contextduty team serve --token <secret> --store fleet.jsonl   # real, self-hosted collector
contextduty team enroll --url https://collector.acme.com --token <secret>   # point a repo at it
```

The dashboard shows **coverage** (which endpoints are live vs. dark >24h), **leaks prevented**, **top detectors**, and a **bypass feed** of `--no-verify` commits. It's single-tenant and self-hosted today; the roadmap is a managed, per-enterprise deployment. Because it's metadata-only, it gives security teams fleet oversight that cloud DLP can't — no source code or secrets ever leave the developer's machine.

---

## Commands

| Command | Description |
|---|---|
| `contextduty protect [watch\|status]` | Write/auto-update ignore files for all 6 AI tools |
| `contextduty install-hooks` / `uninstall-hooks` | Manage the git pre-commit hook |
| `contextduty proxy [setup\|start\|stop\|status]` | Manage the HTTPS interception proxy |
| `contextduty scan <file\|dir> [--nlp] [--verify]` | Scan and print JSON findings (`--verify` checks if found keys are live) |
| `contextduty redact --in <f> --out <f>` | Write a redacted copy |
| `contextduty dashboard` / `report` | Audit dashboard / log summary |
| `contextduty team serve [--demo]` | Self-hosted fleet dashboard (metadata-only) — try `--demo` |
| `contextduty team enroll --url <u>` | Point this repo's policy at a team collector |
| `contextduty policy validate` | Validate and resolve a layered policy |
| `contextduty init` | Create a default `.contextduty.json` |
| `contextduty demo` | 20-second interactive walkthrough |

---

## Local development

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
pip install -e ".[dev]"
make check    # format + lint + tests
```

Architecture: `engine.py` (scan/redact), `detectors.py` (60 patterns), `policy.py` (layered policy), `nlp/` (Presidio + spaCy), `proxy/` (mitmproxy field-walker), `adapters/ide.py` (AI tool registry), `dashboard.py` (audit UI). See [docs/USER_MANUAL.md](docs/USER_MANUAL.md).

## Roadmap

- [x] 60 detectors · git hook · MCP · HTTPS proxy (21 APIs) · 6 IDE ignore files
- [x] Presidio NLP PII detection · notebook API · audit dashboard · policy layering
- [x] Local 100k-row latency/quality benchmark · hosted demo Space
- [x] Team layer — self-hosted, metadata-only fleet dashboard · `--no-verify` bypass detection
- [x] Opt-in live-key verification · signed (HTTPS + SHA-256) central policy distribution
- [ ] Managed, per-enterprise team deployment
- [ ] VS Code / Cursor extension
- [ ] Prometheus metrics endpoint
- [ ] International + domain-specific detector packs

## License

MIT. Built on [Microsoft Presidio](https://github.com/microsoft/presidio). Issues and PRs welcome — [open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues) if a detector is missing or misfiring.
