# Dependencies

How ContextDuty selects, obtains, tracks, and updates its dependencies.

## Philosophy

ContextDuty deliberately keeps its **core runtime dependency-free**. The base
`pip install contextduty` pulls in **no third-party runtime dependencies** — the
scan engine, detectors, policy system, CLI, git hook, and MCP server use only
the Python standard library. Heavier capabilities are **opt-in extras** so users
install only what they need.

## How dependencies are declared and obtained

All dependencies are declared in [`pyproject.toml`](pyproject.toml) and obtained
from **PyPI** via `pip`:

| Extra | Dependencies | Purpose |
|---|---|---|
| (core) | none | Regex detection, policy, CLI, hooks, MCP |
| `nlp` | `spacy`, `en-core-web-sm` | spaCy-based NLP PII detection |
| `presidio` | `presidio-analyzer`, `presidio-anonymizer`, `spacy`, `en-core-web-sm` | Preferred NLP backend |
| `proxy` | `mitmproxy` | HTTPS interception proxy |
| `dev` | `pytest` | Tests |

Direct dependencies are the single source of truth in `pyproject.toml`; there
is no vendored/bundled third-party code in the repository.

## Selection criteria

New dependencies are added sparingly and only when they meet these criteria:

- **Necessity** — the capability can't reasonably be met with the standard
  library, and it belongs in an opt-in extra rather than the core.
- **Provenance & health** — actively maintained, widely used, from a reputable
  source (e.g. Microsoft Presidio, Explosion's spaCy, mitmproxy).
- **License compatibility** — permissive/OSI-approved and compatible with MIT.
- **Security posture** — no known unaddressed critical vulnerabilities.

## Tracking and updating

- **Vulnerability tracking** — [`pip-audit`](https://pypi.org/project/pip-audit/)
  runs in CI on every push/PR and weekly on a schedule, flagging known CVEs in
  the dependency tree.
- **SBOM** — a CycloneDX SBOM is generated in CI and attached to every tagged
  release, giving downstream consumers a machine-readable dependency inventory.
- **Updates** — dependency version constraints are reviewed when `pip-audit`
  reports an issue, when an extra's upstream ships a relevant fix, and at
  release time. Updates land via pull request and must pass CI.

## Building from source

See [CONTRIBUTING.md](CONTRIBUTING.md) for full build/dev setup. In brief:

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
pip install -e ".[dev]"     # add ",presidio" / ",proxy" for those features
make check                  # format + lint + tests
```
