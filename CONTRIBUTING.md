# Contributing to ContextDuty

Thanks for your interest! ContextDuty is an open-source AI context firewall — contributions of all sizes are welcome.

## Contributor License Agreement (required)

Before your first pull request can be merged, you must agree to the
[Contributor License Agreement (CLA)](CLA.md). **You keep the copyright to your
own code** — the CLA simply grants the maintainer the rights needed to evolve
and, in the future, build commercial products from the Project.

To sign: open your pull request, then add a comment with this exact line:

> I have read the ContextDuty CLA and I agree to it. My Contributions are submitted under its terms.

(A CLA-assistant bot may automate this check on your PR.)

## Get started in 3 steps

```bash
git clone https://github.com/SHUBHAGYTA24/contextduty
cd contextduty
pip install -e ".[dev]"
```

That's it. The `contextduty` command is now available in your shell.

## Verify your setup

```bash
make check          # format + lint + all 305 tests
contextduty demo    # see it working end-to-end
```

## Common commands

```bash
contextduty init                              # create a policy file
contextduty scan src/                         # scan a directory
contextduty redact --in secrets.py --out clean.py  # redact a file
contextduty protect                           # generate all AI tool ignore files
contextduty proxy start                       # start HTTPS interception proxy
contextduty dashboard --demo                  # open audit dashboard
```

## What to contribute

| Area | Where to look |
|---|---|
| New detector (e.g. new AI service key) | `src/contextduty/detectors.py` — add one `Detector(name, re.compile(...))` |
| New AI tool ignore file | `src/contextduty/adapters/ide.py` — add one `AITool(...)` entry |
| New AI API endpoint | `src/contextduty/proxy/scope.py` — add host to `AI_API_HOSTS` |
| New NLP entity type | `src/contextduty/nlp/_types.py` and `_scoring.py` — add entity label and context keywords |
| Bug fix | Open an issue first, then a PR |
| Docs | README.md, this file |

## Pull requests

- Keep PRs small and focused on one thing
- Include a clear "why" in the PR description
- Add or update tests — run `make check` before pushing
- The pre-push hook runs automatically and blocks if tests fail

## Project structure (quick map)

```
src/contextduty/
├── detectors.py      ← add new regex detectors here
├── engine.py         ← core scan/redact logic
├── policy.py         ← policy loading and validation
├── adapters/ide.py   ← AI tool ignore file registry
├── proxy/scope.py    ← AI API host list
└── cli.py            ← all CLI commands
```

## Code style

- Python 3.10+, no external dependencies for the core package
- Run `ruff format` and `ruff check` before committing (the pre-push hook does this)
- Keep public error messages short and actionable
- Deterministic behaviour — same input must always produce same output

## Found a bug?

[Open an issue](https://github.com/SHUBHAGYTA24/contextduty/issues) with:
1. What you ran
2. What you expected
3. What actually happened
