# Contributing to ContextDuty

Thanks for your interest in contributing.

## First-time setup
After cloning, install the git hook:
    cp .github/hooks/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push

## Development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
```

## Common commands

```bash
.venv/bin/python -m contextduty.cli init
.venv/bin/python -m contextduty.cli scan sample.txt --report report.json
.venv/bin/python -m contextduty.cli redact --in sample.txt --out clean.txt --report redact-report.json
.venv/bin/python -m contextduty.cli policy validate --policy .contextduty.json --strict
```

## Pull requests

- Keep PRs focused and small.
- Include a short "why" in your PR description.
- Update docs (`README.md`, `USER_GUIDE.md`) when behavior changes.
- Add or update tests when test infrastructure is present.

## Code style

- Prefer clear, explicit Python.
- Keep public-facing error messages actionable.
- Preserve backward compatibility for existing policy files when possible.
