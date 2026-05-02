#!/usr/bin/env bash
set -euo pipefail

echo "== ContextDuty Live Demo =="
echo

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

.venv/bin/python -m pip install -e . >/dev/null

echo "1) Default policy: scan + redact"
.venv/bin/python -m contextduty.cli init --path demo/live/default-policy.json
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/default-policy.json --report demo/live/default-report.json
.venv/bin/python -m contextduty.cli redact --in demo/live/input.txt --out demo/live/default-clean.txt --policy demo/live/default-policy.json --report demo/live/default-redact-report.json
echo

echo "2) No-code custom detector policy"
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/policies/custom-policy.json --report demo/live/custom-report.json
echo

echo "3) Enterprise layering + strict validation"
.venv/bin/python -m contextduty.cli policy validate --policy demo/live/policies/user-policy.json --strict
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/policies/user-policy.json --report demo/live/layered-report.json || true
.venv/bin/python -m contextduty.cli policy validate --policy demo/live/policies/strict-bad-policy.json --strict || true
echo

echo "Artifacts saved under demo/live/"
