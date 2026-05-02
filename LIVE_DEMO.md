# ContextDuty Live Demo Runbook

Use this runbook for a 3-5 minute launch demo.

## Demo goal

Show three things quickly:
- baseline scan/redact works in seconds
- custom detection is no-code (policy only)
- enterprise layering and strict governance are built in

## One-time setup

From project root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
chmod +x scripts/live_demo.sh
```

## Fastest demo (single command)

```bash
./scripts/live_demo.sh
```

Artifacts are written under `demo/live/`.

## Manual live demo flow (recommended for recording)

### 1) Show realistic input

```bash
sed -n '1,12p' demo/live/input.txt
```

Talk track: "This is the kind of mixed sensitive context that accidentally ends up in prompts and logs."

### 2) Baseline policy in seconds

```bash
.venv/bin/python -m contextduty.cli init --path demo/live/default-policy.json
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/default-policy.json --report demo/live/default-report.json
.venv/bin/python -m contextduty.cli redact --in demo/live/input.txt --out demo/live/default-clean.txt --policy demo/live/default-policy.json --report demo/live/default-redact-report.json
sed -n '1,12p' demo/live/default-clean.txt
```

Talk track: "Without changing app code, we can detect and mask risky values before data leaves the environment."

### 3) No-code custom policy

```bash
sed -n '1,20p' demo/live/policies/custom-policy.json
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/policies/custom-policy.json --report demo/live/custom-report.json
```

Talk track: "Each team can define domain-specific patterns in JSON, no Python edits needed."

### 4) Enterprise layering + strict validation

```bash
sed -n '1,20p' demo/live/policies/org-baseline.json
sed -n '1,20p' demo/live/policies/team-policy.json
sed -n '1,20p' demo/live/policies/user-policy.json
.venv/bin/python -m contextduty.cli policy validate --policy demo/live/policies/user-policy.json --strict
.venv/bin/python -m contextduty.cli scan demo/live/input.txt --policy demo/live/policies/user-policy.json --report demo/live/layered-report.json
```

Talk track: "Org baseline, team override, and user additions compose cleanly with deterministic precedence."

### 5) Governance fail-fast example

```bash
.venv/bin/python -m contextduty.cli policy validate --policy demo/live/policies/strict-bad-policy.json --strict
```

Expected: non-zero exit with unknown detector error.

Talk track: "Strict mode catches policy drift and typos before runtime."

## Suggested post caption skeleton

"Shipped ContextDuty today: a policy-driven context firewall for AI workflows.  
In this demo: baseline redaction, no-code custom detectors, and enterprise policy layering (`extends`) with strict validation.  
Goal: prevent sensitive context from leaving your environment by default."
