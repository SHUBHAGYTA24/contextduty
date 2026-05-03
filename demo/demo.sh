#!/usr/bin/env bash
# ContextDuty — live demo script
# Runs a 3-scene demo showing scan, redact, block mode, and custom detectors.
# Recommended: record with `asciinema rec demo.cast` then upload to asciinema.org
#
# Usage:
#   cd <repo-root>
#   pip install -e .
#   bash demo/demo.sh

set -e

# ── colours ───────────────────────────────────────────────────────────────────
BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
DIM='\033[2m'
RESET='\033[0m'

# ── helpers ───────────────────────────────────────────────────────────────────
hr()      { echo -e "${DIM}────────────────────────────────────────────────────${RESET}"; }
title()   { echo ""; hr; echo -e "${BOLD}${CYAN}  $1${RESET}"; hr; echo ""; }
step()    { echo -e "${BOLD}${YELLOW}▶ $1${RESET}"; }
cmd()     { echo -e "${DIM}\$ $1${RESET}"; }
ok()      { echo -e "${GREEN}✓ $1${RESET}"; }
pause()   { sleep "${DEMO_PAUSE:-1}"; }

# ── demo input file ───────────────────────────────────────────────────────────
INPUT="demo/input.txt"
CLEAN_OUT="/tmp/contextduty-clean.txt"

# ── scene 0: what's in the file ───────────────────────────────────────────────
title "Scene 1 — This is what ends up in your AI prompt"

step "A realistic mixed log/context file an engineer might paste into Cursor:"
echo ""
cmd "cat $INPUT"
echo ""
cat "$INPUT"
pause

# ── scene 1: scan ─────────────────────────────────────────────────────────────
title "Scene 2 — Scan: detect what's sensitive"

step "Run contextduty scan in warn mode"
cmd "contextduty scan $INPUT"
echo ""
contextduty scan "$INPUT"
echo ""
ok "Findings reported. Nothing changed. No cloud call made."
pause

# ── scene 2: redact ───────────────────────────────────────────────────────────
title "Scene 3 — Redact: mask before the LLM sees it"

step "Redact the file — sensitive values replaced with deterministic masks"
cmd "contextduty redact --in $INPUT --out $CLEAN_OUT"
echo ""
contextduty redact --in "$INPUT" --out "$CLEAN_OUT"
echo ""
step "What the LLM receives instead:"
cmd "cat $CLEAN_OUT"
echo ""
cat "$CLEAN_OUT"
echo ""
ok "Email, token, AWS key, phone — all masked. Same mask every time (deterministic)."
pause

# ── scene 3: block mode / CI ──────────────────────────────────────────────────
title "Scene 4 — Block mode: fail CI if secrets are found"

BLOCK_POLICY="/tmp/block-policy.json"
cat > "$BLOCK_POLICY" <<'JSON'
{
  "mode": "block",
  "detectors": ["email", "phone", "api_key", "aws_key", "bearer_token"],
  "custom_detectors": {}
}
JSON

step "Switch policy to block mode — this is what you put in CI"
cmd "contextduty scan $INPUT --policy $BLOCK_POLICY"
echo ""
set +e
contextduty scan "$INPUT" --policy "$BLOCK_POLICY"
EXIT_CODE=$?
set -e
echo ""
echo -e "${RED}Exit code: $EXIT_CODE${RESET}"
ok "Non-zero exit → pipeline blocked. Commit never reaches the remote."
pause

# ── scene 4: custom detector ──────────────────────────────────────────────────
title "Scene 5 — Custom detector: no code changes needed"

CUSTOM_INPUT="/tmp/custom-input.txt"
CUSTOM_POLICY="/tmp/custom-policy.json"

cat > "$CUSTOM_INPUT" <<'TXT'
Assigned engineer: EMP-482910
Related ticket: TICKET-OPS-0042
Server: api.internal.corp.com
TXT

cat > "$CUSTOM_POLICY" <<'JSON'
{
  "mode": "redact",
  "detectors": [],
  "custom_detectors": {
    "employee_id": "\\bEMP-[0-9]{6}\\b",
    "internal_ticket": "\\bTICKET-[A-Z]{3}-[0-9]{4}\\b"
  }
}
JSON

step "Input with org-specific patterns (not covered by any built-in detector):"
cmd "cat /tmp/custom-input.txt"
echo ""
cat "$CUSTOM_INPUT"
echo ""
step "Policy with custom regex — no Python changes needed:"
cmd "cat /tmp/custom-policy.json"
echo ""
cat "$CUSTOM_POLICY"
echo ""
step "Scan result:"
cmd "contextduty redact --in /tmp/custom-input.txt --out /tmp/custom-clean.txt --policy /tmp/custom-policy.json"
contextduty redact --in "$CUSTOM_INPUT" --out /tmp/custom-clean.txt --policy "$CUSTOM_POLICY"
echo ""
cat /tmp/custom-clean.txt
echo ""
ok "EMP-482910 and TICKET-OPS-0042 redacted with zero code changes."
pause

# ── done ──────────────────────────────────────────────────────────────────────
title "Done"
echo -e "${BOLD}ContextDuty — local-first, policy-driven, zero dependencies.${RESET}"
echo ""
echo "  pip install contextduty"
echo "  contextduty init"
echo "  contextduty scan <file>"
echo ""
echo -e "${DIM}github.com/SHUBHAGYTA24/contextduty${RESET}"
echo ""
