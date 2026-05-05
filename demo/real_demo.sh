#!/usr/bin/env bash
# ContextDuty — real-world demo
#
# Scenario: A developer at a startup has 3 files with secrets scattered across
# them — a .env, a Python settings file, and a deployment script. They're about
# to paste config into Cursor and push to GitHub. ContextDuty stops both.
#
# Acts:
#   1. Show the problem: files with real-looking secrets
#   2. Scan: 25 detectors catch everything across all 3 files
#   3. Redact: clean versions produced for safe use
#   4. Pre-commit hook: blocks the git commit before it reaches origin
#   5. MCP: shows what Cursor would have sent to OpenAI — and what it sends instead
#
# Usage:
#   cd <repo-root>
#   pip install -e .
#   bash demo/real_demo.sh
#
# To record: asciinema rec --overwrite demo/real-demo.cast -- bash demo/real_demo.sh

set -euo pipefail

BOLD='\033[1m'
CYAN='\033[36m'
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
MAGENTA='\033[35m'
DIM='\033[2m'
RESET='\033[0m'

DEMO_DIR="demo/real"
PAUSE="${DEMO_PAUSE:-1.2}"

_hr()    { echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }
_title() { echo ""; _hr; echo -e "${BOLD}${CYAN}  $1${RESET}"; _hr; echo ""; }
_step()  { echo -e "${BOLD}${YELLOW}▶ $1${RESET}"; }
_cmd()   { echo -e "  ${DIM}\$ $1${RESET}"; }
_ok()    { echo -e "${GREEN}  ✓ $1${RESET}"; }
_warn()  { echo -e "${YELLOW}  ⚠ $1${RESET}"; }
_block() { echo -e "${RED}  ✗ $1${RESET}"; }
_info()  { echo -e "${MAGENTA}  → $1${RESET}"; }
_pause() { sleep "$PAUSE"; }

# ── sanity check ──────────────────────────────────────────────────────────────
if ! command -v contextduty &>/dev/null; then
  echo "contextduty not found. Run: pip install -e ."
  exit 1
fi

# ── setup: block policy ───────────────────────────────────────────────────────
BLOCK_POLICY=$(mktemp /tmp/cd-block-policy-XXXX.json)
cat > "$BLOCK_POLICY" <<'JSON'
{
  "mode": "block",
  "detectors": [
    "email", "phone", "api_key", "bearer_token",
    "aws_key", "aws_secret", "gcp_service_account", "google_oauth_token",
    "github_pat", "openai_key", "anthropic_key", "huggingface_token",
    "slack_token", "stripe_webhook", "sendgrid_key", "mailchimp_key",
    "npm_token", "twilio_sid", "azure_storage_key",
    "db_dsn", "ssh_private_key", "pgp_private_key", "private_key_pem",
    "jwt", "env_secret"
  ],
  "custom_detectors": {}
}
JSON

# ── Act 1: THE PROBLEM ────────────────────────────────────────────────────────
_title "Act 1 — The situation: 3 files, secrets in all of them"

_step "A startup's backend repo. Sprint is closing. These files exist:"
echo ""
echo -e "  ${BOLD}demo/real/.env${RESET}               (environment variables)"
echo -e "  ${BOLD}demo/real/config/settings.py${RESET} (Python config — hotfix from last week)"
echo -e "  ${BOLD}demo/real/scripts/deploy.sh${RESET}  (deployment script)"
echo ""
_step "The developer is about to:"
echo ""
_warn "paste settings.py into Cursor to ask Claude for a code review"
_warn "git push all three files to the remote (it's a private repo, 'should be fine')"
echo ""
_pause

_step "What's actually in these files:"
echo ""
_cmd "head -12 demo/real/.env"
echo ""
head -12 "$DEMO_DIR/.env"
echo ""
_pause

# ── Act 2: SCAN ───────────────────────────────────────────────────────────────
_title "Act 2 — Scan: what ContextDuty finds (25 detectors, zero cloud calls)"

_step "Scan .env"
_cmd "contextduty scan demo/real/.env"
echo ""
contextduty scan "$DEMO_DIR/.env" || true
echo ""
_pause

_step "Scan settings.py"
_cmd "contextduty scan demo/real/config/settings.py"
echo ""
contextduty scan "$DEMO_DIR/config/settings.py" || true
echo ""
_pause

_step "Scan deploy.sh"
_cmd "contextduty scan demo/real/scripts/deploy.sh"
echo ""
contextduty scan "$DEMO_DIR/scripts/deploy.sh" || true
echo ""
_ok "All findings reported. Nothing sent anywhere. No API call, no network request."
_pause

# ── Act 3: REDACT ─────────────────────────────────────────────────────────────
_title "Act 3 — Redact: produce clean files for safe use"

CLEAN_DIR=$(mktemp -d /tmp/cd-clean-XXXX)

_step "Redact all three files"
_cmd "contextduty redact --in demo/real/.env --out /tmp/clean/.env"
contextduty redact --in "$DEMO_DIR/.env"               --out "$CLEAN_DIR/.env"               > /dev/null
contextduty redact --in "$DEMO_DIR/config/settings.py" --out "$CLEAN_DIR/settings.py"        > /dev/null
contextduty redact --in "$DEMO_DIR/scripts/deploy.sh"  --out "$CLEAN_DIR/deploy.sh"          > /dev/null
_ok "All three files redacted."
echo ""

_step "What the .env looks like after redaction — safe to paste anywhere:"
echo ""
cat "$CLEAN_DIR/.env"
echo ""
_ok "Masks are deterministic: same secret → same mask across every file and log line."
_info "You can grep '<GITHUB_PAT_' across your entire audit trail to correlate findings."
_pause

# ── Act 4: PRE-COMMIT HOOK ────────────────────────────────────────────────────
_title "Act 4 — Pre-commit hook: block the git commit before it reaches origin"

# Gracefully skip if install-hooks command isn't available yet
if ! contextduty install-hooks --help &>/dev/null; then
  _info "install-hooks ships in PR #8 (feature/precommit-hook) — merge that PR to enable this act."
  _info "Skipping to Act 5."
  _pause
else

_step "Install the hook (one command, installs to .git/hooks/pre-commit)"
_cmd "contextduty install-hooks"
echo ""

# Use a temp git repo so we don't mess with the real one
DEMO_REPO=$(mktemp -d /tmp/cd-demo-repo-XXXX)
git init -q "$DEMO_REPO"
contextduty install-hooks --repo "$DEMO_REPO" --policy "$BLOCK_POLICY" 2>&1 | sed 's|/tmp/cd-demo-repo-[^/]*/||g'
echo ""

# Stage the .env file in the demo repo
cp "$DEMO_DIR/.env" "$DEMO_REPO/.env"
git -C "$DEMO_REPO" add .env

_step "Developer runs: git commit -m 'add env config'"
_cmd "git commit -m 'add env config'"
echo ""

# Run the hook script directly (avoids needing git hooks to execute in CI)
HOOK="$DEMO_REPO/.git/hooks/pre-commit"
if bash "$HOOK" 2>&1; then
  echo ""
  _block "Commit would have gone through — hook not working"
else
  echo ""
  _ok "Hook blocked the commit. Secrets never reached the remote."
fi
_pause

_step "Fix: redact first, then commit the clean version"
_cmd "contextduty redact --in .env --out .env  &&  git commit -m 'add env config'"
echo ""
cp "$CLEAN_DIR/.env" "$DEMO_REPO/.env"
git -C "$DEMO_REPO" add .env
if bash "$HOOK" 2>&1; then
  git -C "$DEMO_REPO" -c user.email="demo@contextduty.dev" -c user.name="Demo" \
    commit -q -m "add env config" 2>&1 || true
  _ok "Clean file committed. No secrets in history."
fi
rm -rf "$DEMO_REPO"
_pause

fi  # end install-hooks guard

# ── Act 5: MCP / AI PROMPT BOUNDARY ──────────────────────────────────────────
_title "Act 5 — MCP server: intercept before the LLM sees it"

_step "This is the prompt a developer sends to Cursor:"
echo ""
cat <<'PROMPT'
  "Here's my settings.py — can you add retry logic to the DB connection?

   DB_PASS = 'Xk9#mP2qR8vL'
   DATABASE_URL = 'postgresql://app_user:Xk9#mP2qR8vL@prod-db.us-east-1.rds.amazonaws.com/myapp_prod'
   AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
   GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'"
PROMPT
echo ""
_warn "Without ContextDuty: OpenAI/Anthropic receives the DB password, AWS secret key, GitHub token."
echo ""
_pause

_step "With ContextDuty MCP active, the tool intercepts via contextduty_scan_text:"
echo ""

PROMPT_TEXT="DB_PASS = 'Xk9#mP2qR8vL'
DATABASE_URL = 'postgresql://app_user:Xk9#mP2qR8vL@prod-db.us-east-1.rds.amazonaws.com/myapp_prod'
AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
GITHUB_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'"

REDACTED=$(echo "$PROMPT_TEXT" | python3 -c "
import sys, json
sys.path.insert(0, 'src')
from contextduty.engine import scan_text
from contextduty.policy import load_policy
policy = load_policy(None)
result = scan_text(sys.stdin.read(), policy)
print(result.redacted_text)
")

echo -e "${DIM}  ┌─ What the LLM actually receives ──────────────────────────────────┐${RESET}"
while IFS= read -r line; do
  echo -e "${DIM}  │${RESET} $line"
done <<< "$REDACTED"
echo -e "${DIM}  └────────────────────────────────────────────────────────────────────┘${RESET}"
echo ""
_ok "Credentials stripped. LLM gets the structure, not the secrets."
_info "Cursor can still answer the retry logic question. It just can't leak your keys."
_pause

# ── cleanup ───────────────────────────────────────────────────────────────────
rm -rf "$CLEAN_DIR" "$BLOCK_POLICY"

# ── summary ───────────────────────────────────────────────────────────────────
_title "Summary — three enforcement layers, one tool"

echo -e "  ${BOLD}Layer 1 — AI prompt boundary (MCP)${RESET}"
echo    "    contextduty-mcp intercepts prompts before they reach the LLM."
echo    "    Works with Cursor, VS Code, Claude Code, any MCP-compatible client."
echo ""
echo -e "  ${BOLD}Layer 2 — Pre-commit hook${RESET}"
echo    "    contextduty install-hooks  blocks commits containing secrets."
echo    "    One command. Shell script. Survives virtualenv switches."
echo ""
echo -e "  ${BOLD}Layer 3 — CI scan${RESET}"
echo    "    contextduty scan <file> --policy .contextduty.json  in block mode."
echo    "    Non-zero exit fails the pipeline."
echo ""
echo -e "  ${BOLD}25 detectors${RESET} across AWS, GCP, GitHub, OpenAI, Anthropic, Slack,"
echo    "  Stripe, DB DSNs, SSH/PGP keys, JWTs, .env secrets, and more."
echo ""
echo -e "  ${DIM}Zero dependencies. No cloud calls. Deterministic masks.${RESET}"
echo ""
_hr
echo ""
echo -e "  ${BOLD}pip install contextduty${RESET}"
echo    "  contextduty init"
echo    "  contextduty install-hooks"
echo    "  # drop contextduty-mcp into your Cursor/VS Code config"
echo ""
echo -e "  ${DIM}github.com/SHUBHAGYTA24/contextduty${RESET}"
echo ""
