#!/usr/bin/env bash
# =============================================================================
# ContextDuty — Pre-Commit Hook Demo
# =============================================================================
# Run this script from OUTSIDE your repo to see the full hook lifecycle.
# It creates a throwaway git repo, installs the hook, and shows both the
# BLOCKED and ALLOWED commit paths.
#
# Usage:
#   chmod +x demo_hooks.sh
#   ./demo_hooks.sh
#
# Requirements:
#   pip install contextduty   (or: pip install -e . from repo root)
# =============================================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}▶ $1${RESET}"; }
ok()    { echo -e "${GREEN}✓ $1${RESET}"; }
info()  { echo -e "${YELLOW}  $1${RESET}"; }
sep()   { echo -e "\n${BOLD}────────────────────────────────────────────────${RESET}"; }

# ── 1. Create a throwaway git repo ───────────────────────────────────────────
sep
step "Creating a fresh demo git repo in /tmp/contextduty-demo"
DEMO_DIR=$(mktemp -d /tmp/contextduty-demo-XXXX)
cd "$DEMO_DIR"
git init -q
git config user.email "demo@contextduty.dev"
git config user.name  "ContextDuty Demo"
ok "Repo created at $DEMO_DIR"

# ── 2. Set up a block-mode policy ────────────────────────────────────────────
sep
step "Writing .contextduty.json (block mode — aws_key, api_key, email)"
cat > .contextduty.json << 'JSON'
{
  "mode": "block",
  "detectors": ["aws_key", "api_key", "email"],
  "custom_detectors": {}
}
JSON
ok "Policy written"
cat .contextduty.json

# ── 3. Install the pre-commit hook ────────────────────────────────────────────
sep
step "Installing ContextDuty pre-commit hook"
contextduty install-hooks --policy .contextduty.json
ok "Hook installed"
echo ""
info "Hook contents:"
echo "────────────────────────────────────────────────"
head -20 .git/hooks/pre-commit
echo "  ... (truncated)"
echo "────────────────────────────────────────────────"

# ── 4. Commit a CLEAN file — should PASS ─────────────────────────────────────
sep
step "DEMO 1 — Committing a clean file (should PASS)"
cat > clean_config.py << 'PY'
# Safe configuration — no secrets here
DB_HOST = "localhost"
DB_PORT = 5432
DEBUG = False
PY
git add clean_config.py
echo ""
info "Attempting: git commit -m 'Add clean config'"
if git commit -m "Add clean config"; then
    ok "Commit ALLOWED — no secrets found ✓"
else
    echo -e "${RED}✗ Unexpected block on clean file${RESET}"
fi

# ── 5. Commit a file with an AWS key — should BLOCK ──────────────────────────
sep
step "DEMO 2 — Committing a file with an AWS key (should BLOCK)"
cat > deploy.sh << 'SH'
#!/bin/bash
# Deployment script
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
echo "Deploying to production..."
SH
git add deploy.sh
echo ""
info "Attempting: git commit -m 'Add deploy script'"
if git commit -m "Add deploy script"; then
    echo -e "${RED}✗ Commit should have been blocked!${RESET}"
else
    ok "Commit BLOCKED — AWS key detected ✓"
fi

# ── 6. Commit a file with an email — should BLOCK ────────────────────────────
sep
step "DEMO 3 — Committing a hardcoded email (should BLOCK)"
cat > app_config.py << 'PY'
# App configuration
ADMIN_EMAIL = "admin@acme-corp-internal.com"
SUPPORT_EMAIL = "support@acme-corp-internal.com"
API_KEY = "sk-prod-abcdef1234567890abcdef1234567890"
PY
git add app_config.py
echo ""
info "Attempting: git commit -m 'Add app config'"
if git commit -m "Add app config"; then
    echo -e "${RED}✗ Commit should have been blocked!${RESET}"
else
    ok "Commit BLOCKED — email + api_key detected ✓"
fi

# ── 7. Redact the file, then commit ──────────────────────────────────────────
sep
step "DEMO 4 — Redact the file first, then commit (should PASS)"
contextduty redact --in app_config.py --out app_config_redacted.py
echo ""
info "Redacted file:"
echo "────────────────────────────────────────────────"
cat app_config_redacted.py
echo "────────────────────────────────────────────────"
cp app_config_redacted.py app_config.py
git add app_config.py
echo ""
info "Attempting: git commit -m 'Add redacted app config'"
if git commit -m "Add redacted app config"; then
    ok "Commit ALLOWED — secrets redacted before commit ✓"
else
    echo -e "${RED}✗ Unexpected block after redaction${RESET}"
fi

# ── 8. Bypass with --no-verify (shows the escape hatch) ──────────────────────
sep
step "DEMO 5 — Using --no-verify to bypass (escape hatch, NOT recommended)"
cat > risky.py << 'PY'
PASSWORD = "super-secret-password-123"
PY
git add risky.py
info "Attempting: git commit --no-verify (bypasses all hooks)"
git commit --no-verify -m "Add risky file (bypassed hook)"
ok "Commit allowed via --no-verify — but this is logged in your audit trail"

# ── 9. Uninstall ──────────────────────────────────────────────────────────────
sep
step "DEMO 6 — Uninstalling the hook"
contextduty uninstall-hooks
ok "Hook removed"
if [ ! -f .git/hooks/pre-commit ]; then
    ok "Confirmed: .git/hooks/pre-commit no longer exists"
fi

# ── 10. pre-commit framework usage ───────────────────────────────────────────
sep
step "BONUS — Using with the pre-commit framework (.pre-commit-config.yaml)"
cat << 'YAML'
# Add this to your .pre-commit-config.yaml:

repos:
  - repo: https://github.com/SHUBHAGYTA24/contextduty
    rev: v0.1.0
    hooks:
      - id: contextduty-scan
YAML
info "Then run: pre-commit install && pre-commit run --all-files"

# ── Summary ───────────────────────────────────────────────────────────────────
sep
echo -e "${BOLD}${GREEN}Demo complete!${RESET}"
echo ""
echo "  Commands shown:"
echo "   contextduty install-hooks [--policy <path>] [--audit-log <path>]"
echo "   contextduty uninstall-hooks"
echo "   contextduty redact --in <file> --out <file>"
echo "   contextduty scan <file>"
echo ""
echo "  Repo used: $DEMO_DIR"
echo "  Clean up:  rm -rf $DEMO_DIR"
echo ""