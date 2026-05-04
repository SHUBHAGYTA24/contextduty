#!/usr/bin/env sh
# ContextDuty hook installer
# Usage: bash scripts/install-pre-commit-hook.sh [--hook pre-push|pre-commit]
#
# This script is intentionally dependency-free — it works even before
# contextduty is installed, and is safe to pipe via curl.

set -e

HOOK_TYPE="${1:-pre-push}"
GIT_DIR=$(git rev-parse --git-dir 2>/dev/null) || {
  echo "Error: not inside a git repository."
  exit 1
}

HOOK_PATH="$GIT_DIR/hooks/$HOOK_TYPE"
MARKER="# ContextDuty hook"

# Already installed?
if [ -f "$HOOK_PATH" ] && grep -q "$MARKER" "$HOOK_PATH" 2>/dev/null; then
  echo "[ContextDuty] Hook already installed at $HOOK_PATH"
  exit 0
fi

if [ "$HOOK_TYPE" = "pre-commit" ]; then
cat >> "$HOOK_PATH" << 'HOOK_BODY'
# ContextDuty hook — auto-installed by scripts/install-pre-commit-hook.sh
#!/usr/bin/env sh
set -e
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
[ -z "$STAGED" ] && exit 0
command -v contextduty > /dev/null 2>&1 || { echo "[ContextDuty] Not found on PATH, skipping."; exit 0; }
FAILED=0
for FILE in $STAGED; do
  case "$FILE" in *.py|*.js|*.ts|*.env|*.env.*|*.json|*.yaml|*.yml|*.toml|*.sh|*.tf|*.hcl|*.rb|*.go|*.java|*.rs|*.cs|*.php|*.conf) ;;
    *) continue ;;
  esac
  [ -f "$FILE" ] || continue
  RESULT=$(contextduty scan "$FILE" 2>&1)
  [ $? -eq 0 ] || { echo "[ContextDuty] ❌ Secret found in $FILE — commit blocked."; echo "$RESULT"; FAILED=1; }
done
[ $FAILED -eq 0 ] && echo "[ContextDuty] ✓ No secrets in staged files." || exit 1
HOOK_BODY
else
cat >> "$HOOK_PATH" << 'HOOK_BODY'
# ContextDuty hook — auto-installed by scripts/install-pre-commit-hook.sh
#!/usr/bin/env sh
set -e
command -v contextduty > /dev/null 2>&1 || { echo "[ContextDuty] Not found on PATH, skipping."; exit 0; }
while read local_ref local_sha remote_ref remote_sha; do
  [ "$local_sha" = "0000000000000000000000000000000000000000" ] && continue
  if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
    FILES=$(git diff-tree --no-commit-id -r --name-only "$local_sha" 2>/dev/null || true)
  else
    FILES=$(git diff --name-only "$remote_sha" "$local_sha" 2>/dev/null || true)
  fi
  FAILED=0
  for FILE in $FILES; do
    case "$FILE" in *.py|*.js|*.ts|*.env|*.env.*|*.json|*.yaml|*.yml|*.toml|*.sh|*.tf|*.hcl|*.rb|*.go|*.java|*.rs|*.cs|*.php|*.conf) ;;
      *) continue ;;
    esac
    [ -f "$FILE" ] || continue
    RESULT=$(contextduty scan "$FILE" 2>&1) && continue
    echo "[ContextDuty] ❌ Secret in $FILE — push blocked."; echo "$RESULT"; FAILED=1
  done
  [ $FAILED -eq 0 ] || exit 1
done
echo "[ContextDuty] ✓ No secrets detected."
HOOK_BODY
fi

chmod +x "$HOOK_PATH"
echo "[ContextDuty] ✓ $HOOK_TYPE hook installed at $HOOK_PATH"
echo "  To remove: contextduty uninstall-hook --hook $HOOK_TYPE"
echo "  Or manually: rm $HOOK_PATH"