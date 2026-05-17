"""
contextduty.hooks
~~~~~~~~~~~~~~~~~
Install / uninstall git pre-commit and pre-push hooks.

  contextduty install-hook [--hook pre-push|pre-commit] [--repo .]
  contextduty uninstall-hook [--hook pre-push|pre-commit] [--repo .]
"""

import stat
from pathlib import Path
from typing import Literal

HookType = Literal["pre-commit", "pre-push"]

# ---------------------------------------------------------------------------
# Hook script templates
# ---------------------------------------------------------------------------

_PRE_COMMIT_SCRIPT = """\
#!/usr/bin/env sh
# ContextDuty pre-commit hook
# Auto-installed by: contextduty install-hook --hook pre-commit
# Remove with:       contextduty uninstall-hook --hook pre-commit
set -e

# Collect staged files
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

if [ -z "$STAGED" ]; then
  exit 0
fi

# Check contextduty is available
if ! command -v contextduty > /dev/null 2>&1; then
  echo "[ContextDuty] WARNING: contextduty not found on PATH, skipping hook." >&2
  exit 0
fi

FAILED=0
for FILE in $STAGED; do
  # Only scan text-like files
  case "$FILE" in
    *.py|*.js|*.ts|*.tsx|*.jsx|*.env|*.env.*|*.json|*.yaml|*.yml|*.toml|*.ini|*.cfg|*.sh|*.bash|*.zsh|*.txt|*.md|*.tf|*.hcl|*.rb|*.go|*.java|*.rs|*.cs|*.php|*.xml|*.conf|*.config)
      ;;
    *)
      continue
      ;;
  esac

  if [ ! -f "$FILE" ]; then
    continue
  fi

  RESULT=$(contextduty scan "$FILE" 2>&1)
  EXIT_CODE=$?

  if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  ContextDuty — SECRET DETECTED, commit blocked       ║"
    echo "╠══════════════════════════════════════════════════════╣"
    echo "║  File: $FILE"
    echo "╚══════════════════════════════════════════════════════╝"
    echo "$RESULT"
    echo ""
    echo "  Fix: remove the secret, then re-stage the file."
    echo "  Use environment variables or a secrets manager instead."
    echo "  Override (not recommended): git commit --no-verify"
    echo ""
    FAILED=1
  fi
done

if [ $FAILED -ne 0 ]; then
  exit 1
fi

echo "[ContextDuty] ✓ No secrets found in staged files."
exit 0
"""

_PRE_PUSH_SCRIPT = """\
#!/usr/bin/env sh
# ContextDuty pre-push hook
# Auto-installed by: contextduty install-hook --hook pre-push
# Remove with:       contextduty uninstall-hook --hook pre-push
set -e

REMOTE="$1"
URL="$2"

# Read pushed refs from stdin (format: <local-ref> <local-sha> <remote-ref> <remote-sha>)
while read local_ref local_sha remote_ref remote_sha; do
  # Skip deletions
  if [ "$local_sha" = "0000000000000000000000000000000000000000" ]; then
    continue
  fi

  # Get list of changed files in this push
  if [ "$remote_sha" = "0000000000000000000000000000000000000000" ]; then
    # New branch — compare against first parent or all commits
    RANGE="$local_sha"
    FILES=$(git diff-tree --no-commit-id -r --name-only "$local_sha" 2>/dev/null || true)
  else
    RANGE="$remote_sha..$local_sha"
    FILES=$(git diff --name-only "$remote_sha" "$local_sha" 2>/dev/null || true)
  fi

  if [ -z "$FILES" ]; then
    continue
  fi

  if ! command -v contextduty > /dev/null 2>&1; then
    echo "[ContextDuty] WARNING: contextduty not found on PATH, skipping hook." >&2
    exit 0
  fi

  FAILED=0
  for FILE in $FILES; do
    case "$FILE" in
      *.py|*.js|*.ts|*.tsx|*.jsx|*.env|*.env.*|*.json|*.yaml|*.yml|*.toml|*.ini|*.cfg|*.sh|*.bash|*.zsh|*.txt|*.md|*.tf|*.hcl|*.rb|*.go|*.java|*.rs|*.cs|*.php|*.xml|*.conf|*.config)
        ;;
      *)
        continue
        ;;
    esac

    if [ ! -f "$FILE" ]; then
      continue
    fi

    RESULT=$(contextduty scan "$FILE" 2>&1)
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ]; then
      echo ""
      echo "╔══════════════════════════════════════════════════════╗"
      echo "║  ContextDuty — SECRET DETECTED, push blocked        ║"
      echo "╠══════════════════════════════════════════════════════╣"
      echo "║  File:   $FILE"
      echo "║  Remote: $REMOTE ($URL)"
      echo "╚══════════════════════════════════════════════════════╝"
      echo "$RESULT"
      echo ""
      echo "  Fix: remove the secret and recommit before pushing."
      echo "  Override (not recommended): git push --no-verify"
      echo ""
      FAILED=1
    fi
  done

  if [ $FAILED -ne 0 ]; then
    exit 1
  fi
done

echo "[ContextDuty] ✓ No secrets found in push."
exit 0
"""

_MARKER = "# ContextDuty pre-commit hook"


def _git_dir(repo) -> Path:
    git_dir = Path(repo) / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(
            f"No .git directory found at {str(repo)!r}. Run from inside a git repository."
        )
    return git_dir


def _build_script(policy_path: str | None = None, audit_log: str | None = None) -> str:
    """Build the pre-commit hook script, optionally embedding policy/audit paths."""
    policy_flag = f" --policy {policy_path}" if policy_path else ""
    audit_flag = f" --audit {audit_log}" if audit_log else ""
    return _PRE_COMMIT_SCRIPT.replace(
        'contextduty scan "$FILE"',
        f'contextduty scan "$FILE"{policy_flag}{audit_flag}',
    )


def install_git_hook(
    repo=None,
    policy_path: str | None = None,
    audit_log: str | None = None,
) -> Path:
    """Install the ContextDuty pre-commit hook.

    Args:
        repo: Path to the git repository root (default: current directory).
        policy_path: Optional path to policy file to embed in the hook script.
        audit_log: Optional path to audit log file to embed in the hook script.

    Returns:
        Path to the installed hook file.

    Raises:
        FileNotFoundError: If no .git directory is found.
        RuntimeError: If a foreign (non-ContextDuty) hook already exists.
    """
    if repo is None:
        repo = "."
    hook_path = _git_dir(repo) / "hooks" / "pre-commit"
    script = _build_script(policy_path=policy_path, audit_log=audit_log)

    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if _MARKER not in existing:
            raise RuntimeError(
                f"A pre-commit hook already exists at {hook_path} and was "
                "not installed by ContextDuty. Remove it manually first."
            )
        # Overwrite our own hook (e.g. to update policy_path/audit_log)

    hook_path.write_text(script, encoding="utf-8")

    # Make executable
    mode = hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    hook_path.chmod(mode)
    return hook_path


def uninstall_git_hook(repo=None) -> bool:
    """Remove the ContextDuty pre-commit hook.

    Returns:
        True if the hook was removed, False if it wasn't installed.

    Raises:
        RuntimeError: If a foreign (non-ContextDuty) hook exists.
    """
    if repo is None:
        repo = "."
    hook_path = _git_dir(repo) / "hooks" / "pre-commit"
    if not hook_path.exists():
        return False

    content = hook_path.read_text(encoding="utf-8")
    if _MARKER not in content:
        raise RuntimeError(f"The pre-commit hook at {hook_path} was not installed by ContextDuty.")

    hook_path.unlink()
    return True


# ---------------------------------------------------------------------------
# Legacy aliases — kept for backward compatibility with CLI code
# ---------------------------------------------------------------------------


def install_hook(hook_type: HookType = "pre-commit", repo: str = ".") -> str:
    """Compatibility shim: install pre-commit hook, return str path."""
    return str(install_git_hook(repo=repo))


def uninstall_hook(hook_type: HookType = "pre-commit", repo: str = ".") -> bool:
    """Compatibility shim: uninstall pre-commit hook."""
    return uninstall_git_hook(repo=repo)
