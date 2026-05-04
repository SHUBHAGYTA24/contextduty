# ruff: noqa: E501
"""Git hook installation and pre-commit scanning for ContextDuty.

Usage:
    contextduty install-hooks [--audit-log <path>] [--policy <path>]

This writes a git pre-commit hook to .git/hooks/pre-commit that:
1. Gets all staged files from git (text files only)
2. Scans each one against your ContextDuty policy
3. Blocks the commit if any file has findings in block mode
4. Optionally appends to an audit log

The hook is written as a shell script that calls contextduty directly,
so it works even if the engineer switches Python virtualenvs.

Also supports the pre-commit framework (https://pre-commit.com) via
the hooks definition at .pre-commit-hooks.yaml.
"""

from __future__ import annotations

import stat
import sys
from pathlib import Path

# The shell script written to .git/hooks/pre-commit
_HOOK_TEMPLATE = """\
#!/usr/bin/env bash
# ContextDuty pre-commit hook
# Installed by: contextduty install-hooks
# To uninstall: rm .git/hooks/pre-commit
#
# Scans all staged text files against your ContextDuty policy.
# Blocks the commit if any file has findings in block mode.
# Edit CONTEXTDUTY_POLICY and CONTEXTDUTY_AUDIT_LOG below to customise.

set -euo pipefail

CONTEXTDUTY_POLICY="{policy}"
CONTEXTDUTY_AUDIT_LOG="{audit_log}"

# Require contextduty to be installed
if ! command -v contextduty &>/dev/null; then
  echo "[ContextDuty] contextduty not found in PATH."
  echo "  Run: pip install contextduty"
  exit 1
fi

# Get staged files — text files only, skip deleted files
STAGED=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)

if [ -z "$STAGED" ]; then
  exit 0
fi

BLOCKED=0
FINDINGS=0

while IFS= read -r file; do
  # Skip binary files
  if ! file "$file" 2>/dev/null | grep -qE "text|JSON|CSV|XML|script"; then
    continue
  fi

  SCAN_ARGS=("$file")
  if [ -f "$CONTEXTDUTY_POLICY" ]; then
    SCAN_ARGS+=(--policy "$CONTEXTDUTY_POLICY")
  fi
  if [ -n "$CONTEXTDUTY_AUDIT_LOG" ]; then
    SCAN_ARGS+=(--audit-log "$CONTEXTDUTY_AUDIT_LOG")
  fi

  OUTPUT=$(contextduty scan "${{SCAN_ARGS[@]}}" 2>&1)
  EXIT_CODE=$?

  # Parse findings_count from JSON output
  COUNT=$(echo "$OUTPUT" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('findings_count',0))" 2>/dev/null || echo "0")
  FINDINGS=$((FINDINGS + COUNT))

  if [ "$EXIT_CODE" -ne 0 ]; then
    echo ""
    echo "[ContextDuty] BLOCKED: $file"
    echo "$OUTPUT" | python3 -c "
import json, sys
try:
    d = json.loads(sys.stdin.read())
    for det, count in d.get('detector_counts', {{}}).items():
        print(f'  {{det}}: {{count}} finding(s)')
    for det in d.get('blocked_by', []):
        print(f'  → {{det}} is set to block mode')
except Exception:
    pass
" 2>/dev/null || true
    BLOCKED=1
  elif [ "$COUNT" -gt 0 ]; then
    echo "[ContextDuty] WARNING: $file — $COUNT finding(s) (not blocked by current policy)"
  fi
done <<< "$STAGED"

if [ "$BLOCKED" -eq 1 ]; then
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  ContextDuty blocked this commit.                           ║"
  echo "║                                                              ║"
  echo "║  Sensitive values were found in staged files.               ║"
  echo "║  Remove or redact them before committing.                   ║"
  echo "║                                                              ║"
  echo "║  To redact a file:                                          ║"
  echo "║    contextduty redact --in <file> --out <file>              ║"
  echo "║                                                              ║"
  echo "║  To bypass (NOT recommended):                               ║"
  echo "║    git commit --no-verify                                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  exit 1
fi

if [ "$FINDINGS" -gt 0 ]; then
  echo "[ContextDuty] $FINDINGS finding(s) noted (warn mode — commit allowed)"
fi

exit 0
"""

_PRE_COMMIT_HOOKS_YAML = """\
# .pre-commit-hooks.yaml
# ContextDuty hook for use with https://pre-commit.com
#
# Add to your .pre-commit-config.yaml:
#
#   repos:
#     - repo: https://github.com/SHUBHAGYTA24/contextduty
#       rev: v0.1.0
#       hooks:
#         - id: contextduty-scan
#
- id: contextduty-scan
  name: ContextDuty — scan for secrets and PII
  description: Scans staged files for sensitive data before commit.
  entry: contextduty-pre-commit
  language: python
  types: [text]
  pass_filenames: true
  additional_dependencies: []
"""


def install_git_hook(
    repo_root: Path,
    policy_path: str = ".contextduty.json",
    audit_log: str = "",
) -> Path:
    """Write the pre-commit hook to .git/hooks/pre-commit.

    Returns the path to the installed hook.
    Raises FileNotFoundError if the repo root has no .git directory.
    Raises RuntimeError if a non-ContextDuty hook already exists (will not overwrite).
    """
    git_dir = repo_root / ".git"
    if not git_dir.is_dir():
        raise FileNotFoundError(f"No .git directory found at {repo_root}. Is this a git repo?")

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    # Refuse to overwrite a hook we didn't install
    if hook_path.exists():
        existing = hook_path.read_text(encoding="utf-8")
        if "ContextDuty pre-commit hook" not in existing:
            raise RuntimeError(
                f"A pre-commit hook already exists at {hook_path} and was not installed by "
                "ContextDuty. Remove it manually or append ContextDuty to it, then re-run."
            )

    hook_content = _HOOK_TEMPLATE.format(
        policy=policy_path,
        audit_log=audit_log,
    )

    hook_path.write_text(hook_content, encoding="utf-8")
    hook_path.chmod(hook_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return hook_path


def uninstall_git_hook(repo_root: Path) -> bool:
    """Remove the ContextDuty pre-commit hook if present.

    Returns True if removed, False if no ContextDuty hook was found.
    Raises RuntimeError if the hook exists but was not installed by ContextDuty.
    """
    hook_path = repo_root / ".git" / "hooks" / "pre-commit"
    if not hook_path.exists():
        return False
    existing = hook_path.read_text(encoding="utf-8")
    if "ContextDuty pre-commit hook" not in existing:
        raise RuntimeError(
            f"Hook at {hook_path} was not installed by ContextDuty. Remove it manually."
        )
    hook_path.unlink()
    return True


def write_pre_commit_hooks_yaml(repo_root: Path) -> Path:
    """Write .pre-commit-hooks.yaml for use with the pre-commit framework."""
    out = repo_root / ".pre-commit-hooks.yaml"
    out.write_text(_PRE_COMMIT_HOOKS_YAML, encoding="utf-8")
    return out


def pre_commit_entrypoint(files: list[str]) -> int:
    """Entrypoint for contextduty-pre-commit — used by the pre-commit framework.

    Receives staged file paths as arguments (pre-commit passes them automatically).
    Returns exit code: 0 = clean, 1 = blocked.
    """
    from .engine import scan_file
    from .policy import load_policy

    policy_path = Path(".contextduty.json")
    policy = load_policy(policy_path if policy_path.exists() else None)

    blocked = False
    for file_str in files:
        path = Path(file_str)
        if not path.exists() or not path.is_file():
            continue
        try:
            result = scan_file(path, policy)
        except Exception as exc:
            print(f"[ContextDuty] Error scanning {file_str}: {exc}", file=sys.stderr)
            continue

        if result.findings_count > 0:
            print(f"[ContextDuty] {file_str}: {result.findings_count} finding(s)", file=sys.stderr)
            for det, count in result.detector_counts.items():
                print(f"  {det}: {count}", file=sys.stderr)

        if result.blocked:
            blocked = True

    return 1 if blocked else 0


def main_pre_commit() -> None:
    """CLI entrypoint: contextduty-pre-commit <file> [<file> ...]"""
    raise SystemExit(pre_commit_entrypoint(sys.argv[1:]))
