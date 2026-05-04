"""Tests for git hook installation and pre-commit scanning."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from contextduty.hooks import install_git_hook, pre_commit_entrypoint, uninstall_git_hook


def _make_git_repo(path: Path) -> Path:
    """Create a minimal git repo structure for testing."""
    (path / ".git" / "hooks").mkdir(parents=True)
    return path


def run(*args) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "contextduty.cli", *args],
        capture_output=True,
        text=True,
    )


# ---------------------------------------------------------------------------
# install_git_hook
# ---------------------------------------------------------------------------


def test_install_hook_creates_file(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = install_git_hook(repo)
    assert hook_path.exists()
    assert hook_path.name == "pre-commit"


def test_install_hook_is_executable(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = install_git_hook(repo)
    mode = hook_path.stat().st_mode
    assert mode & stat.S_IEXEC


def test_install_hook_contains_policy_path(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = install_git_hook(repo, policy_path="/org/policy.json")
    content = hook_path.read_text()
    assert "/org/policy.json" in content


def test_install_hook_contains_audit_log(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = install_git_hook(repo, audit_log="/var/log/audit.jsonl")
    content = hook_path.read_text()
    assert "/var/log/audit.jsonl" in content


def test_install_hook_contains_contextduty_marker(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = install_git_hook(repo)
    assert "ContextDuty pre-commit hook" in hook_path.read_text()


def test_install_hook_no_git_dir_raises(tmp_path):
    with pytest.raises(FileNotFoundError, match=".git"):
        install_git_hook(tmp_path)


def test_install_hook_overwrites_own_hook(tmp_path):
    repo = _make_git_repo(tmp_path)
    install_git_hook(repo, policy_path="old.json")
    hook_path = install_git_hook(repo, policy_path="new.json")
    assert "new.json" in hook_path.read_text()


def test_install_hook_refuses_foreign_hook(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.write_text("#!/bin/bash\necho 'some other hook'\n")
    with pytest.raises(RuntimeError, match="not installed by ContextDuty"):
        install_git_hook(repo)


# ---------------------------------------------------------------------------
# uninstall_git_hook
# ---------------------------------------------------------------------------


def test_uninstall_hook_removes_file(tmp_path):
    repo = _make_git_repo(tmp_path)
    install_git_hook(repo)
    removed = uninstall_git_hook(repo)
    assert removed is True
    assert not (repo / ".git" / "hooks" / "pre-commit").exists()


def test_uninstall_hook_no_hook_returns_false(tmp_path):
    repo = _make_git_repo(tmp_path)
    removed = uninstall_git_hook(repo)
    assert removed is False


def test_uninstall_hook_foreign_raises(tmp_path):
    repo = _make_git_repo(tmp_path)
    hook_path = repo / ".git" / "hooks" / "pre-commit"
    hook_path.write_text("#!/bin/bash\necho 'other hook'\n")
    with pytest.raises(RuntimeError):
        uninstall_git_hook(repo)


# ---------------------------------------------------------------------------
# pre_commit_entrypoint
# ---------------------------------------------------------------------------


def test_pre_commit_clean_file_exits_zero(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    code = pre_commit_entrypoint([str(f)])
    assert code == 0


def test_pre_commit_finds_secret_but_warn_exits_zero(tmp_path):
    """Default policy is redact/warn — findings but not blocked."""
    f = tmp_path / "config.py"
    f.write_text("email = 'user@example.com'\n")
    # Default policy is redact — not blocked
    code = pre_commit_entrypoint([str(f)])
    assert code == 0


def test_pre_commit_block_mode_exits_one(tmp_path):
    policy = tmp_path / "p.json"
    policy.write_text(
        json.dumps({"mode": "block", "detectors": ["aws_key"], "custom_detectors": {}})
    )
    # Write policy file where contextduty will find it
    import os

    original_dir = os.getcwd()
    os.chdir(tmp_path)
    try:
        f = tmp_path / "creds.txt"
        f.write_text("AKIA1234567890ABCDEF\n")
        (tmp_path / ".contextduty.json").write_text(
            json.dumps({"mode": "block", "detectors": ["aws_key"], "custom_detectors": {}})
        )
        code = pre_commit_entrypoint([str(f)])
        assert code == 1
    finally:
        os.chdir(original_dir)


def test_pre_commit_skips_missing_files(tmp_path):
    code = pre_commit_entrypoint([str(tmp_path / "does_not_exist.txt")])
    assert code == 0


def test_pre_commit_multiple_files(tmp_path):
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing here\n")
    also_clean = tmp_path / "also_clean.txt"
    also_clean.write_text("still nothing\n")
    code = pre_commit_entrypoint([str(clean), str(also_clean)])
    assert code == 0


# ---------------------------------------------------------------------------
# CLI commands: install-hooks / uninstall-hooks
# ---------------------------------------------------------------------------


def test_cli_install_hooks(tmp_path):
    _make_git_repo(tmp_path)
    result = run("install-hooks", "--repo", str(tmp_path))
    assert result.returncode == 0
    assert "installed" in result.stdout.lower()
    assert (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_cli_install_hooks_no_git(tmp_path):
    result = run("install-hooks", "--repo", str(tmp_path))
    assert result.returncode == 1
    assert ".git" in result.stderr


def test_cli_uninstall_hooks(tmp_path):
    _make_git_repo(tmp_path)
    run("install-hooks", "--repo", str(tmp_path))
    result = run("uninstall-hooks", "--repo", str(tmp_path))
    assert result.returncode == 0
    assert "removed" in result.stdout.lower()
    assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()


def test_cli_uninstall_hooks_nothing_to_remove(tmp_path):
    _make_git_repo(tmp_path)
    result = run("uninstall-hooks", "--repo", str(tmp_path))
    assert result.returncode == 0
    assert "nothing" in result.stdout.lower()
