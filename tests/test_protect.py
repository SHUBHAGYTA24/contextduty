"""Tests for the universal AI workspace protection module."""

from __future__ import annotations

from pathlib import Path

from contextduty.policy import load_policy
from contextduty.protect import (
    AI_API_HOSTS,
    AI_TOOLS,
    _scan_workspace,
    _write_ignore_file,
    protect_workspace,
)


def _make_workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        fpath = tmp_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    return tmp_path


def test_ai_tools_registry_has_entries():
    assert len(AI_TOOLS) >= 5
    names = [t.name for t in AI_TOOLS]
    assert "Cursor" in names
    assert "GitHub Copilot" in names


def test_ai_api_hosts_registry_comprehensive():
    assert "api.openai.com" in AI_API_HOSTS
    assert "api.anthropic.com" in AI_API_HOSTS
    assert "api2.cursor.sh" in AI_API_HOSTS
    assert "api.deepseek.com" in AI_API_HOSTS
    assert "api.mistral.ai" in AI_API_HOSTS
    assert len(AI_API_HOSTS) >= 15


def test_protect_writes_all_ignore_files(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(tmp_path, {"config.py": f'KEY = "{aws_key}"'})
    rc = protect_workspace(ws)
    assert rc == 0

    # Check all ignore files were created
    assert (ws / ".cursorignore").exists()
    assert (ws / ".copilotignore").exists()
    assert (ws / ".codeiumignore").exists()
    assert (ws / ".tabnine_ignore").exists()

    # Verify content
    content = (ws / ".cursorignore").read_text()
    assert "config.py" in content
    assert "aws_key" in content


def test_protect_clean_workspace_no_files(tmp_path, capsys):
    ws = _make_workspace(tmp_path, {"app.py": "print('hello')"})
    rc = protect_workspace(ws)
    assert rc == 0
    # Should NOT create ignore files if workspace is clean
    assert not (ws / ".cursorignore").exists()


def test_protect_skips_hidden_and_vendor_dirs(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(tmp_path, {
        ".git/config": f'key = {aws_key}',
        "node_modules/pkg/x.js": f'k = "{aws_key}"',
        "vendor/lib.go": f'k = "{aws_key}"',
        "src/main.py": "print('clean')",
    })
    policy = load_policy(None)
    results = _scan_workspace(ws, policy)
    assert results == []


def test_write_ignore_file_preserves_manual(tmp_path):
    tool = AI_TOOLS[0]  # Cursor
    ignore_path = tmp_path / tool.ignore_file
    # Pre-existing content
    ignore_path.write_text(
        "# ── AUTO-START (do not edit between START/END) ──\nold.py  # email\n# ── AUTO-END ──\n\n# My custom rules\nsecret_dir/\n"
    )
    sensitive = [("new.py", {"aws_key"})]
    _write_ignore_file(ignore_path, sensitive, tmp_path, tool)

    content = ignore_path.read_text()
    assert "new.py" in content
    assert "old.py" not in content
    assert "secret_dir/" in content  # manual preserved


def test_proxy_addon_uses_full_registry():
    """Verify proxy addon loads the full AI_API_HOSTS registry."""
    from contextduty.proxy_addon import AI_HOSTS

    # Should include Cursor and others from the registry
    assert "api2.cursor.sh" in AI_HOSTS
    assert "api.anthropic.com" in AI_HOSTS
    assert "api.openai.com" in AI_HOSTS
    # Should have many more hosts from the registry
    assert len(AI_HOSTS) >= 10
