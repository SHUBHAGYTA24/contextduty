"""Tests for the Cursor workspace protection module."""

from __future__ import annotations

from pathlib import Path

from contextduty._workspace import matches_gitignore, scan_workspace
from contextduty.adapters.ide import AI_TOOLS, write_ignore_file
from contextduty.cursor import cursor_setup
from contextduty.policy import load_policy

_CURSOR_TOOL = next(t for t in AI_TOOLS if t.name == "Cursor")


def _make_workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    """Create a temp workspace with given files."""
    for rel, content in files.items():
        fpath = tmp_path / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
    return tmp_path


def test_scan_workspace_finds_aws_key(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(
        tmp_path,
        {
            "config.py": f'AWS_KEY = "{aws_key}"',
            "readme.md": "# Hello world",
        },
    )
    policy = load_policy(None)
    results = scan_workspace(ws, policy)
    assert len(results) == 1
    assert results[0][0] == "config.py"
    assert "aws_key" in results[0][1]


def test_scan_workspace_skips_clean_files(tmp_path):
    ws = _make_workspace(
        tmp_path,
        {
            "app.py": "print('hello world')",
            "utils.py": "def add(a, b): return a + b",
        },
    )
    policy = load_policy(None)
    results = scan_workspace(ws, policy)
    assert results == []


def test_scan_workspace_skips_hidden_dirs(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(
        tmp_path,
        {
            ".git/config": f"key = {aws_key}",
            "src/main.py": "print('clean')",
        },
    )
    policy = load_policy(None)
    results = scan_workspace(ws, policy)
    assert results == []


def test_scan_workspace_skips_node_modules(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(
        tmp_path,
        {
            "node_modules/pkg/index.js": f'const k = "{aws_key}"',
            "src/main.py": "print('clean')",
        },
    )
    policy = load_policy(None)
    results = scan_workspace(ws, policy)
    assert results == []


def test_write_cursorignore_creates_file(tmp_path):
    sensitive = [
        ("config.py", {"aws_key"}),
        ("secrets/db.env", {"database_url", "email"}),
    ]
    out = tmp_path / ".cursorignore"
    write_ignore_file(out, sensitive, _CURSOR_TOOL)

    content = out.read_text()
    assert "config.py" in content
    assert "secrets/db.env" in content
    assert "AUTO-START" in content
    assert "AUTO-END" in content


def test_write_cursorignore_preserves_manual_entries(tmp_path):
    out = tmp_path / ".cursorignore"
    out.write_text(
        "# ── AUTO-START (do not edit between START/END) ──\nold.py  # aws_key\n# ── AUTO-END ──\n\n# Manual\nmy_custom_ignore.txt\n"
    )

    sensitive = [("new.py", {"email"})]
    write_ignore_file(out, sensitive, _CURSOR_TOOL)

    content = out.read_text()
    assert "new.py" in content
    assert "old.py" not in content
    assert "my_custom_ignore.txt" in content  # manual preserved


def test_matches_gitignore_basic():
    patterns = ["node_modules", "*.pyc", "dist/"]
    assert matches_gitignore("node_modules/pkg/index.js", patterns)
    assert matches_gitignore("src/app.pyc", patterns)
    assert matches_gitignore("dist/bundle.js", patterns)
    assert not matches_gitignore("src/main.py", patterns)


def test_cursor_setup_clean_workspace(tmp_path, capsys):
    ws = _make_workspace(tmp_path, {"app.py": "print('hello')"})
    rc = cursor_setup(ws)
    assert rc == 0
    captured = capsys.readouterr()
    assert "clean" in captured.out.lower() or "No secrets" in captured.out


def test_cursor_setup_writes_cursorignore(tmp_path, capsys):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(
        tmp_path,
        {
            "config.py": f'KEY = "{aws_key}"',
            "app.py": "print('ok')",
        },
    )
    rc = cursor_setup(ws)
    assert rc == 0

    ignore_file = ws / ".cursorignore"
    assert ignore_file.exists()
    content = ignore_file.read_text()
    assert "config.py" in content


def test_scan_workspace_detects_multiple_types(tmp_path):
    aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
    ws = _make_workspace(
        tmp_path,
        {
            "config.py": f'KEY = "{aws_key}"\nEMAIL = "admin@secret.com"',
        },
    )
    policy = load_policy(None)
    results = scan_workspace(ws, policy)
    assert len(results) == 1
    assert "aws_key" in results[0][1]
    assert "email" in results[0][1]
