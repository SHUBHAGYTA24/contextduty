"""Proxy lifecycle management — setup, start, stop, status, daemon.

This is the orchestrator. It delegates to:
    ca.py     — certificate operations
    system.py — OS proxy configuration
    addon.py  — the actual mitmproxy request handler

The proxy runs as either:
    - Foreground: os.execvp replaces the process with mitmdump (clean, no zombie)
    - Daemon: subprocess.Popen with start_new_session=True + PID file
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from ..config import HOME_DIR
from ..ui.output import style
from . import ca, system
from .scope import AI_API_HOSTS

_PROXY_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080
_PID_FILE = HOME_DIR / "proxy.pid"



# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def proxy_setup(policy_path: str = ".contextduty.json", audit_log: str = "") -> int:
    """Install CA cert and configure system proxy. One-time setup."""
    _section("ContextDuty Proxy Setup")

    # Step 1 — Generate CA cert
    if not ca.is_cert_installed():
        _step("Generating mitmproxy CA certificate...")
        if not ca.generate_cert():
            _err("Certificate generation failed. Is mitmproxy installed?")
            _err("  pip install 'contextduty[proxy]'")
            return 1
    _ok(f"CA certificate ready: {ca.CERT_FILE}")

    # Step 2 — Install into system trust store
    import platform

    os_name = platform.system()
    if os_name == "Darwin":
        _step("Installing CA certificate into macOS System Keychain...")
        _print(f"  {style.dim}(requires sudo — you will be prompted){style.reset}")
        rc = ca.install_cert()
        if rc != 0:
            _err("Certificate installation failed.")
            _print("  Run manually: sudo security add-trusted-cert -d -r trustRoot \\")
            _print(f"    -k /Library/Keychains/System.keychain {ca.CERT_FILE}")
            return 1
        _ok("CA certificate trusted by macOS")
    elif os_name == "Linux":
        _step("Installing CA certificate (Linux)...")
        rc = ca.install_cert()
        if rc != 0:
            _err("Certificate installation failed — see instructions above.")
            return 1
        _ok("CA certificate trusted")
    else:
        _warn(f"Auto cert install not supported on {os_name}.")
        _print(f"  Manually trust: {ca.CERT_FILE}")

    # Step 3 — Save config
    config = {"policy_path": policy_path, "audit_log": audit_log, "port": _DEFAULT_PORT}
    system.save_config(config)

    # Step 4 — Next steps
    _print()
    _ok("Setup complete. Start intercepting with:")
    _print(f"  {style.cyan}contextduty proxy start{style.reset}")
    _print()
    _print(f"  {style.dim}Set your system proxy to 127.0.0.1:{_DEFAULT_PORT} or run:{style.reset}")
    _print(f"  {style.cyan}contextduty proxy start --set-system-proxy{style.reset}")
    return 0


def proxy_start(
    policy_path: str | None = None,
    audit_log: str = "",
    port: int = _DEFAULT_PORT,
    set_system_proxy: bool = False,
    daemon: bool = False,
) -> int:
    """Start the ContextDuty interception proxy."""
    if not _mitmdump_available():
        _err("mitmproxy not found. Install it:")
        _err("  pip install 'contextduty[proxy]'")
        return 1

    if _is_running():
        pid = _read_pid()
        _warn(f"Proxy already running (PID {pid}). Stop it first:")
        _print("  contextduty proxy stop")
        return 1

    # Resolve settings from saved config
    if policy_path is None:
        saved = system.load_config()
        policy_path = saved.get("policy_path", ".contextduty.json")
        if not audit_log:
            audit_log = saved.get("audit_log", "")
        port = saved.get("port", _DEFAULT_PORT)

    # Build mitmdump command
    addon_path = Path(__file__).parent / "addon.py"
    cmd = [
        _mitmdump_path(),
        "--listen-host",
        _PROXY_HOST,
        "--listen-port",
        str(port),
        "--ssl-insecure",
        "-s",
        str(addon_path),
        "--set",
        f"contextduty_policy={policy_path}",
    ]
    if audit_log:
        cmd += ["--set", f"contextduty_audit_log={audit_log}"]

    # Print status
    _section("ContextDuty Proxy")
    _print(f"  Listening on   {style.bold}127.0.0.1:{port}{style.reset}")
    _print(f"  Intercepting   {style.dim}{len(AI_API_HOSTS)} AI API endpoints{style.reset}")
    _print(f"  Policy         {style.dim}{policy_path}{style.reset}")
    if audit_log:
        _print(f"  Audit log      {style.dim}{audit_log}{style.reset}")
    if not ca.is_cert_installed():
        _print()
        _warn("CA cert not installed yet. Browsers/tools may reject the proxy.")
        _print(f"  Run first: {style.cyan}contextduty proxy setup{style.reset}")
    _print()

    if set_system_proxy:
        system.configure(port, enable=True)
        _ok(f"System proxy set to 127.0.0.1:{port}")
        _print(f"  {style.dim}Run 'contextduty proxy stop' to restore.{style.reset}")
        _print()

    if daemon:
        return _start_daemon(cmd, port)

    _print(f"  {style.dim}Press Ctrl+C to stop.{style.reset}\n")
    try:
        os.execvp(cmd[0], cmd)
    except FileNotFoundError:
        _err(f"mitmdump not found at: {cmd[0]}")
        return 1
    return 0  # unreachable after execvp


def proxy_stop() -> int:
    """Stop the ContextDuty proxy and restore system proxy settings."""
    if not _is_running():
        _warn("No ContextDuty proxy is running.")
        return 0

    pid = _read_pid()
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        _ok(f"Proxy stopped (was PID {pid})")
    except ProcessLookupError:
        _ok("Proxy process already gone.")
    except PermissionError:
        _err(f"Cannot signal PID {pid} — permission denied.")
        return 1

    _PID_FILE.unlink(missing_ok=True)

    # Restore system proxy
    config = system.load_config()
    if config.get("system_proxy_was_set"):
        system.configure(config.get("port", _DEFAULT_PORT), enable=False)
        _ok("System proxy settings restored.")

    return 0


def proxy_status() -> int:
    """Print proxy status."""
    _section("ContextDuty Proxy Status")
    if _is_running():
        pid = _read_pid()
        config = system.load_config()
        port = config.get("port", _DEFAULT_PORT)
        _ok(f"Running  (PID {pid}, port {port})")
        _print(f"  Intercepting: {len(AI_API_HOSTS)} AI API endpoints")
        _print(f"  Policy:       {config.get('policy_path', 'default')}")
    else:
        _warn("Not running")
        _print(f"  Start with: {style.cyan}contextduty proxy start{style.reset}")

    _print()
    if ca.is_cert_installed():
        _ok(f"CA cert installed: {ca.CERT_FILE}")
    else:
        _warn(f"CA cert not installed — run: {style.cyan}contextduty proxy setup{style.reset}")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────


def _is_running() -> bool:
    pid = _read_pid()
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        _PID_FILE.unlink(missing_ok=True)
        return False


def _read_pid() -> int | None:
    try:
        return int(_PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _start_daemon(cmd: list[str], port: int) -> int:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(proc.pid))

    time.sleep(1)
    if proc.poll() is not None:
        _err("Proxy failed to start.")
        _PID_FILE.unlink(missing_ok=True)
        return 1

    _ok(f"Proxy running in background (PID {proc.pid})")
    _print(f"  Stop with: {style.cyan}contextduty proxy stop{style.reset}")
    return 0


def _mitmdump_path() -> str:
    return shutil.which("mitmdump") or ""


def _mitmdump_available() -> bool:
    return bool(_mitmdump_path())


# ─────────────────────────────────────────────────────────────────────────────
# Terminal output helpers
# ─────────────────────────────────────────────────────────────────────────────


def _section(title: str) -> None:
    _print(f"\n{style.bold}{'─' * 50}{style.reset}")
    _print(f"{style.bold}  {title}{style.reset}")
    _print(f"{style.bold}{'─' * 50}{style.reset}\n")


def _step(msg: str) -> None:
    print(f"  → {msg}", flush=True)


def _ok(msg: str) -> None:
    print(f"  {style.green}✓{style.reset}  {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"  {style.yellow}⚠{style.reset}  {msg}", flush=True)


def _err(msg: str) -> None:
    print(f"  {style.red}✗{style.reset}  {msg}", file=sys.stderr, flush=True)


def _print(msg: str = "") -> None:
    print(msg, flush=True)
