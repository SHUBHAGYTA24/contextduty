"""Local HTTPS proxy management for ContextDuty.

Wraps mitmproxy to intercept AI API traffic (OpenAI, Anthropic, Copilot)
and redact sensitive data before it reaches the cloud.

Commands:
    contextduty proxy setup    — install CA cert + configure system proxy (one-time, sudo)
    contextduty proxy start    — start intercepting
    contextduty proxy stop     — stop and restore system settings
    contextduty proxy status   — show whether proxy is running
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

_PROXY_HOST = "127.0.0.1"
_PROXY_PORT = 8080
_PID_FILE = Path.home() / ".contextduty" / "proxy.pid"
_CERT_DIR = Path.home() / ".mitmproxy"
_CERT_FILE = _CERT_DIR / "mitmproxy-ca-cert.pem"

_BOLD = "\033[1m"
_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def proxy_setup(policy_path: str = ".contextduty.json", audit_log: str = "") -> int:
    """Install CA cert and configure system proxy. Requires sudo on macOS."""
    _section("ContextDuty Proxy Setup")

    # Step 1 — generate the mitmproxy CA cert by running it briefly
    if not _CERT_FILE.exists():
        _step("Generating mitmproxy CA certificate...")
        _generate_cert()
        if not _CERT_FILE.exists():
            _err("Certificate generation failed. Is mitmproxy installed?")
            _err("  pip install 'contextduty[proxy]'")
            return 1
    _ok(f"CA certificate ready: {_CERT_FILE}")

    # Step 2 — install cert into system trust store
    system = platform.system()
    if system == "Darwin":
        _step("Installing CA certificate into macOS System Keychain...")
        _print(f"  {_DIM}(requires sudo — you will be prompted){_RESET}")
        rc = _install_cert_macos()
        if rc != 0:
            _err("Certificate installation failed.")
            _print("  Run manually: sudo security add-trusted-cert -d -r trustRoot \\")
            _print(f"    -k /Library/Keychains/System.keychain {_CERT_FILE}")
            return 1
        _ok("CA certificate trusted by macOS")
    elif system == "Linux":
        _step("Installing CA certificate (Linux)...")
        rc = _install_cert_linux()
        if rc != 0:
            _err("Certificate installation failed — see instructions above.")
            return 1
        _ok("CA certificate trusted")
    else:
        _warn(f"Auto cert install not supported on {system}.")
        _print(f"  Manually trust: {_CERT_FILE}")

    # Step 3 — write proxy config so start knows the policy
    _CERT_DIR.mkdir(parents=True, exist_ok=True)
    config = {"policy_path": policy_path, "audit_log": audit_log, "port": _PROXY_PORT}
    (_CERT_DIR / "contextduty-proxy.json").write_text(json.dumps(config, indent=2))

    # Step 4 — print next step
    _print()
    _ok("Setup complete. Start intercepting with:")
    _print(f"  {_CYAN}contextduty proxy start{_RESET}")
    _print()
    _print(f"  {_DIM}Set your system proxy to 127.0.0.1:{_PROXY_PORT} or run:{_RESET}")
    _print(f"  {_CYAN}contextduty proxy start --set-system-proxy{_RESET}")
    return 0


def proxy_start(
    policy_path: str | None = None,
    audit_log: str = "",
    port: int = _PROXY_PORT,
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

    # Resolve policy
    if policy_path is None:
        saved = _load_proxy_config()
        policy_path = saved.get("policy_path", ".contextduty.json")
        if not audit_log:
            audit_log = saved.get("audit_log", "")
        port = saved.get("port", _PROXY_PORT)

    # Find the addon script
    addon_path = Path(__file__).parent / "proxy_addon.py"

    cmd = [
        _mitmdump_path(),
        "--listen-host",
        _PROXY_HOST,
        "--listen-port",
        str(port),
        "--ssl-insecure",  # don't break on self-signed upstream certs
        "-s",
        str(addon_path),
        "--set",
        f"contextduty_policy={policy_path}",
    ]
    if audit_log:
        cmd += ["--set", f"contextduty_audit_log={audit_log}"]

    _section("ContextDuty Proxy")
    _print(f"  Listening on   {_BOLD}127.0.0.1:{port}{_RESET}")
    _print(f"  Intercepting   {_DIM}api.openai.com, api.anthropic.com, copilot.github.com{_RESET}")
    _print(f"  Policy         {_DIM}{policy_path}{_RESET}")
    if audit_log:
        _print(f"  Audit log      {_DIM}{audit_log}{_RESET}")
    if not _CERT_FILE.exists():
        _print()
        _warn("CA cert not installed yet. Browsers/tools may reject the proxy.")
        _print(f"  Run first: {_CYAN}contextduty proxy setup{_RESET}")
    _print()

    if set_system_proxy:
        _configure_system_proxy(port, enable=True)
        _print(f"  {_GREEN}✓{_RESET} System proxy set to 127.0.0.1:{port}")
        _print(f"  {_DIM}Run 'contextduty proxy stop' to restore.{_RESET}")
        _print()

    if daemon:
        return _start_daemon(cmd, port, set_system_proxy)

    _print(f"  {_DIM}Press Ctrl+C to stop.{_RESET}\n")
    try:
        os.execvp(cmd[0], cmd)  # replace this process — cleaner than subprocess
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
        # Wait up to 3 seconds
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
    config = _load_proxy_config()
    if config.get("system_proxy_was_set"):
        _configure_system_proxy(config.get("port", _PROXY_PORT), enable=False)
        _ok("System proxy settings restored.")

    return 0


def proxy_status() -> int:
    """Print proxy status."""
    _section("ContextDuty Proxy Status")
    if _is_running():
        pid = _read_pid()
        config = _load_proxy_config()
        port = config.get("port", _PROXY_PORT)
        _ok(f"Running  (PID {pid}, port {port})")
        _print("  Intercepting: api.openai.com, api.anthropic.com, copilot.github.com")
        _print(f"  Policy:       {config.get('policy_path', 'default')}")
    else:
        _warn("Not running")
        _print(f"  Start with: {_CYAN}contextduty proxy start{_RESET}")

    _print()
    if _CERT_FILE.exists():
        _ok(f"CA cert installed: {_CERT_FILE}")
    else:
        _warn(f"CA cert not installed — run: {_CYAN}contextduty proxy setup{_RESET}")
    return 0


# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------


def _generate_cert() -> None:
    """Run mitmdump briefly to generate the CA cert."""
    mitmdump = _mitmdump_path()
    if not mitmdump:
        return
    proc = subprocess.Popen(
        [mitmdump, "--listen-port", "18999"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=5)


def _install_cert_macos() -> int:
    return subprocess.call(
        [
            "sudo",
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            str(_CERT_FILE),
        ]
    )


def _install_cert_linux() -> int:
    # Try Debian/Ubuntu path first, then RHEL/Fedora
    if shutil.which("update-ca-certificates"):
        dest = Path("/usr/local/share/ca-certificates/contextduty-mitmproxy.crt")
        _print(f"  {_DIM}Copying cert to {dest} (requires sudo){_RESET}")
        rc = subprocess.call(["sudo", "cp", str(_CERT_FILE), str(dest)])
        if rc == 0:
            rc = subprocess.call(["sudo", "update-ca-certificates"])
        return rc
    elif shutil.which("update-ca-trust"):
        dest = Path("/etc/pki/ca-trust/source/anchors/contextduty-mitmproxy.crt")
        rc = subprocess.call(["sudo", "cp", str(_CERT_FILE), str(dest)])
        if rc == 0:
            rc = subprocess.call(["sudo", "update-ca-trust", "extract"])
        return rc
    else:
        _warn("Could not find system cert update tool.")
        _print(f"  Manually trust: {_CERT_FILE}")
        return 1


# ---------------------------------------------------------------------------
# System proxy helpers (macOS)
# ---------------------------------------------------------------------------


def _get_active_network_service() -> str:
    """Return the active network service name (e.g. 'Wi-Fi' or 'Ethernet')."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if (
                line
                and not line.startswith("*")
                and line not in ("An asterisk (*) denotes that a network service is disabled.",)
            ):
                # First non-disabled service wins
                if line not in ("", "An asterisk (*) denotes that a network service is disabled."):
                    return line
    except FileNotFoundError:
        pass
    return "Wi-Fi"  # sensible default


def _configure_system_proxy(port: int, enable: bool) -> None:
    if platform.system() != "Darwin":
        if enable:
            _print(f"  {_DIM}Set HTTPS_PROXY=http://127.0.0.1:{port} for each tool.{_RESET}")
        return

    service = _get_active_network_service()
    state = "on" if enable else "off"
    host = _PROXY_HOST if enable else ""
    p = str(port) if enable else ""

    cmds = [
        ["networksetup", "-setwebproxy", service, host, p]
        if enable
        else ["networksetup", "-setwebproxystate", service, state],
        ["networksetup", "-setsecurewebproxy", service, host, p]
        if enable
        else ["networksetup", "-setsecurewebproxystate", service, state],
    ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)

    # Track that we set it so stop() can restore
    config = _load_proxy_config()
    config["system_proxy_was_set"] = enable
    config["port"] = port
    _CERT_DIR.mkdir(parents=True, exist_ok=True)
    (_CERT_DIR / "contextduty-proxy.json").write_text(json.dumps(config, indent=2))


# ---------------------------------------------------------------------------
# Daemon helpers
# ---------------------------------------------------------------------------


def _start_daemon(cmd: list[str], port: int, set_system_proxy: bool) -> int:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    _PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    _PID_FILE.write_text(str(proc.pid))

    # Save that we set system proxy so stop() can restore
    if set_system_proxy:
        config = _load_proxy_config()
        config["system_proxy_was_set"] = True
        config["port"] = port
        (_CERT_DIR / "contextduty-proxy.json").write_text(json.dumps(config, indent=2))

    time.sleep(1)
    if proc.poll() is not None:
        _err("Proxy failed to start.")
        _PID_FILE.unlink(missing_ok=True)
        return 1

    _ok(f"Proxy running in background (PID {proc.pid})")
    _print(f"  Stop with: {_CYAN}contextduty proxy stop{_RESET}")
    return 0


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _mitmdump_path() -> str | None:
    return shutil.which("mitmdump")


def _mitmdump_available() -> bool:
    return _mitmdump_path() is not None


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


def _load_proxy_config() -> dict:
    cfg_file = _CERT_DIR / "contextduty-proxy.json"
    try:
        return json.loads(cfg_file.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def _section(title: str) -> None:
    _print(f"\n{_BOLD}{'─' * 50}{_RESET}")
    _print(f"{_BOLD}  {title}{_RESET}")
    _print(f"{_BOLD}{'─' * 50}{_RESET}\n")


def _step(msg: str) -> None:
    print(f"  → {msg}", flush=True)


def _ok(msg: str) -> None:
    print(f"  {_GREEN}✓{_RESET}  {msg}", flush=True)


def _warn(msg: str) -> None:
    print(f"  {_YELLOW}⚠{_RESET}  {msg}", flush=True)


def _err(msg: str) -> None:
    print(f"  {_RED}✗{_RESET}  {msg}", file=sys.stderr, flush=True)


def _print(msg: str = "") -> None:
    print(msg, flush=True)
