"""System proxy configuration — macOS, Linux, Windows.

Handles:
    - Setting the system HTTPS proxy to route traffic through ContextDuty
    - Restoring original proxy settings on stop
    - Detecting the active network interface (macOS)
    - Persisting state so stop() knows what to restore
"""

from __future__ import annotations

import json
import platform
import subprocess
from pathlib import Path

from .ca import CERT_DIR

_CONFIG_FILE: Path = CERT_DIR / "contextduty-proxy.json"
_PROXY_HOST: str = "127.0.0.1"


def configure(port: int, enable: bool) -> None:
    """Set or unset system proxy. Saves state for restore on stop."""
    system = platform.system()
    if system == "Darwin":
        _configure_macos(port, enable)
    elif system == "Linux":
        _configure_linux(port, enable)
    # Windows: future support via registry

    # Persist state
    config = load_config()
    config["system_proxy_was_set"] = enable
    config["port"] = port
    save_config(config)


def get_active_network_service() -> str:
    """Return the active macOS network service name (e.g. 'Wi-Fi')."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("*") and "asterisk" not in line.lower():
                return line
    except FileNotFoundError:
        pass
    return "Wi-Fi"


def load_config() -> dict:
    """Load proxy config from disk."""
    try:
        return json.loads(_CONFIG_FILE.read_text())
    except (FileNotFoundError, ValueError):
        return {}


def save_config(config: dict) -> None:
    """Save proxy config to disk."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    _CONFIG_FILE.write_text(json.dumps(config, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# Platform-specific implementations
# ─────────────────────────────────────────────────────────────────────────────


def _configure_macos(port: int, enable: bool) -> None:
    service = get_active_network_service()
    if enable:
        cmds = [
            ["networksetup", "-setwebproxy", service, _PROXY_HOST, str(port)],
            ["networksetup", "-setsecurewebproxy", service, _PROXY_HOST, str(port)],
        ]
    else:
        cmds = [
            ["networksetup", "-setwebproxystate", service, "off"],
            ["networksetup", "-setsecurewebproxystate", service, "off"],
        ]
    for cmd in cmds:
        subprocess.run(cmd, capture_output=True)


def _configure_linux(port: int, enable: bool) -> None:
    """Print env var instructions for Linux (no system-wide registry)."""
    if enable:
        # We can't set system-wide env vars persistently without sudo,
        # but we can write a helper script
        env_file = CERT_DIR / "contextduty-proxy-env.sh"
        env_file.write_text(
            f'export HTTPS_PROXY="http://{_PROXY_HOST}:{port}"\n'
            f'export HTTP_PROXY="http://{_PROXY_HOST}:{port}"\n'
            f'export https_proxy="http://{_PROXY_HOST}:{port}"\n'
            f'export http_proxy="http://{_PROXY_HOST}:{port}"\n'
        )
