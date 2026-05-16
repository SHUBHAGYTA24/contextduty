"""CA certificate generation and system trust installation.

Handles:
    - Generating the mitmproxy CA certificate (by running mitmdump briefly)
    - Installing the CA into the macOS System Keychain (requires sudo once)
    - Installing the CA on Linux (Debian/Ubuntu and RHEL/Fedora)
    - Checking whether the CA is already installed

The CA cert is stored at ~/.mitmproxy/mitmproxy-ca-cert.pem (mitmproxy's default).
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import time
from pathlib import Path

CERT_DIR: Path = Path.home() / ".mitmproxy"
CERT_FILE: Path = CERT_DIR / "mitmproxy-ca-cert.pem"


def is_cert_installed() -> bool:
    """Check if the CA certificate file exists."""
    return CERT_FILE.exists()


def generate_cert() -> bool:
    """Generate mitmproxy CA certificate by running mitmdump briefly.

    Returns True if cert was generated successfully.
    """
    mitmdump = shutil.which("mitmdump")
    if not mitmdump:
        return False

    proc = subprocess.Popen(
        [mitmdump, "--listen-port", "18999"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Poll for cert file instead of fixed sleep
    for _ in range(40):  # up to 4 seconds
        time.sleep(0.1)
        if CERT_FILE.exists():
            break
    proc.terminate()
    proc.wait(timeout=5)
    return CERT_FILE.exists()


def install_cert() -> int:
    """Install CA certificate into system trust store. Returns 0 on success."""
    system = platform.system()
    if system == "Darwin":
        return _install_macos()
    elif system == "Linux":
        return _install_linux()
    else:
        return 1  # Unsupported — caller should show manual instructions


def _install_macos() -> int:
    """Add CA to macOS System Keychain. Requires sudo."""
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
            str(CERT_FILE),
        ]
    )


def _install_linux() -> int:
    """Install CA on Linux — tries Debian/Ubuntu then RHEL/Fedora."""
    if shutil.which("update-ca-certificates"):
        dest = Path("/usr/local/share/ca-certificates/contextduty-mitmproxy.crt")
        rc = subprocess.call(["sudo", "cp", str(CERT_FILE), str(dest)])
        if rc == 0:
            rc = subprocess.call(["sudo", "update-ca-certificates"])
        return rc
    elif shutil.which("update-ca-trust"):
        dest = Path("/etc/pki/ca-trust/source/anchors/contextduty-mitmproxy.crt")
        rc = subprocess.call(["sudo", "cp", str(CERT_FILE), str(dest)])
        if rc == 0:
            rc = subprocess.call(["sudo", "update-ca-trust", "extract"])
        return rc
    return 1
