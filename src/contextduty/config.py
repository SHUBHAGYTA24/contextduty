"""Application configuration — paths, settings, environment variables.

All magic paths and configurable values live here. Import from config
instead of hardcoding paths in business logic.
"""

from __future__ import annotations

import os
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Standard paths
# ─────────────────────────────────────────────────────────────────────────────

HOME_DIR: Path = Path.home() / ".contextduty"
"""User-level ContextDuty config directory."""

PROXY_PID_FILE: Path = HOME_DIR / "proxy.pid"
"""PID file for the background proxy daemon."""

MITMPROXY_DIR: Path = Path.home() / ".mitmproxy"
"""mitmproxy's config directory (stores CA cert)."""

CA_CERT_FILE: Path = MITMPROXY_DIR / "mitmproxy-ca-cert.pem"
"""CA certificate used by the HTTPS proxy."""

PROXY_CONFIG_FILE: Path = MITMPROXY_DIR / "contextduty-proxy.json"
"""Proxy settings persisted between start/stop."""

DEFAULT_POLICY_FILE: str = ".contextduty.json"
"""Default policy filename in a workspace."""

DEFAULT_AUDIT_LOG: Path = HOME_DIR / "audit.jsonl"
"""Default audit log location."""

# ─────────────────────────────────────────────────────────────────────────────
# Environment variable overrides
# ─────────────────────────────────────────────────────────────────────────────

PROXY_PORT: int = int(os.environ.get("CONTEXTDUTY_PROXY_PORT", "8080"))
"""Proxy listen port. Override with CONTEXTDUTY_PROXY_PORT env var."""

LOG_LEVEL: str = os.environ.get("CONTEXTDUTY_LOG_LEVEL", "WARNING")
"""Logging verbosity. Override with CONTEXTDUTY_LOG_LEVEL env var."""

NO_COLOR: bool = os.environ.get("NO_COLOR", "") != "" or not os.isatty(1)
"""Disable ANSI colors. Respects NO_COLOR standard (https://no-color.org/)."""

# ─────────────────────────────────────────────────────────────────────────────
# Binary file extensions — skipped during directory scans
# ─────────────────────────────────────────────────────────────────────────────

BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg",
        ".pdf", ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".bin",
        ".whl", ".egg", ".pyc", ".pyo", ".pyd",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".ttf", ".otf", ".woff", ".woff2",
        ".db", ".sqlite", ".sqlite3",
        ".lock",
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# Directories to skip during workspace scans
# ─────────────────────────────────────────────────────────────────────────────

SKIP_DIRECTORIES: frozenset[str] = frozenset(
    {
        "node_modules", "__pycache__", "venv", ".venv",
        "dist", "build", "target", "vendor", "packages",
        ".next", ".nuxt", "coverage", ".git", ".hg", ".svn",
    }
)
