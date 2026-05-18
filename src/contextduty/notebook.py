"""
contextduty.notebook
~~~~~~~~~~~~~~~~~~~~
Notebook-friendly API for data scientists.

Usage in any Jupyter/Colab/Databricks notebook:

    from contextduty.notebook import guard, redact, scan

    # Scan text and print warnings
    guard("aws_secret_access_key = wJalrXUtnFEMI...")

    # Get redacted version back
    clean = redact("db_url = postgres://admin:pass@prod:5432/db")

    # Scan and get structured result
    result = scan("my config text here")
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from .detectors import DETECTORS
from .engine import ScanResult, ScanTextResult, scan_text
from .policy import Policy

if TYPE_CHECKING:
    pass


def _default_policy(mode: str = "warn") -> Policy:
    """Create a sensible default policy for notebook use — all detectors enabled."""
    return Policy(
        mode=mode,
        detectors={d.name for d in DETECTORS},
        custom_detectors={},
    )


def scan(text: str, *, mode: str = "warn", policy: Policy | None = None) -> ScanTextResult:
    """Scan text for secrets and PII. Returns a ScanTextResult with findings and redacted text.

    Args:
        text: The text to scan.
        mode: Default mode — "warn", "redact", or "block".
        policy: Optional custom policy. If None, uses all built-in detectors.

    Example::

        from contextduty.notebook import scan
        result = scan("my_key = AKIAIOSFODNN7EXAMPLE")
        print(result.scan.findings_count)  # 1
        print(result.scan.detector_counts)  # {'aws_key': 1}
    """
    p = policy or _default_policy(mode)
    return scan_text(text, p)


def redact(text: str, *, policy: Policy | None = None) -> str:
    """Scan and redact secrets from text. Returns the clean version.

    Args:
        text: The text to redact.
        policy: Optional custom policy. If None, uses all built-in detectors in redact mode.

    Example::

        from contextduty.notebook import redact
        clean = redact("db = postgres://admin:secret@prod:5432/app")
        print(clean)  # db = <POSTGRES_DSN_a1b2c3d4>
    """
    p = policy or _default_policy("redact")
    result = scan_text(text, p)
    return result.redacted_text


def guard(text: str, *, policy: Policy | None = None, raise_on_block: bool = False) -> ScanResult:
    """Scan text and print a visible warning if secrets are found.

    Designed for interactive notebook use — prints colored warnings
    that are hard to miss.

    Args:
        text: The text to scan.
        policy: Optional custom policy. If None, uses all built-in detectors.
        raise_on_block: If True, raise an exception when a detector is in block mode.

    Example::

        from contextduty.notebook import guard
        guard('''
            aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        ''')
        # ⚠️  ContextDuty: 1 secret(s) found!
        #   - aws_secret: 1 occurrence(s)
    """
    p = policy or _default_policy()
    result = scan_text(text, p)

    if result.scan.findings_count > 0:
        _print_warning(result.scan)

    if raise_on_block and result.scan.blocked:
        raise SecretFoundError(f"Blocked by ContextDuty: {', '.join(result.scan.blocked_by)}")

    return result.scan


def _print_warning(result: ScanResult) -> None:
    """Print a highly visible warning to notebook output."""
    is_notebook = _is_notebook()
    if is_notebook:
        _print_html_warning(result)
    else:
        _print_text_warning(result)


def _is_notebook() -> bool:
    """Detect if running inside a Jupyter/IPython notebook."""
    try:
        from IPython import get_ipython  # type: ignore[import-not-found]

        shell = get_ipython()
        if shell is None:
            return False
        return shell.__class__.__name__ == "ZMQInteractiveShell"
    except (ImportError, NameError):
        return False


def _print_html_warning(result: ScanResult) -> None:
    """Print a rich HTML warning in Jupyter notebooks."""
    try:
        from IPython.display import HTML, display  # type: ignore[import-not-found]
    except ImportError:
        _print_text_warning(result)
        return

    detectors_html = "".join(
        f"<li><code>{name}</code>: {count} occurrence(s)</li>"
        for name, count in sorted(result.detector_counts.items())
    )

    blocked_html = ""
    if result.blocked:
        blocked_html = (
            '<p style="color:#d32f2f;font-weight:bold;">'
            f"🚫 BLOCKED by: {', '.join(result.blocked_by)}</p>"
        )

    html = f"""
    <div style="border:2px solid #f57c00; background:#fff3e0; padding:12px 16px;
                border-radius:8px; margin:8px 0; font-family:system-ui,sans-serif;">
        <p style="margin:0 0 8px 0; font-size:15px; font-weight:bold; color:#e65100;">
            ⚠️ ContextDuty: {result.findings_count} secret(s) found!
        </p>
        <ul style="margin:4px 0; padding-left:20px; color:#333;">
            {detectors_html}
        </ul>
        {blocked_html}
        <p style="margin:8px 0 0 0; font-size:12px; color:#888;">
            Use <code>redact(text)</code> to get a clean version.
        </p>
    </div>
    """
    display(HTML(html))


def _print_text_warning(result: ScanResult) -> None:
    """Print a plain-text warning for terminal/non-notebook environments."""
    print("\n╔══════════════════════════════════════════════════╗", file=sys.stderr)
    print(
        f"║  ⚠️  ContextDuty: {result.findings_count} secret(s) found!",
        file=sys.stderr,
    )
    print("╠══════════════════════════════════════════════════╣", file=sys.stderr)
    for name, count in sorted(result.detector_counts.items()):
        print(f"║  • {name}: {count} occurrence(s)", file=sys.stderr)
    if result.blocked:
        print(f"║  🚫 BLOCKED by: {', '.join(result.blocked_by)}", file=sys.stderr)
    print("╚══════════════════════════════════════════════════╝", file=sys.stderr)
    print("  Use redact(text) to get a clean version.\n", file=sys.stderr)


class SecretFoundError(Exception):
    """Raised when guard() finds a blocked secret and raise_on_block=True."""

    pass
