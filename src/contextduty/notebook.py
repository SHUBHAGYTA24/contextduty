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


def guard(
    text: str,
    *,
    policy: Policy | None = None,
    raise_on_block: bool = False,
    nlp: bool = True,
    min_confidence: float = 0.5,
) -> ScanResult:
    """Scan text and print a visible warning if secrets are found.

    Designed for interactive notebook use — prints colored warnings
    that are hard to miss. Automatically uses NLP detection if spaCy is installed.

    Args:
        text: The text to scan.
        policy: Optional custom policy. If None, uses all built-in detectors.
        raise_on_block: If True, raise an exception when a detector is in block mode.
        nlp: If True and spaCy is installed, also run NLP-based PII detection.
        min_confidence: Minimum confidence for NLP findings (0.0-1.0).

    Example::

        from contextduty.notebook import guard
        guard('''
            aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
            Patient: John Smith, DOB: 1990-01-15
        ''')
        # ⚠️  ContextDuty: 2 secret(s) found!
        #   - aws_secret: 1 occurrence(s)
        #   - nlp_person: 1 (NLP) — John Smith [0.85]
    """
    p = policy or _default_policy()
    result = scan_text(text, p)

    # Run NLP detection if available
    nlp_result = None
    if nlp:
        nlp_result = _try_nlp_scan(text, min_confidence)

    # Merge and print warnings
    total_findings = result.scan.findings_count
    if nlp_result and nlp_result.findings:
        total_findings += len(nlp_result.findings)

    if total_findings > 0:
        _print_combined_warning(result.scan, nlp_result)

    if raise_on_block and result.scan.blocked:
        raise SecretFoundError(f"Blocked by ContextDuty: {', '.join(result.scan.blocked_by)}")

    return result.scan


def _try_nlp_scan(text: str, min_confidence: float = 0.5):
    """Try to run NLP scan. Returns None if spaCy is not installed."""
    try:
        from .nlp import scan_text_nlp

        return scan_text_nlp(text, min_confidence=min_confidence, extract_segments=False)
    except ImportError:
        return None


def _print_combined_warning(result: ScanResult, nlp_result=None) -> None:
    """Print combined regex + NLP warnings."""
    is_notebook = _is_notebook()
    if is_notebook:
        _print_html_warning(result, nlp_result)
    else:
        _print_text_warning(result, nlp_result)


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


def _print_html_warning(result: ScanResult, nlp_result=None) -> None:
    """Print a rich HTML warning in Jupyter notebooks."""
    try:
        from IPython.display import HTML, display  # type: ignore[import-not-found]
    except ImportError:
        _print_text_warning(result, nlp_result)
        return

    total = result.findings_count + (len(nlp_result.findings) if nlp_result else 0)

    # Regex findings
    detectors_html = "".join(
        f"<li><code>{name}</code>: {count} occurrence(s)</li>"
        for name, count in sorted(result.detector_counts.items())
    )

    # NLP findings
    nlp_html = ""
    if nlp_result and nlp_result.findings:
        nlp_items = ""
        for f in nlp_result.findings:
            nlp_items += (
                f'<li><code>{f.detector_name}</code>: '
                f'<b>{f.entity_text}</b> '
                f'<span style="color:#888;">[confidence: {f.confidence:.2f}]</span>'
                f"</li>"
            )
        nlp_html = f"""
        <p style="margin:8px 0 4px 0; font-size:13px; font-weight:bold; color:#4a148c;">
            🧠 NLP-detected PII:
        </p>
        <ul style="margin:4px 0; padding-left:20px; color:#333;">
            {nlp_items}
        </ul>
        """

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
            ⚠️ ContextDuty: {total} finding(s) detected!
        </p>
        <ul style="margin:4px 0; padding-left:20px; color:#333;">
            {detectors_html}
        </ul>
        {nlp_html}
        {blocked_html}
        <p style="margin:8px 0 0 0; font-size:12px; color:#888;">
            Use <code>redact(text)</code> to get a clean version.
        </p>
    </div>
    """
    display(HTML(html))


def _print_text_warning(result: ScanResult, nlp_result=None) -> None:
    """Print a plain-text warning for terminal/non-notebook environments."""
    total = result.findings_count + (len(nlp_result.findings) if nlp_result else 0)
    print("\n╔══════════════════════════════════════════════════╗", file=sys.stderr)
    print(
        f"║  ⚠️  ContextDuty: {total} finding(s) detected!",
        file=sys.stderr,
    )
    print("╠══════════════════════════════════════════════════╣", file=sys.stderr)
    if result.detector_counts:
        print("║  Regex detectors:", file=sys.stderr)
        for name, count in sorted(result.detector_counts.items()):
            print(f"║    • {name}: {count} occurrence(s)", file=sys.stderr)
    if nlp_result and nlp_result.findings:
        print("║  🧠 NLP-detected PII:", file=sys.stderr)
        for f in nlp_result.findings:
            print(
                f"║    • {f.detector_name}: {f.entity_text} [confidence: {f.confidence:.2f}]",
                file=sys.stderr,
            )
    if result.blocked:
        print(f"║  🚫 BLOCKED by: {', '.join(result.blocked_by)}", file=sys.stderr)
    print("╚══════════════════════════════════════════════════╝", file=sys.stderr)
    print("  Use redact(text) to get a clean version.\n", file=sys.stderr)


class SecretFoundError(Exception):
    """Raised when guard() finds a blocked secret and raise_on_block=True."""

    pass
