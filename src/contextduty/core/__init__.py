"""contextduty.core — public API shim.

Provides a dict-based API used by the CLI layer.
Lower-level code (engine, policy) uses richer dataclasses.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict

from .exceptions import (  # noqa: F401
    CertificateError,
    ContextDutyError,
    FileAccessError,
    PolicyCycleError,
    PolicyError,
    PolicyValidationError,
    ProxyAlreadyRunningError,
    ProxyError,
    ProxyNotInstalledError,
    ScanError,
)

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def load_policy(path: str) -> dict:
    """Load and return a policy dict from *path*.

    Falls back to an empty default if the file doesn't exist.
    """
    from contextduty.detectors import BUILTIN_NAMES as _BUILTIN_NAMES

    p = Path(path)
    if not p.exists():
        return {"mode": "redact", "detectors": list(_BUILTIN_NAMES), "custom_detectors": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise PolicyError(f"Cannot load policy {path}: {exc}") from exc

    # Resolve 'extends' inheritance (single level)
    if "extends" in data:
        base_path = p.parent / data["extends"]
        try:
            base = json.loads(base_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise PolicyError(f"Cannot load base policy {base_path}: {exc}") from exc
        merged = {**base, **data}
        merged.pop("extends", None)
        return merged

    return data


# ---------------------------------------------------------------------------
# Scanning — dict-based wrappers around the engine
# ---------------------------------------------------------------------------


def _compile_detectors(detectors_dict: Dict[str, re.Pattern]) -> list:
    """Convert a {name: pattern} dict to a list of Detector NamedTuples."""
    from contextduty.detectors import Detector

    return [Detector(name=name, pattern=pat) for name, pat in detectors_dict.items()]


def scan_text(text: str, detectors: Dict[str, re.Pattern]) -> dict:
    """Scan *text* with the given detectors dict.

    Returns a dict compatible with the CLI JSON output:
        {"findings_count": int, "detector_counts": {name: count}}
    """
    from contextduty.engine import _scan_line

    detector_list = _compile_detectors(detectors)
    detector_counts: dict = {}

    for line in text.splitlines(keepends=True):
        findings = _scan_line(line, detector_list)
        for finding in findings:
            detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1

    return {
        "findings_count": sum(detector_counts.values()),
        "detector_counts": detector_counts,
    }


def redact_text(text: str, detectors: Dict[str, re.Pattern]) -> dict:
    """Redact *text* with the given detectors dict.

    Returns:
        {
            "redacted": str,
            "findings_count": int,
            "detector_counts": {name: count},
            "masked_values_count": int,
        }
    """
    from contextduty.detectors import stable_mask
    from contextduty.engine import _scan_line

    detector_list = _compile_detectors(detectors)
    detector_counts: dict = {}
    masked_values: set = set()
    redacted_lines: list = []

    for line in text.splitlines(keepends=True):
        findings = _scan_line(line, detector_list)
        updated = line
        for finding in findings:
            detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
            mask = stable_mask(finding.detector, finding.value)
            updated = updated.replace(finding.value, mask)
            masked_values.add(finding.value)
        redacted_lines.append(updated)

    return {
        "redacted": "".join(redacted_lines),
        "findings_count": sum(detector_counts.values()),
        "detector_counts": detector_counts,
        "masked_values_count": len(masked_values),
    }
