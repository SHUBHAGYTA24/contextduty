"""Scanning and redaction engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .detectors import DETECTORS, Detector, stable_mask
from .policy import Policy


@dataclass(frozen=True)
class Finding:
    detector: str
    value: str


@dataclass(frozen=True)
class ScanResult:
    findings_count: int
    detector_counts: dict[str, int]
    blocked: bool
    # Detectors that triggered a block (subset of detector_counts keys).
    blocked_by: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.blocked_by is None:
            object.__setattr__(self, "blocked_by", [])


def _effective_mode(policy: Policy, detector_name: str) -> str:
    """Return the mode for a specific detector, falling back to the global policy mode."""
    return policy.detector_modes.get(detector_name, policy.mode)


def _is_allowed(value: str, detector_name: str, policy: Policy) -> bool:
    """Return True if the value matches any allow_pattern for this detector."""
    patterns = policy.allow_patterns.get(detector_name, [])
    return any(re.search(pattern, value) for pattern in patterns)


def _active_detectors(policy: Policy) -> list[Detector]:
    active = [detector for detector in DETECTORS if detector.name in policy.detectors]
    for name, pattern in policy.custom_detectors.items():
        if name in policy.detectors:
            active.append(Detector(name=name, pattern=re.compile(pattern)))
    return active


def _scan_line(line: str, detectors: Iterable[Detector]) -> list[Finding]:
    """Scan a single line, deduplicating overlapping matches.

    Detectors are ordered most-specific → least-specific. When a more specific
    detector already claimed a span, generic detectors that overlap that span
    are skipped so one secret counts as one finding.
    """
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []  # (start, end) spans already matched

    for detector in detectors:
        for match in detector.pattern.finditer(line):
            start, end = match.start(), match.end()
            # Skip if any existing claimed span overlaps this one
            if any(s < end and start < e for s, e in claimed):
                continue
            claimed.append((start, end))
            findings.append(Finding(detector=detector.name, value=match.group(0)))
    return findings


def _apply_findings(
    text: str,
    findings: list[Finding],
    policy: Policy,
    detector_counts: dict[str, int],
    blocked_detectors: set[str],
) -> str:
    """Apply per-detector mode logic to a text segment. Returns the (possibly redacted) text."""
    updated = text
    for finding in findings:
        if _is_allowed(finding.value, finding.detector, policy):
            continue
        detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
        mode = _effective_mode(policy, finding.detector)
        if mode == "block":
            blocked_detectors.add(finding.detector)
        elif mode == "redact":
            updated = updated.replace(finding.value, stable_mask(finding.detector, finding.value))
        # mode == "warn": count it, don't mask, don't block
    return updated


def scan_file(path: Path, policy: Policy) -> ScanResult:
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            findings = _scan_line(line, detectors)
            _apply_findings(line, findings, policy, detector_counts, blocked_detectors)

    findings_count = sum(detector_counts.values())
    blocked = len(blocked_detectors) > 0
    return ScanResult(
        findings_count=findings_count,
        detector_counts=detector_counts,
        blocked=blocked,
        blocked_by=sorted(blocked_detectors),
    )


def redact_file(input_path: Path, output_path: Path, policy: Policy) -> ScanResult:
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()

    with (
        input_path.open("r", encoding="utf-8", errors="replace") as source,
        output_path.open("w", encoding="utf-8") as target,
    ):
        for line in source:
            findings = _scan_line(line, detectors)
            updated = _apply_findings(line, findings, policy, detector_counts, blocked_detectors)
            target.write(updated)

    findings_count = sum(detector_counts.values())
    blocked = len(blocked_detectors) > 0
    return ScanResult(
        findings_count=findings_count,
        detector_counts=detector_counts,
        blocked=blocked,
        blocked_by=sorted(blocked_detectors),
    )


@dataclass(frozen=True)
class ScanTextResult:
    """Result of scanning and redacting an in-memory text string."""

    scan: ScanResult
    redacted_text: str


def scan_text(text: str, policy: Policy) -> ScanTextResult:
    """Scan and redact an in-memory string without touching the filesystem.

    This is the primary entry point for MCP tool use — the LLM passes raw
    text and receives back a findings report plus the redacted version.
    """
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()
    redacted_lines: list[str] = []

    for line in text.splitlines(keepends=True):
        findings = _scan_line(line, detectors)
        updated = _apply_findings(line, findings, policy, detector_counts, blocked_detectors)
        redacted_lines.append(updated)

    findings_count = sum(detector_counts.values())
    blocked = len(blocked_detectors) > 0
    scan_result = ScanResult(
        findings_count=findings_count,
        detector_counts=detector_counts,
        blocked=blocked,
        blocked_by=sorted(blocked_detectors),
    )
    return ScanTextResult(
        scan=scan_result,
        redacted_text="".join(redacted_lines),
    )


def report_to_json(result: ScanResult) -> str:
    payload = {
        "findings_count": result.findings_count,
        "detector_counts": result.detector_counts,
        "blocked": result.blocked,
        "blocked_by": result.blocked_by,
    }
    return json.dumps(payload, indent=2)
