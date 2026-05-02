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


def _active_detectors(policy: Policy) -> list[Detector]:
    active = [detector for detector in DETECTORS if detector.name in policy.detectors]
    for name, pattern in policy.custom_detectors.items():
        if name in policy.detectors:
            active.append(Detector(name=name, pattern=re.compile(pattern)))
    return active


def _scan_line(line: str, detectors: Iterable[Detector]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in detectors:
        for match in detector.pattern.finditer(line):
            findings.append(Finding(detector=detector.name, value=match.group(0)))
    return findings


def scan_file(path: Path, policy: Policy) -> ScanResult:
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    findings_count = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            findings = _scan_line(line, detectors)
            findings_count += len(findings)
            for finding in findings:
                detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
    blocked = findings_count > 0 and policy.mode == "block"
    return ScanResult(findings_count=findings_count, detector_counts=detector_counts, blocked=blocked)


def redact_file(input_path: Path, output_path: Path, policy: Policy) -> ScanResult:
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    findings_count = 0
    blocked = False

    with input_path.open("r", encoding="utf-8", errors="replace") as source, output_path.open(
        "w", encoding="utf-8"
    ) as target:
        for line in source:
            updated = line
            findings = _scan_line(updated, detectors)
            findings_count += len(findings)
            for finding in findings:
                detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
                if policy.mode == "redact":
                    updated = updated.replace(finding.value, stable_mask(finding.detector, finding.value))
            target.write(updated)

    if findings_count > 0 and policy.mode == "block":
        blocked = True

    return ScanResult(findings_count=findings_count, detector_counts=detector_counts, blocked=blocked)


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
    findings_count = 0
    redacted = text

    for line in text.splitlines(keepends=True):
        findings = _scan_line(line, detectors)
        findings_count += len(findings)
        for finding in findings:
            detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
            if policy.mode == "redact":
                redacted = redacted.replace(finding.value, stable_mask(finding.detector, finding.value))

    blocked = findings_count > 0 and policy.mode == "block"
    scan_result = ScanResult(
        findings_count=findings_count,
        detector_counts=detector_counts,
        blocked=blocked,
    )
    return ScanTextResult(scan=scan_result, redacted_text=redacted if policy.mode == "redact" else text)


def report_to_json(result: ScanResult) -> str:
    payload = {
        "findings_count": result.findings_count,
        "detector_counts": result.detector_counts,
        "blocked": result.blocked,
    }
    return json.dumps(payload, indent=2)
