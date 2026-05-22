"""Scanning and redaction engine."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .config import BINARY_EXTENSIONS
from .detectors import DETECTORS, Detector, stable_mask
from .policy import Policy

# Backward-compat alias — old imports still work
_BINARY_EXTENSIONS = BINARY_EXTENSIONS

# Cache for compiled custom detector patterns — avoids re-compiling on every scan.
_custom_pattern_cache: dict[str, re.Pattern[str]] = {}


@dataclass(frozen=True)
class Finding:
    detector: str
    value: str
    start: int = 0  # character offset within the line
    end: int = 0


@dataclass(frozen=True)
class ScanResult:
    findings_count: int
    detector_counts: dict[str, int]
    blocked: bool
    # Detectors that triggered a block (subset of detector_counts keys).
    blocked_by: list[str] = None  # type: ignore[assignment]
    # Files scanned (populated by scan_dir; empty for single-file scans).
    files_scanned: list[str] = field(default_factory=list)

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
    for name, pattern_str in policy.custom_detectors.items():
        if name in policy.detectors:
            # Cache compiled patterns — same pattern string reuses the compiled object.
            if pattern_str not in _custom_pattern_cache:
                _custom_pattern_cache[pattern_str] = re.compile(pattern_str)
            active.append(Detector(name=name, pattern=_custom_pattern_cache[pattern_str]))
    return active


def _scan_line(line: str, detectors: Iterable[Detector]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in detectors:
        for match in detector.pattern.finditer(line):
            findings.append(
                Finding(
                    detector=detector.name,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
    return findings


def _apply_findings(
    text: str,
    findings: list[Finding],
    policy: Policy,
    detector_counts: dict[str, int],
    blocked_detectors: set[str],
    redact_blocked: bool = False,
) -> str:
    """Apply per-detector mode logic to a text segment. Returns the (possibly redacted) text.

    Uses offset-based single-pass replacement: sort findings by start position,
    skip overlapping ranges already claimed by a longer match, and build the
    output string in one pass.  This avoids O(n²) ``str.replace()`` chains on
    lines with many findings.

    Args:
        redact_blocked: When True (used by redact_file), block-mode detectors also have their
            values masked in the output. When False (used by scan), block-mode values are left
            in place and only flagged.
    """
    if not findings:
        return text

    # First pass: decide what to mask (longest match wins for overlaps).
    # Sort longest-first so a long match takes priority over shorter overlapping ones.
    replacements: list[tuple[int, int, str]] = []  # (start, end, mask)
    claimed: set[str] = set()  # deduplicate identical values

    for finding in sorted(findings, key=lambda f: len(f.value), reverse=True):
        if _is_allowed(finding.value, finding.detector, policy):
            continue
        if finding.value in claimed:
            # Still count it, but don't add another replacement.
            detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
            mode = _effective_mode(policy, finding.detector)
            if mode == "block":
                blocked_detectors.add(finding.detector)
            continue

        detector_counts[finding.detector] = detector_counts.get(finding.detector, 0) + 1
        mode = _effective_mode(policy, finding.detector)

        if mode == "block":
            blocked_detectors.add(finding.detector)
            if redact_blocked:
                mask = stable_mask(finding.detector, finding.value)
                replacements.append((finding.start, finding.end, mask))
                claimed.add(finding.value)
        elif mode == "redact":
            mask = stable_mask(finding.detector, finding.value)
            replacements.append((finding.start, finding.end, mask))
            claimed.add(finding.value)
        # mode == "warn": count it, don't mask, don't block

    if not replacements:
        return text

    # Second pass: build output in one sweep (sort by start offset).
    replacements.sort(key=lambda r: r[0])
    parts: list[str] = []
    cursor = 0
    for start, end, mask in replacements:
        if start < cursor:
            continue  # skip if overlapping with a prior replacement
        parts.append(text[cursor:start])
        parts.append(mask)
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def _extract_notebook_sources(path: Path) -> list[str]:
    """Extract source lines from Jupyter notebook code and markdown cells."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            nb = json.load(f)
        lines: list[str] = []
        for cell in nb.get("cells", []):
            source = cell.get("source", [])
            if isinstance(source, list):
                lines.extend(source)
            elif isinstance(source, str):
                lines.extend(source.splitlines(keepends=True))
            # Also scan cell outputs for leaked secrets
            for output in cell.get("outputs", []):
                text = output.get("text", [])
                if isinstance(text, list):
                    lines.extend(text)
                elif isinstance(text, str):
                    lines.extend(text.splitlines(keepends=True))
                data = output.get("data", {})
                for mime_lines in data.values():
                    if isinstance(mime_lines, list):
                        lines.extend(mime_lines)
                    elif isinstance(mime_lines, str):
                        lines.extend(mime_lines.splitlines(keepends=True))
        return lines
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def scan_file(path: Path, policy: Policy) -> ScanResult:
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()

    if path.suffix.lower() == ".ipynb":
        lines = _extract_notebook_sources(path)
        if not lines:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        for line in lines:
            findings = _scan_line(line, detectors)
            _apply_findings(line, findings, policy, detector_counts, blocked_detectors)
    else:
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


def scan_dir(
    root: Path,
    policy: Policy,
    recursive: bool = True,
    *,
    fail_fast: bool = False,
) -> ScanResult:
    """Scan every text file under *root* and return a combined ScanResult.

    Skips binary files (by extension) and files that cannot be decoded as UTF-8.
    If *root* is a file, delegates to scan_file().

    Args:
        fail_fast: When True, stop scanning after the first file that triggers
            a block.  Useful for large repos in CI where you only care whether
            the build should fail.
    """
    if root.is_file():
        return scan_file(root, policy)

    if not root.is_dir():
        raise ValueError(f"{root} is not a file or directory")

    glob = root.rglob("*") if recursive else root.glob("*")

    combined_counts: dict[str, int] = {}
    combined_blocked: set[str] = set()
    files_scanned: list[str] = []

    for path in sorted(p for p in glob if p.is_file()):
        if path.suffix.lower() in _BINARY_EXTENSIONS:
            continue
        try:
            result = scan_file(path, policy)
        except (OSError, UnicodeDecodeError):
            continue
        files_scanned.append(str(path))
        for det, count in result.detector_counts.items():
            combined_counts[det] = combined_counts.get(det, 0) + count
        combined_blocked.update(result.blocked_by)

        if fail_fast and combined_blocked:
            break

    return ScanResult(
        findings_count=sum(combined_counts.values()),
        detector_counts=combined_counts,
        blocked=bool(combined_blocked),
        blocked_by=sorted(combined_blocked),
        files_scanned=files_scanned,
    )


def _redact_notebook(input_path: Path, output_path: Path, policy: Policy) -> ScanResult:
    """Redact secrets in a Jupyter notebook, preserving the .ipynb JSON structure."""
    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        nb = json.load(f)

    for cell in nb.get("cells", []):
        source = cell.get("source", [])
        if isinstance(source, list):
            cell["source"] = [
                _apply_findings(
                    line,
                    _scan_line(line, detectors),
                    policy,
                    detector_counts,
                    blocked_detectors,
                    redact_blocked=True,
                )
                for line in source
            ]
        elif isinstance(source, str):
            lines = source.splitlines(keepends=True)
            cell["source"] = "".join(
                _apply_findings(
                    line,
                    _scan_line(line, detectors),
                    policy,
                    detector_counts,
                    blocked_detectors,
                    redact_blocked=True,
                )
                for line in lines
            )
        for output in cell.get("outputs", []):
            text = output.get("text", [])
            if isinstance(text, list):
                output["text"] = [
                    _apply_findings(
                        line,
                        _scan_line(line, detectors),
                        policy,
                        detector_counts,
                        blocked_detectors,
                        redact_blocked=True,
                    )
                    for line in text
                ]
            data = output.get("data", {})
            for mime_type, mime_lines in data.items():
                if isinstance(mime_lines, list):
                    data[mime_type] = [
                        _apply_findings(
                            line,
                            _scan_line(line, detectors),
                            policy,
                            detector_counts,
                            blocked_detectors,
                            redact_blocked=True,
                        )
                        for line in mime_lines
                    ]

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)
        f.write("\n")

    findings_count = sum(detector_counts.values())
    blocked = len(blocked_detectors) > 0
    return ScanResult(
        findings_count=findings_count,
        detector_counts=detector_counts,
        blocked=blocked,
        blocked_by=sorted(blocked_detectors),
    )


def redact_file(input_path: Path, output_path: Path, policy: Policy) -> ScanResult:
    if input_path.suffix.lower() == ".ipynb":
        try:
            return _redact_notebook(input_path, output_path, policy)
        except (json.JSONDecodeError, KeyError, TypeError):
            pass  # Fallback to plain text redaction

    detectors = _active_detectors(policy)
    detector_counts: dict[str, int] = {}
    blocked_detectors: set[str] = set()

    with (
        input_path.open("r", encoding="utf-8", errors="replace") as source,
        output_path.open("w", encoding="utf-8") as target,
    ):
        for line in source:
            findings = _scan_line(line, detectors)
            updated = _apply_findings(
                line, findings, policy, detector_counts, blocked_detectors, redact_blocked=True
            )
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
    if result.files_scanned:
        payload["files_scanned"] = len(result.files_scanned)
        payload["files_with_findings"] = [f for f in result.files_scanned]
    return json.dumps(payload, indent=2)
