"""
contextduty.dirscanner
~~~~~~~~~~~~~~~~~~~~~~
Scan an entire directory tree, respecting .gitignore rules and
skipping binary / vendor / generated files.

Usage (from core / CLI):
    from contextduty.dirscanner import scan_directory

    results = scan_directory(
        root="src/",
        policy=policy,
        detectors=detectors,
    )
    # results: list of {"file": str, "report": ScanReport}
"""

import os
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

# ---------------------------------------------------------------------------
# Gitignore-aware file walker
# ---------------------------------------------------------------------------

# Extensions we always skip (binary, compiled, lock files, etc.)
_SKIP_EXTENSIONS = {
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp4", ".mp3", ".mov", ".avi", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".xz", ".rar", ".7z", ".whl", ".egg",
    ".lock",  # package-lock.json, poetry.lock, Cargo.lock — too noisy
    ".min.js", ".min.css",
}

# Directory names we always skip
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".eggs", "*.egg-info", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "coverage", ".coverage",
    "vendor", "third_party", ".idea", ".vscode",
}


def _parse_gitignore(root: Path) -> List[re.Pattern]:
    """Return compiled ignore patterns from <root>/.gitignore."""
    gi = root / ".gitignore"
    patterns: List[re.Pattern] = []
    if not gi.exists():
        return patterns
    for line in gi.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Convert glob to regex (very simplified — covers common cases)
        escaped = re.escape(line).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        try:
            patterns.append(re.compile(escaped))
        except re.error:
            pass
    return patterns


def _is_ignored(path: Path, root: Path, gitignore_patterns: List[re.Pattern]) -> bool:
    rel = str(path.relative_to(root))
    for pat in gitignore_patterns:
        if pat.search(rel):
            return True
    return False


def _should_skip_file(path: Path) -> bool:
    name = path.name
    suffix = path.suffix.lower()
    if suffix in _SKIP_EXTENSIONS:
        return True
    if name.endswith(".min.js") or name.endswith(".min.css"):
        return True
    # Skip very large files (>1 MB) — likely generated / data
    try:
        if path.stat().st_size > 1_048_576:
            return True
    except OSError:
        return True
    # Quick binary sniff — look at first 512 bytes
    try:
        with path.open("rb") as fh:
            chunk = fh.read(512)
        if b"\x00" in chunk:
            return True
    except OSError:
        return True
    return False


def iter_files(root: str) -> Iterator[Path]:
    """Yield scannable files under root, respecting .gitignore and skip lists."""
    root_path = Path(root).resolve()
    gitignore = _parse_gitignore(root_path)

    for dirpath, dirnames, filenames in os.walk(root_path):
        cur = Path(dirpath)
        # Prune skip dirs in-place so os.walk doesn't descend
        dirnames[:] = [
            d for d in dirnames
            if d not in _SKIP_DIRS
            and not _is_ignored(cur / d, root_path, gitignore)
        ]
        for fname in filenames:
            fpath = cur / fname
            if _should_skip_file(fpath):
                continue
            if _is_ignored(fpath, root_path, gitignore):
                continue
            yield fpath


def scan_directory(
    root: str,
    scan_fn: Any,          # callable(text: str, detectors) -> ScanReport-like dict
    detectors: Dict,
    policy: Any,
) -> List[Dict]:
    """
    Walk root and call scan_fn on each file's text content.
    Returns list of {"file": str, "report": dict, "error": str|None}.
    """
    results = []
    for fpath in iter_files(root):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
            report = scan_fn(text, detectors, policy)
            results.append({"file": str(fpath), "report": report, "error": None})
        except Exception as exc:
            results.append({"file": str(fpath), "report": None, "error": str(exc)})
    return results


def aggregate_report(results: List[Dict]) -> Dict:
    """Summarise directory scan results into a single report dict."""
    total_findings = 0
    detector_counts: Dict[str, int] = {}
    files_with_findings = []
    errors = []
    files_scanned = 0

    for item in results:
        if item["error"]:
            errors.append({"file": item["file"], "error": item["error"]})
            continue
        files_scanned += 1
        report = item["report"] or {}
        fc = report.get("findings_count", 0)
        total_findings += fc
        if fc > 0:
            files_with_findings.append({
                "file": item["file"],
                "findings_count": fc,
                "detector_counts": report.get("detector_counts", {}),
            })
        for det, cnt in report.get("detector_counts", {}).items():
            detector_counts[det] = detector_counts.get(det, 0) + cnt

    return {
        "files_scanned": files_scanned,
        "files_with_findings": len(files_with_findings),
        "findings_count": total_findings,
        "detector_counts": detector_counts,
        "files": files_with_findings,
        "errors": errors,
        "blocked": total_findings > 0,  # caller checks policy mode
    }