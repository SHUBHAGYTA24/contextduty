"""
contextduty.githistory
~~~~~~~~~~~~~~~~~~~~~~
Scan committed git history for secrets — the "I think I leaked something"
emergency command.

Usage:
    contextduty scan-history [--since <rev>] [--max-commits N] [--policy <file>]

How it works:
    1. Runs `git log -p --all` (or a bounded subset) and feeds the patch
       stream through the same detector engine used for file scans.
    2. For each finding, records: commit SHA, author, timestamp, file path,
       line number, detector name, and the masked value.
    3. Outputs a structured JSON report.  Never prints raw secret values.

The scan is read-only — it never rewrites history.  To actually purge a
secret from history you need git-filter-repo or BFG Repo Cleaner; the report
tells you exactly which commits and files to target.
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Tuple


@dataclass
class HistoryFinding:
    commit_sha: str
    author: str
    author_email: str
    commit_date: str
    commit_message: str
    file_path: str
    line_number: int
    detector: str
    masked_value: str
    raw_line: str  # line with secret already masked


@dataclass
class HistoryScanReport:
    findings: List[HistoryFinding] = field(default_factory=list)
    commits_scanned: int = 0
    files_affected: List[str] = field(default_factory=list)
    commits_affected: List[str] = field(default_factory=list)
    detector_counts: Dict[str, int] = field(default_factory=dict)
    remediation_hint: str = (
        "To purge secrets from history, use: "
        "git filter-repo --path <file> --invert-paths  "
        "or BFG Repo Cleaner (https://rtyley.github.io/bfg-repo-cleaner/)"
    )

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["findings_count"] = len(self.findings)
        d["files_affected"] = sorted(set(self.files_affected))
        d["commits_affected"] = sorted(set(self.commits_affected))
        return d


# Simple deterministic masker (mirrors core.py logic without import cycle)
def _mask(value: str, detector: str) -> str:
    import hashlib
    h = hashlib.sha256(value.encode()).hexdigest()[:10]
    tag = detector.upper()
    return f"<{tag}_{h}>"


def _check_git_available() -> bool:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _git_log_stream(since: Optional[str], max_commits: Optional[int]) -> Iterator[str]:
    """Stream `git log -p` output line by line."""
    cmd = [
        "git", "log", "-p", "--all",
        "--format=COMMIT_HEADER %H %ae %an %ci %s",
        "--diff-filter=AM",  # only Added / Modified — not deletions
        "--no-color",
    ]
    if since:
        cmd.append(f"--since={since}")
    if max_commits:
        cmd.extend(["-n", str(max_commits)])

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors="replace", bufsize=1
    )
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            yield line.rstrip("\n")
    finally:
        proc.wait()


def scan_history(
    detectors: Dict[str, Any],  # {name: compiled re.Pattern}
    since: Optional[str] = None,
    max_commits: Optional[int] = 500,
    repo_path: str = ".",
) -> HistoryScanReport:
    """
    Walk git history and detect secrets in patch diffs.
    Returns a HistoryScanReport (never raises on missing git).
    """
    import os
    orig_dir = os.getcwd()
    report = HistoryScanReport()

    if not _check_git_available():
        report.remediation_hint = "git not found or not inside a git repository."
        return report

    try:
        os.chdir(repo_path)
        current_commit: Dict[str, str] = {}
        current_file = "(unknown)"
        line_number = 0
        seen_commits: set = set()

        for raw_line in _git_log_stream(since, max_commits):
            # ── Parse commit header injected by --format ──────────────────
            if raw_line.startswith("COMMIT_HEADER "):
                parts = raw_line[len("COMMIT_HEADER "):].split(" ", 4)
                sha = parts[0] if len(parts) > 0 else "unknown"
                if sha not in seen_commits:
                    seen_commits.add(sha)
                    report.commits_scanned += 1
                current_commit = {
                    "sha": sha,
                    "email": parts[1] if len(parts) > 1 else "",
                    "author": parts[2] if len(parts) > 2 else "",
                    "date": parts[3] if len(parts) > 3 else "",
                    "message": parts[4] if len(parts) > 4 else "",
                }
                current_file = "(unknown)"
                line_number = 0
                continue

            # ── Parse diff file header ────────────────────────────────────
            if raw_line.startswith("+++ b/"):
                current_file = raw_line[6:]
                line_number = 0
                continue

            # ── Track line numbers in added hunks ─────────────────────────
            if raw_line.startswith("@@ "):
                # @@ -a,b +c,d @@ ...  — extract the '+' start line
                m = re.search(r"\+(\d+)", raw_line)
                line_number = int(m.group(1)) - 1 if m else 0
                continue

            # Only scan added lines (not context or removed)
            if not raw_line.startswith("+"):
                continue

            line_number += 1
            content = raw_line[1:]  # strip leading '+'

            # ── Run detectors ─────────────────────────────────────────────
            for det_name, pattern in detectors.items():
                for m in pattern.finditer(content):
                    raw_val = m.group(0)
                    masked = _mask(raw_val, det_name)
                    masked_line = content[:m.start()] + masked + content[m.end():]

                    finding = HistoryFinding(
                        commit_sha=current_commit.get("sha", ""),
                        author=current_commit.get("author", ""),
                        author_email=current_commit.get("email", ""),
                        commit_date=current_commit.get("date", ""),
                        commit_message=current_commit.get("message", ""),
                        file_path=current_file,
                        line_number=line_number,
                        detector=det_name,
                        masked_value=masked,
                        raw_line=masked_line,
                    )
                    report.findings.append(finding)
                    report.files_affected.append(current_file)
                    report.commits_affected.append(current_commit.get("sha", ""))
                    report.detector_counts[det_name] = (
                        report.detector_counts.get(det_name, 0) + 1
                    )

        return report

    except Exception as exc:
        report.remediation_hint = f"Scan error: {exc}"
        return report
    finally:
        os.chdir(orig_dir)