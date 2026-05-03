"""Structured audit logging for ContextDuty.

Every scan and redact operation can emit a JSONL entry to an audit log.
The log never records matched values — only that a finding occurred,
which detector fired, and what enforcement action was taken.

This gives enterprise security teams the audit trail they need for
SOC 2, HIPAA, and internal AI usage governance without creating a
secondary leak vector.

Usage:
    contextduty scan file.txt --audit-log /var/log/contextduty/audit.jsonl
    contextduty report --audit-log /var/log/contextduty/audit.jsonl
"""

from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from .engine import ScanResult


def _identity() -> dict[str, str]:
    """Collect non-sensitive identity context for the audit entry."""
    return {
        "hostname": socket.gethostname(),
        "user": os.environ.get("CONTEXTDUTY_USER")
        or os.environ.get("USER")
        or os.environ.get("USERNAME")
        or "unknown",
        "tool": os.environ.get("CONTEXTDUTY_TOOL", "cli"),
    }


def write_audit_entry(
    *,
    operation: str,
    result: ScanResult,
    policy_path: str | None,
    target: str,
    audit_log_path: Path,
) -> None:
    """Append one JSONL audit entry to audit_log_path.

    Args:
        operation: "scan" or "redact"
        result: the ScanResult from the engine
        policy_path: path to the policy file used, or None for default
        target: the file path or "<text>" for in-memory scans
        audit_log_path: path to the JSONL audit log file
    """
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "target": target,
        "policy": policy_path or "<default>",
        "findings_count": result.findings_count,
        "detector_counts": result.detector_counts,
        "blocked": result.blocked,
        "blocked_by": result.blocked_by,
        **_identity(),
    }

    with audit_log_path.open("a", encoding="utf-8") as log:
        log.write(json.dumps(entry, separators=(",", ":")) + "\n")


def generate_report(audit_log_path: Path) -> dict:
    """Read the audit log and produce a summary report.

    Returns a dict suitable for JSON serialisation.
    """
    if not audit_log_path.exists():
        return {"error": f"Audit log not found: {audit_log_path}"}

    entries: list[dict] = []
    with audit_log_path.open("r", encoding="utf-8") as log:
        for line in log:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not entries:
        return {"total_scans": 0, "message": "No entries in audit log."}

    total_scans = len(entries)
    total_findings = sum(e.get("findings_count", 0) for e in entries)
    total_blocked = sum(1 for e in entries if e.get("blocked"))

    detector_totals: dict[str, int] = {}
    for entry in entries:
        for det, count in entry.get("detector_counts", {}).items():
            detector_totals[det] = detector_totals.get(det, 0) + count

    users: dict[str, int] = {}
    for entry in entries:
        user = entry.get("user", "unknown")
        users[user] = users.get(user, 0) + 1

    blocked_by_totals: dict[str, int] = {}
    for entry in entries:
        for det in entry.get("blocked_by", []):
            blocked_by_totals[det] = blocked_by_totals.get(det, 0) + 1

    first_ts = entries[0].get("ts", "")
    last_ts = entries[-1].get("ts", "")

    return {
        "period": {"from": first_ts, "to": last_ts},
        "total_scans": total_scans,
        "total_findings": total_findings,
        "total_blocked": total_blocked,
        "block_rate_pct": round(100 * total_blocked / total_scans, 1) if total_scans else 0,
        "detector_totals": dict(sorted(detector_totals.items(), key=lambda x: x[1], reverse=True)),
        "blocked_by_totals": dict(
            sorted(blocked_by_totals.items(), key=lambda x: x[1], reverse=True)
        ),
        "scans_by_user": dict(sorted(users.items(), key=lambda x: x[1], reverse=True)),
        "entries": total_scans,
    }
