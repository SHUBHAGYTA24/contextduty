"""
contextduty.audit
~~~~~~~~~~~~~~~~~
Local append-only audit log.

Every scan / redact / interception is written to:
  ~/.contextduty/audit.jsonl   (JSONL, one record per line)

Records are never deleted by this module — rotation / archival is the
operator's responsibility (or a future `contextduty audit rotate` command).

Schema per record:
{
  "ts":          "<ISO-8601 UTC>",
  "op":          "scan" | "redact" | "mcp_intercept" | "hook_block",
  "source":      "<file path or 'stdin' or 'mcp:prompt'>",
  "policy_mode": "warn" | "redact" | "block",
  "findings":    { "<detector>": <count>, ... },
  "findings_count": <int>,
  "blocked":     true | false,
  "masked_values_count": <int>,   // only on redact ops
  "session_id":  "<uuid4>",       // groups events in one CLI run
  "version":     "<tool version>"
}
"""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_SESSION_ID = str(uuid.uuid4())
_AUDIT_DIR = Path.home() / ".contextduty"
_AUDIT_FILE = _AUDIT_DIR / "audit.jsonl"

try:
    from importlib.metadata import version as _pkg_version
    _VERSION = _pkg_version("contextduty")
except Exception:
    _VERSION = "dev"


def _ensure_dir() -> None:
    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def record(
    op: str,
    source: str,
    policy_mode: str,
    findings: Dict[str, int],
    blocked: bool,
    masked_values_count: int = 0,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Append one record to the audit log. Silent on failure (never crash the tool)."""
    try:
        _ensure_dir()
        entry: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "op": op,
            "source": source,
            "policy_mode": policy_mode,
            "findings": findings,
            "findings_count": sum(findings.values()),
            "blocked": blocked,
            "masked_values_count": masked_values_count,
            "session_id": _SESSION_ID,
            "version": _VERSION,
        }
        if extra:
            entry.update(extra)
        with _AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # audit failures must never break the tool


def tail(n: int = 20) -> list:
    """Return the last n records from the audit log."""
    try:
        if not _AUDIT_FILE.exists():
            return []
        lines = _AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        return [json.loads(ln) for ln in lines[-n:] if ln.strip()]
    except Exception:
        return []


def summary() -> Dict[str, Any]:
    """Return aggregate stats across the entire audit log."""
    try:
        if not _AUDIT_FILE.exists():
            return {"total_scans": 0, "total_findings": 0, "total_blocked": 0}
        records = []
        for ln in _AUDIT_FILE.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                try:
                    records.append(json.loads(ln))
                except Exception:
                    pass
        detector_totals: Dict[str, int] = {}
        blocked = 0
        total_findings = 0
        for r in records:
            total_findings += r.get("findings_count", 0)
            if r.get("blocked"):
                blocked += 1
            for det, cnt in r.get("findings", {}).items():
                detector_totals[det] = detector_totals.get(det, 0) + cnt
        return {
            "total_scans": len(records),
            "total_findings": total_findings,
            "total_blocked": blocked,
            "top_detectors": dict(
                sorted(detector_totals.items(), key=lambda x: -x[1])[:10]
            ),
            "audit_file": str(_AUDIT_FILE),
        }
    except Exception:
        return {}


def export_csv(out_path: str) -> int:
    """Export audit log to CSV. Returns number of rows written."""
    import csv
    records_list = []
    if _AUDIT_FILE.exists():
        for ln in _AUDIT_FILE.read_text(encoding="utf-8").splitlines():
            if ln.strip():
                try:
                    records_list.append(json.loads(ln))
                except Exception:
                    pass
    if not records_list:
        return 0
    fieldnames = ["ts", "op", "source", "policy_mode", "findings_count",
                  "blocked", "masked_values_count", "session_id", "version"]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(records_list)
    return len(records_list)