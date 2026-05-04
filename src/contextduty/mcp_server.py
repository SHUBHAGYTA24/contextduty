"""
contextduty.mcp_server
~~~~~~~~~~~~~~~~~~~~~~~
MCP stdio server for ContextDuty.

Exposed tools:
  contextduty_scan_text   — scan an in-memory string (primary prompt-interception tool)
  contextduty_scan        — scan a file on disk
  contextduty_redact      — redact a file on disk
  contextduty_audit_summary — return audit log stats (observability for Cursor users)

Run:
  contextduty-mcp

Or from editable install:
  python -m contextduty.mcp_server
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from contextduty import core, audit as _audit
    from contextduty.detectors import BUILTIN_DETECTORS, BUILTIN_NAMES
except ImportError:
    import importlib
    _pkg = Path(__file__).parent
    sys.path.insert(0, str(_pkg.parent))
    from contextduty import core, audit as _audit
    from contextduty.detectors import BUILTIN_DETECTORS, BUILTIN_NAMES

import re

# ---------------------------------------------------------------------------
# MCP wire protocol helpers (stdio JSON-RPC 2.0 subset)
# ---------------------------------------------------------------------------

def _write(obj: Dict) -> None:
    line = json.dumps(obj)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _error(req_id: Any, code: int, message: str) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def _ok(req_id: Any, result: Any) -> None:
    _write({"jsonrpc": "2.0", "id": req_id, "result": result})


# ---------------------------------------------------------------------------
# Tool definitions (returned on tools/list)
# ---------------------------------------------------------------------------

_TOOLS = [
    {
        "name": "contextduty_scan_text",
        "description": (
            "Scan an in-memory string for secrets and PII BEFORE sending it to an LLM. "
            "This is the primary ContextDuty tool for prompt-boundary enforcement. "
            "Call this on any text you are about to send to an AI model."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan"},
                "policyPath": {"type": "string", "description": "Optional policy file path"},
                "source_hint": {"type": "string", "description": "Label for audit log (e.g. 'cursor:prompt')"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "contextduty_scan",
        "description": "Scan a file on disk for secrets and PII.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute or relative file path"},
                "policyPath": {"type": "string"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "contextduty_redact",
        "description": "Redact secrets from inputPath and write clean file to outputPath.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "inputPath": {"type": "string"},
                "outputPath": {"type": "string"},
                "policyPath": {"type": "string"},
            },
            "required": ["inputPath", "outputPath"],
        },
    },
    {
        "name": "contextduty_audit_summary",
        "description": (
            "Return audit log statistics — total scans, findings, "
            "and which detectors have fired most. "
            "Use this to verify ContextDuty is actively intercepting prompts."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ---------------------------------------------------------------------------
# Core tool implementations
# ---------------------------------------------------------------------------

def _get_detectors(policy_path: Optional[str]) -> tuple:
    policy = core.load_policy(policy_path or ".contextduty.json")
    enabled = set(policy.get("detectors", list(BUILTIN_NAMES)))
    detectors = {k: v for k, v in BUILTIN_DETECTORS.items() if k in enabled}
    for name, pat in policy.get("custom_detectors", {}).items():
        try:
            detectors[name] = re.compile(pat, re.MULTILINE)
        except re.error:
            pass
    return detectors, policy


def tool_scan_text(params: Dict) -> Dict:
    text = params.get("text", "")
    policy_path = params.get("policyPath")
    source = params.get("source_hint", "mcp:prompt")
    detectors, policy = _get_detectors(policy_path)

    report = core.scan_text(text, detectors)
    mode = policy.get("mode", "redact")
    blocked = mode == "block" and report.get("findings_count", 0) > 0

    _audit.record(
        op="mcp_intercept",
        source=source,
        policy_mode=mode,
        findings=report.get("detector_counts", {}),
        blocked=blocked,
    )

    return {
        "findings_count": report.get("findings_count", 0),
        "detector_counts": report.get("detector_counts", {}),
        "blocked": blocked,
        "mode": mode,
        "safe_to_send": report.get("findings_count", 0) == 0 or mode == "warn",
        "message": (
            f"⚠️ {report['findings_count']} secret(s) detected. "
            "Redact before sending to AI." if report.get("findings_count", 0) > 0
            else "✓ No secrets detected."
        ),
    }


def tool_scan(params: Dict) -> Dict:
    path = params.get("path", "")
    policy_path = params.get("policyPath")
    detectors, policy = _get_detectors(policy_path)

    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {"error": str(exc)}

    report = core.scan_text(text, detectors)
    mode = policy.get("mode", "warn")
    blocked = mode == "block" and report.get("findings_count", 0) > 0

    _audit.record(
        op="scan",
        source=path,
        policy_mode=mode,
        findings=report.get("detector_counts", {}),
        blocked=blocked,
    )
    report["blocked"] = blocked
    return report


def tool_redact(params: Dict) -> Dict:
    in_path = params.get("inputPath", "")
    out_path = params.get("outputPath", "")
    policy_path = params.get("policyPath")
    detectors, policy = _get_detectors(policy_path)

    try:
        text = Path(in_path).read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return {"error": str(exc)}

    result = core.redact_text(text, detectors)
    try:
        Path(out_path).write_text(result["redacted"], encoding="utf-8")
    except Exception as exc:
        return {"error": f"Could not write output: {exc}"}

    _audit.record(
        op="redact",
        source=in_path,
        policy_mode=policy.get("mode", "redact"),
        findings=result.get("detector_counts", {}),
        blocked=False,
        masked_values_count=result.get("masked_values_count", 0),
    )
    return {
        "findings_count": result.get("findings_count", 0),
        "masked_values_count": result.get("masked_values_count", 0),
        "output": out_path,
    }


def tool_audit_summary(_params: Dict) -> Dict:
    return _audit.summary()


_TOOL_HANDLERS = {
    "contextduty_scan_text": tool_scan_text,
    "contextduty_scan": tool_scan,
    "contextduty_redact": tool_redact,
    "contextduty_audit_summary": tool_audit_summary,
}


# ---------------------------------------------------------------------------
# MCP message loop
# ---------------------------------------------------------------------------

def main() -> None:
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        req_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        if method == "initialize":
            _ok(req_id, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "contextduty", "version": "0.1.0"},
                "capabilities": {"tools": {}},
            })

        elif method == "tools/list":
            _ok(req_id, {"tools": _TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_input = params.get("arguments", {})
            handler = _TOOL_HANDLERS.get(tool_name)
            if handler is None:
                _error(req_id, -32601, f"Unknown tool: {tool_name}")
            else:
                try:
                    result = handler(tool_input)
                    _ok(req_id, {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
                    })
                except Exception as exc:
                    _error(req_id, -32603, str(exc))

        elif method == "notifications/initialized":
            pass  # no response needed

        else:
            _error(req_id, -32601, f"Method not found: {method}")


if __name__ == "__main__":
    main()