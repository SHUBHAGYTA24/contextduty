"""Minimal MCP stdio server exposing ContextDuty as tools.

Implements:
- initialize
- tools/list
- tools/call

Spec: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .engine import redact_file, report_to_json, scan_file, scan_text
from .policy import load_policy

PROTOCOL_VERSION = "2025-06-18"


def _send(obj: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _err(_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": _id, "error": {"code": code, "message": message}}


def _ok(_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": _id, "result": result}


def _tool_result(
    text: str, is_error: bool = False, structured: dict[str, Any] | None = None
) -> dict[str, Any]:
    payload: dict[str, Any] = {"content": [{"type": "text", "text": text}], "isError": is_error}
    if structured is not None:
        payload["structuredContent"] = structured
    return payload


def _tools_list() -> list[dict[str, Any]]:
    return [
        {
            "name": "contextduty_scan_text",
            "title": "ContextDuty Scan Text",
            "description": (
                "Scan a raw text string for sensitive data (emails, API keys, tokens, etc.) "
                "before it is sent to an LLM. Returns findings and the redacted version of the text."  # noqa: E501
                "Use this to check prompt content, log snippets, or any in-memory string."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The text content to scan and redact.",
                    },
                    "policyPath": {
                        "type": "string",
                        "description": "Optional policy JSON path (.contextduty.json).",
                    },
                },
                "required": ["text"],
            },
        },
        {
            "name": "contextduty_scan",
            "title": "ContextDuty Scan",
            "description": "Scan a file for sensitive data based on ContextDuty policy.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to input file to scan."},
                    "policyPath": {
                        "type": "string",
                        "description": "Optional policy JSON path (.contextduty.json).",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "contextduty_redact",
            "title": "ContextDuty Redact",
            "description": "Redact sensitive data from an input file into an output file based on ContextDuty policy.",  # noqa: E501
            "inputSchema": {
                "type": "object",
                "properties": {
                    "inputPath": {"type": "string", "description": "Path to input file."},
                    "outputPath": {"type": "string", "description": "Path to write redacted file."},
                    "policyPath": {
                        "type": "string",
                        "description": "Optional policy JSON path (.contextduty.json).",
                    },
                },
                "required": ["inputPath", "outputPath"],
            },
        },
    ]


def _load_policy(policy_path: str | None):
    if not policy_path:
        return load_policy(None)
    p = Path(policy_path)
    if not p.exists():
        return load_policy(None)
    return load_policy(p)


def _handle_tools_call(params: dict[str, Any]) -> dict[str, Any]:
    name = params.get("name")
    args = params.get("arguments") or {}

    if name == "contextduty_scan_text":
        text = args.get("text")
        if not isinstance(text, str):
            raise ValueError("Missing required argument: text")
        policy = _load_policy(args.get("policyPath"))
        result = scan_text(text, policy)
        structured = {
            "findings_count": result.scan.findings_count,
            "detector_counts": result.scan.detector_counts,
            "blocked": result.scan.blocked,
            "redacted_text": result.redacted_text,
        }
        report = json.dumps(structured, indent=2)
        return _tool_result(report, is_error=result.scan.blocked, structured=structured)

    if name == "contextduty_scan":
        path = args.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("Missing required argument: path")
        policy = _load_policy(args.get("policyPath"))
        result = scan_file(Path(path), policy)
        report = report_to_json(result)
        structured = {
            "findings_count": result.findings_count,
            "detector_counts": result.detector_counts,
            "blocked": result.blocked,
        }
        return _tool_result(report, is_error=False, structured=structured)

    if name == "contextduty_redact":
        input_path = args.get("inputPath")
        output_path = args.get("outputPath")
        if not isinstance(input_path, str) or not input_path:
            raise ValueError("Missing required argument: inputPath")
        if not isinstance(output_path, str) or not output_path:
            raise ValueError("Missing required argument: outputPath")
        policy = _load_policy(args.get("policyPath"))
        result = redact_file(Path(input_path), Path(output_path), policy)
        report = report_to_json(result)
        structured = {
            "findings_count": result.findings_count,
            "detector_counts": result.detector_counts,
            "blocked": result.blocked,
            "output_path": output_path,
        }
        return _tool_result(report, is_error=False, structured=structured)

    raise KeyError(f"Unknown tool: {name}")


def run_stdio() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue

        try:
            msg = json.loads(raw)
        except Exception:
            continue

        _id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params") or {}

        if _id is None:
            continue

        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "contextduty", "version": "0.1.0"},
                }
                _send(_ok(_id, result))
                continue

            if method == "tools/list":
                _send(_ok(_id, {"tools": _tools_list()}))
                continue

            if method == "tools/call":
                try:
                    payload = _handle_tools_call(params)
                    _send(_ok(_id, payload))
                except KeyError as e:
                    _send(_err(_id, -32602, str(e)))
                except Exception as e:
                    _send(_ok(_id, _tool_result(f"{type(e).__name__}: {e}", is_error=True)))
                continue

            _send(_err(_id, -32601, f"Method not found: {method}"))
        except Exception as e:
            _send(_err(_id, -32603, f"Server error: {type(e).__name__}: {e}"))


def main() -> None:
    run_stdio()


if __name__ == "__main__":
    main()
