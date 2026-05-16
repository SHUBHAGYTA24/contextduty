"""mitmproxy addon — intercepts AI API requests and redacts sensitive data.

Supports:
  - OpenAI chat completions  (api.openai.com)
  - Anthropic messages       (api.anthropic.com)
  - GitHub Copilot           (copilot.github.com, api.githubcopilot.com)

Only the *outbound* request body is scanned (the prompt going out).
Streaming responses are untouched — the prompt is where leakage originates.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("contextduty.proxy")

# AI API hostnames to intercept — everything else passes through untouched
AI_HOSTS: frozenset[str] = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "copilot.github.com",
        "api.githubcopilot.com",
        "openai.azure.com",  # Azure OpenAI
    }
)

# Paths that carry prompt content — skip embeddings, images, audio
_PROMPT_PATHS = {
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/messages",
    "/v1/engines",
}


def _is_prompt_request(host: str, path: str) -> bool:
    if host not in AI_HOSTS:
        return False
    # Accept if path starts with any known prompt path, or if it's Copilot
    if "copilot" in host or "githubcopilot" in host:
        return True
    return any(path.startswith(p) for p in _PROMPT_PATHS)


# ---------------------------------------------------------------------------
# Text extraction — each provider has a different request body schema
# ---------------------------------------------------------------------------


def _extract_texts(body: dict[str, Any], host: str) -> list[str]:
    """Pull all prompt text strings out of the request body."""
    texts: list[str] = []

    if "anthropic" in host:
        # system prompt is a top-level string
        if isinstance(body.get("system"), str):
            texts.append(body["system"])
        # system can also be a list of content blocks
        elif isinstance(body.get("system"), list):
            for block in body["system"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
        # messages array
        for msg in body.get("messages", []):
            _collect_content(msg.get("content", ""), texts)
    else:
        # OpenAI / Copilot / Azure OpenAI
        for msg in body.get("messages", []):
            _collect_content(msg.get("content", ""), texts)
        # legacy completions API
        if isinstance(body.get("prompt"), str):
            texts.append(body["prompt"])

    return texts


def _collect_content(content: Any, out: list[str]) -> None:
    """Recursively collect text from a content field (str or list of blocks)."""
    if isinstance(content, str):
        out.append(content)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    out.append(block.get("text", ""))
                # tool_use results can embed text too
                elif block.get("type") == "tool_result":
                    _collect_content(block.get("content", ""), out)


def _inject_texts(body: dict[str, Any], texts: list[str], host: str) -> None:
    """Write redacted text back into the request body in place."""
    idx = 0

    def _next() -> str:
        nonlocal idx
        t = texts[idx] if idx < len(texts) else ""
        idx += 1
        return t

    if "anthropic" in host:
        if isinstance(body.get("system"), str):
            body["system"] = _next()
        elif isinstance(body.get("system"), list):
            for block in body["system"]:
                if isinstance(block, dict) and block.get("type") == "text":
                    block["text"] = _next()
        for msg in body.get("messages", []):
            _inject_content(msg, "content", _next)
    else:
        for msg in body.get("messages", []):
            _inject_content(msg, "content", _next)
        if isinstance(body.get("prompt"), str):
            body["prompt"] = _next()


def _inject_content(obj: dict, key: str, next_text) -> None:
    content = obj.get(key, "")
    if isinstance(content, str):
        obj[key] = next_text()
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                block["text"] = next_text()
            elif isinstance(block, dict) and block.get("type") == "tool_result":
                _inject_content(block, "content", next_text)


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------


class ContextDutyAddon:
    """mitmproxy addon — intercepts and redacts AI API requests."""

    def __init__(self, policy_path: str | None = None, audit_log: str | None = None):
        from .engine import scan_text
        from .policy import load_policy

        self._scan_text = scan_text
        policy_file = Path(policy_path) if policy_path else Path(".contextduty.json")
        self.policy = load_policy(policy_file if policy_file.exists() else None)
        self.audit_log = Path(audit_log) if audit_log else None
        self._findings_total = 0
        self._requests_intercepted = 0

    def request(self, flow) -> None:  # mitmproxy.http.HTTPFlow
        host = flow.request.host
        path = flow.request.path

        if not _is_prompt_request(host, path):
            return

        # Only handle JSON bodies
        content_type = flow.request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return

        try:
            raw = flow.request.get_text(strict=False)
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return

        texts = _extract_texts(body, host)
        if not texts:
            return

        self._requests_intercepted += 1
        total_findings = 0
        blocked = False
        all_detector_counts: dict[str, int] = {}

        redacted_texts: list[str] = []
        for text in texts:
            result = self._scan_text(text, self.policy)
            redacted_texts.append(result.redacted_text)
            total_findings += result.scan.findings_count
            for det, count in result.scan.detector_counts.items():
                all_detector_counts[det] = all_detector_counts.get(det, 0) + count
            if result.scan.blocked:
                blocked = True

        self._findings_total += total_findings

        if total_findings == 0:
            return  # clean — forward unchanged

        if blocked:
            log.warning(
                "[ContextDuty] BLOCKED request to %s — %d finding(s): %s",
                host,
                total_findings,
                ", ".join(f"{k}:{v}" for k, v in all_detector_counts.items()),
            )
            flow.response = _block_response()
            self._write_audit(
                "proxy_intercept", host, total_findings, all_detector_counts, blocked=True
            )
            return

        # warn mode — log but don't modify the request body
        if self.policy.mode == "warn" and not any(
            self.policy.detector_modes.get(d) == "redact" for d in all_detector_counts
        ):
            log.info(
                "[ContextDuty] WARN request to %s — %d finding(s): %s",
                host,
                total_findings,
                ", ".join(f"{k}:{v}" for k, v in all_detector_counts.items()),
            )
            self._write_audit(
                "proxy_intercept", host, total_findings, all_detector_counts, blocked=False
            )
            return

        # Redact in place
        _inject_texts(body, redacted_texts, host)
        flow.request.set_text(json.dumps(body))

        log.info(
            "[ContextDuty] Redacted request to %s — %d finding(s): %s",
            host,
            total_findings,
            ", ".join(f"{k}:{v}" for k, v in all_detector_counts.items()),
        )
        self._write_audit(
            "proxy_intercept", host, total_findings, all_detector_counts, blocked=False
        )

    def _write_audit(
        self,
        operation: str,
        target: str,
        findings_count: int,
        detector_counts: dict[str, int],
        blocked: bool,
    ) -> None:
        if not self.audit_log:
            return
        try:
            from .audit import write_audit_entry
            from .engine import ScanResult

            result = ScanResult(
                findings_count=findings_count,
                detector_counts=detector_counts,
                blocked=blocked,
                blocked_by=sorted(k for k in detector_counts if blocked),
            )
            write_audit_entry(
                operation=operation,
                result=result,
                policy_path=None,
                target=target,
                audit_log_path=self.audit_log,
            )
        except Exception as exc:
            log.debug("Audit write failed: %s", exc)


def _block_response():
    """Return a 403 JSON response that looks like an API error."""

    body = json.dumps(
        {
            "error": {
                "type": "contextduty_block",
                "code": "sensitive_data_detected",
                "message": (
                    "ContextDuty blocked this request: sensitive data detected in prompt. "
                    "Remove or redact the sensitive values before sending."
                ),
            }
        }
    ).encode()

    from mitmproxy.http import Response

    return Response.make(
        403,
        body,
        {"Content-Type": "application/json", "X-Blocked-By": "ContextDuty"},
    )


# Entry point for `mitmdump -s proxy_addon.py`
addons = [ContextDutyAddon()]
