"""mitmproxy addon — intercepts AI API requests and redacts sensitive data.

This is loaded by mitmdump via: mitmdump -s addon.py

Supports all AI providers registered in scope.py. Uses the declarative
interceptor for request body parsing — handles Cursor, OpenAI, Anthropic,
Google Gemini, and any future provider with zero code changes (just add
field paths to interceptor.PROVIDER_FIELDS).
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

# When mitmproxy loads this file via `-s addon.py` it runs it as
# __mitmproxy_script__, not as contextduty.proxy.addon — so relative
# imports fail. We detect that and ensure the package is importable.
if __name__ == "__mitmproxy_script__" or not __package__:
    _pkg_root = Path(__file__).parent.parent.parent.parent
    if str(_pkg_root) not in sys.path:
        sys.path.insert(0, str(_pkg_root))
    from contextduty.proxy.feed import record_interception
    from contextduty.proxy.interceptor import redact_body
    from contextduty.proxy.scope import is_prompt_request
else:
    from .feed import record_interception
    from .interceptor import redact_body
    from .scope import is_prompt_request

log = logging.getLogger("contextduty.proxy")


class ContextDutyAddon:
    """mitmproxy addon — intercepts and redacts AI API requests."""

    def __init__(self, policy_path: str | None = None, audit_log: str | None = None):
        from ..engine import scan_text
        from ..policy import load_policy

        self._scan_text = scan_text
        policy_file = Path(policy_path) if policy_path else Path(".contextduty.json")
        self.policy = load_policy(policy_file if policy_file.exists() else None)
        self.audit_log = Path(audit_log) if audit_log else None
        self._findings_total = 0
        self._requests_intercepted = 0

    def request(self, flow) -> None:  # mitmproxy.http.HTTPFlow
        """Called by mitmproxy for every intercepted request."""
        host = flow.request.host
        path = flow.request.path

        if not is_prompt_request(host, path):
            return

        content_type = flow.request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return

        try:
            raw = flow.request.get_text(strict=False)
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return

        self._requests_intercepted += 1
        policy = self.policy

        def scan_fn(text: str):
            return self._scan_text(text, policy)

        # Declarative interceptor handles all providers
        total_findings, detector_counts, blocked = redact_body(body, host, scan_fn)
        self._findings_total += total_findings

        # Emit live feed event
        if blocked:
            action = "blocked"
        elif total_findings > 0:
            action = "redacted" if policy.mode != "warn" else "warn"
        else:
            action = "clean"
        record_interception(host, action, total_findings, detector_counts)

        if total_findings == 0:
            return  # clean — forward unchanged

        if blocked:
            log.warning(
                "[ContextDuty] BLOCKED %s — %d finding(s): %s",
                host,
                total_findings,
                ", ".join(f"{k}:{v}" for k, v in detector_counts.items()),
            )
            flow.response = _block_response()
            self._write_audit(host, total_findings, detector_counts, blocked=True)
            return

        # Warn mode — log only, don't modify body
        if policy.mode == "warn" and not any(
            policy.detector_modes.get(d) == "redact" for d in detector_counts
        ):
            log.info(
                "[ContextDuty] WARN %s — %d finding(s)",
                host,
                total_findings,
            )
            self._write_audit(host, total_findings, detector_counts, blocked=False)
            return

        # Redact mode — body was modified in-place by redact_body
        flow.request.set_text(json.dumps(body))
        log.info(
            "[ContextDuty] Redacted %s — %d finding(s): %s",
            host,
            total_findings,
            ", ".join(f"{k}:{v}" for k, v in detector_counts.items()),
        )
        self._write_audit(host, total_findings, detector_counts, blocked=False)

    def _write_audit(
        self,
        target: str,
        findings_count: int,
        detector_counts: dict[str, int],
        blocked: bool,
    ) -> None:
        if not self.audit_log:
            return
        try:
            from ..audit import write_audit_entry
            from ..engine import ScanResult

            result = ScanResult(
                findings_count=findings_count,
                detector_counts=detector_counts,
                blocked=blocked,
                blocked_by=sorted(k for k in detector_counts if blocked),
            )
            write_audit_entry(
                operation="proxy_intercept",
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

    try:
        from mitmproxy.http import Response

        return Response.make(
            403,
            body,
            {"Content-Type": "application/json", "X-Blocked-By": "ContextDuty"},
        )
    except ImportError:
        # Fallback for environments without mitmproxy (e.g. testing)
        from unittest.mock import MagicMock

        resp = MagicMock()
        resp.status_code = 403
        resp.content = body
        return resp


# Entry point for `mitmdump -s addon.py`
addons = [ContextDutyAddon()]
