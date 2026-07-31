"""Live-credential verification (opt-in).

For a subset of detectors, ContextDuty can check whether a *found* credential
is actually **live** by making a minimal, read-only request to that
credential's **own provider** (e.g. a GitHub token → api.github.com). This
turns a finding from "matched a pattern" into "this is an active key," which
sharply reduces false-positive fatigue.

This is **opt-in and off by default** because it makes network calls. When
enabled, the credential is sent only to its own issuing provider — never to
ContextDuty or any third party. Nothing is stored.

Status values:
    active       — the provider accepted the credential (it works)
    inactive     — the provider rejected it (revoked / invalid)
    unverified   — network error, timeout, or ambiguous response
    unsupported  — no verifier exists for this detector
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from base64 import b64encode
from typing import Callable

__all__ = [
    "ACTIVE",
    "INACTIVE",
    "UNVERIFIED",
    "UNSUPPORTED",
    "is_verifiable",
    "verify",
    "verify_findings",
]

ACTIVE = "active"
INACTIVE = "inactive"
UNVERIFIED = "unverified"
UNSUPPORTED = "unsupported"

_DEFAULT_TIMEOUT = 5.0
_UA = "contextduty-verify"


def _status_code(url: str, headers: dict[str, str], timeout: float) -> int | None:
    """GET *url* and return the HTTP status code, or None on network error."""
    req = urllib.request.Request(url, headers={**headers, "User-Agent": _UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only below)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


def _verify_github(value: str, timeout: float) -> str:
    code = _status_code(
        "https://api.github.com/user", {"Authorization": f"Bearer {value}"}, timeout
    )
    if code == 200:
        return ACTIVE
    if code in (401, 403):
        return INACTIVE
    return UNVERIFIED


def _verify_openai(value: str, timeout: float) -> str:
    code = _status_code(
        "https://api.openai.com/v1/models", {"Authorization": f"Bearer {value}"}, timeout
    )
    if code == 200:
        return ACTIVE
    if code == 401:
        return INACTIVE
    return UNVERIFIED


def _verify_stripe(value: str, timeout: float) -> str:
    token = b64encode(f"{value}:".encode()).decode()
    code = _status_code(
        "https://api.stripe.com/v1/account", {"Authorization": f"Basic {token}"}, timeout
    )
    if code == 200:
        return ACTIVE
    if code == 401:
        return INACTIVE
    return UNVERIFIED


def _verify_slack(value: str, timeout: float) -> str:
    # Slack returns HTTP 200 with an {"ok": bool} body regardless of validity.
    req = urllib.request.Request(
        "https://slack.com/api/auth.test",
        headers={"Authorization": f"Bearer {value}", "User-Agent": _UA},
        data=b"",
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return ACTIVE if body.get("ok") else INACTIVE
    except Exception:
        return UNVERIFIED


# detector name → verifier. Only credentials whose own provider offers a cheap
# read-only auth check are listed; everything else is "unsupported".
_VERIFIERS: dict[str, Callable[[str, float], str]] = {
    "github_pat": _verify_github,
    "github_oauth": _verify_github,
    "github_app_token": _verify_github,
    "github_refresh_token": _verify_github,
    "openai_key": _verify_openai,
    "stripe_secret": _verify_stripe,
    "stripe_restricted": _verify_stripe,
    "slack_bot_token": _verify_slack,
    "slack_user_token": _verify_slack,
}


def is_verifiable(detector: str) -> bool:
    """Return True if ContextDuty can check whether *detector*'s value is live."""
    return detector in _VERIFIERS


def verify(detector: str, value: str, *, timeout: float = _DEFAULT_TIMEOUT) -> str:
    """Check whether *value* is a live credential for *detector*.

    Makes a read-only request to the credential's own provider. Returns one of
    ``ACTIVE``, ``INACTIVE``, ``UNVERIFIED``, or ``UNSUPPORTED``.
    """
    verifier = _VERIFIERS.get(detector)
    if verifier is None:
        return UNSUPPORTED
    return verifier(value, timeout)


def verify_findings(text, policy, *, timeout: float = _DEFAULT_TIMEOUT) -> list[tuple[str, str]]:
    """Scan *text* and verify each unique verifiable credential found.

    Returns a list of ``(detector, status)`` tuples — one per distinct
    verifiable credential. Raw values are never returned. Non-verifiable
    detectors are ignored here.
    """
    from .engine import _active_detectors, _scan_line

    detectors = [d for d in _active_detectors(policy) if is_verifiable(d.name)]
    if not detectors:
        return []

    seen: set[tuple[str, str]] = set()
    results: list[tuple[str, str]] = []
    for line in text.splitlines():
        for finding in _scan_line(line, detectors):
            key = (finding.detector, finding.value)
            if key in seen:
                continue
            seen.add(key)
            status = verify(finding.detector, finding.value, timeout=timeout)
            results.append((finding.detector, status))
    return results
