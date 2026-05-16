"""Simple policy loading for ContextDuty."""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .core.exceptions import PolicyCycleError, PolicyValidationError
from .detectors import DETECTORS

VALID_MODES = {"redact", "warn", "block"}


@dataclass(frozen=True)
class Policy:
    mode: str
    detectors: set[str]
    custom_detectors: dict[str, str]
    # Per-detector mode overrides. Detectors not listed here fall back to `mode`.
    # Example: {"api_key": "block", "phone": "warn"} while global mode is "redact".
    detector_modes: dict[str, str] = field(default_factory=dict)
    # Per-detector allowlist patterns. Values matching any pattern are skipped.
    # Example: {"email": ["noreply@.*", "alerts@corp\\.com"]}
    allow_patterns: dict[str, list[str]] = field(default_factory=dict)


DEFAULT_POLICY: dict[str, Any] = {
    "mode": "redact",
    "detectors": [
        # PII
        "email",
        "phone",
        # Generic tokens
        "api_key",
        "bearer_token",
        # Cloud provider keys
        "aws_key",
        "aws_secret",
        "gcp_service_account",
        # VCS platform tokens
        "github_pat",
        # AI / ML service keys
        "openai_key",
        "anthropic_key",
        "huggingface_token",
        # Communication platforms
        "slack_token",
        # Payment / SaaS platforms
        "stripe_webhook",
        "sendgrid_key",
        "mailchimp_key",
        # Package registries
        "npm_token",
        # Telephony
        "twilio_sid",
        # Azure
        "azure_storage_key",
        # Google OAuth
        "google_oauth_token",
        # Database connection strings
        "db_dsn",
        # Cryptographic material
        "ssh_private_key",
        "pgp_private_key",
        "private_key_pem",
        # JWTs
        "jwt",
        # .env / config file secrets
        "env_secret",
    ],
    "custom_detectors": {},
    "detector_modes": {},
    "allow_patterns": {},
}


def write_default_policy(path: Path) -> None:
    out = {k: v for k, v in DEFAULT_POLICY.items() if k not in {"detector_modes", "allow_patterns"}}
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")


def _read_policy_config(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PolicyValidationError(f"policy file must contain a JSON object: {path}", field="root")
    return raw


def _normalize_extends(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise PolicyValidationError("policy extends must be a string or list of strings", field="extends")


def _merge_policy_configs(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)

    base_detectors = base.get("detectors", [])
    override_detectors = override.get("detectors", [])
    if not isinstance(base_detectors, list) or not all(
        isinstance(name, str) for name in base_detectors
    ):
        raise PolicyValidationError("policy detectors must be a list of strings")
    if not isinstance(override_detectors, list) or not all(
        isinstance(name, str) for name in override_detectors
    ):
        raise PolicyValidationError("policy detectors must be a list of strings")
    merged["detectors"] = list(dict.fromkeys(base_detectors + override_detectors))

    base_custom = base.get("custom_detectors", {})
    override_custom = override.get("custom_detectors", {})
    if not isinstance(base_custom, dict) or not isinstance(override_custom, dict):
        raise PolicyValidationError("policy custom_detectors must be an object of {name: regex}")
    merged["custom_detectors"] = {**base_custom, **override_custom}

    if "mode" in override:
        merged["mode"] = override["mode"]

    # detector_modes: child overrides parent key-by-key
    base_dm = base.get("detector_modes", {})
    override_dm = override.get("detector_modes", {})
    if not isinstance(base_dm, dict) or not isinstance(override_dm, dict):
        raise PolicyValidationError("policy detector_modes must be an object of {detector: mode}")
    merged["detector_modes"] = {**base_dm, **override_dm}

    # allow_patterns: lists are merged (union) per detector key
    base_ap = base.get("allow_patterns", {})
    override_ap = override.get("allow_patterns", {})
    if not isinstance(base_ap, dict) or not isinstance(override_ap, dict):
        raise PolicyValidationError("policy allow_patterns must be an object of {detector: [pattern, ...]}")
    merged_ap: dict[str, list[str]] = dict(base_ap)
    for key, patterns in override_ap.items():
        existing = merged_ap.get(key, [])
        merged_ap[key] = list(dict.fromkeys(existing + patterns))
    merged["allow_patterns"] = merged_ap

    return merged


def _resolve_policy_config(path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    seen = seen or set()
    resolved_path = path.resolve()
    if resolved_path in seen:
        raise PolicyCycleError([str(p) for p in seen] + [str(resolved_path)])
    seen.add(resolved_path)

    config = _read_policy_config(resolved_path)
    parent_refs = _normalize_extends(config.get("extends"))

    merged: dict[str, Any] = {
        "mode": DEFAULT_POLICY["mode"],
        "detectors": list(DEFAULT_POLICY["detectors"]),
        "custom_detectors": dict(DEFAULT_POLICY["custom_detectors"]),
        "detector_modes": {},
        "allow_patterns": {},
    }

    for parent_ref in parent_refs:
        if _is_url(parent_ref):
            parent_config = _resolve_policy_config_with_urls(
                parent_ref, resolved_path.parent, seen, set()
            )
        else:
            parent_path = (resolved_path.parent / parent_ref).resolve()
            parent_config = _resolve_policy_config(parent_path, seen)
        merged = _merge_policy_configs(merged, parent_config)

    local_config = dict(config)
    local_config.pop("extends", None)
    merged = _merge_policy_configs(merged, local_config)

    seen.remove(resolved_path)
    return merged


def _validate_detector_modes(detector_modes: dict[str, Any]) -> dict[str, str]:
    validated: dict[str, str] = {}
    for name, mode in detector_modes.items():
        if not isinstance(name, str) or not name.strip():
            raise PolicyValidationError("detector_modes keys must be non-empty strings")
        if not isinstance(mode, str) or mode not in VALID_MODES:
            raise PolicyValidationError(
                f"detector_modes['{name}'] must be one of: {', '.join(sorted(VALID_MODES))}"
            )
        validated[name] = mode
    return validated


def _validate_allow_patterns(allow_patterns: dict[str, Any]) -> dict[str, list[str]]:
    validated: dict[str, list[str]] = {}
    for detector_name, patterns in allow_patterns.items():
        if not isinstance(detector_name, str) or not detector_name.strip():
            raise PolicyValidationError("allow_patterns keys must be non-empty strings")
        if not isinstance(patterns, list):
            raise PolicyValidationError(f"allow_patterns['{detector_name}'] must be a list of regex strings")
        compiled: list[str] = []
        for i, pattern in enumerate(patterns):
            if not isinstance(pattern, str) or not pattern.strip():
                raise PolicyValidationError(
                    f"allow_patterns['{detector_name}'][{i}] must be a non-empty regex string"
                )
            try:
                re.compile(pattern)
            except re.error as exc:
                raise PolicyValidationError(
                    f"invalid regex in allow_patterns['{detector_name}'][{i}]: {exc}"
                ) from exc
            compiled.append(pattern)
        validated[detector_name] = compiled
    return validated


def load_policy(path: Path | None) -> Policy:
    if path is None:
        config = DEFAULT_POLICY
    else:
        config = _resolve_policy_config(path)

    mode = str(config.get("mode", "redact")).lower()
    if mode not in VALID_MODES:
        raise PolicyValidationError("policy mode must be one of: redact, warn, block")

    detectors_raw = config.get("detectors", DEFAULT_POLICY["detectors"])
    if not isinstance(detectors_raw, list) or not all(
        isinstance(name, str) for name in detectors_raw
    ):
        raise PolicyValidationError("policy detectors must be a list of strings")

    custom_raw = config.get("custom_detectors", {})
    if not isinstance(custom_raw, dict):
        raise PolicyValidationError("policy custom_detectors must be an object of {name: regex}")

    built_in_names = {detector.name for detector in DETECTORS}
    custom_detectors: dict[str, str] = {}
    for name, pattern in custom_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise PolicyValidationError("custom detector names must be non-empty strings")
        if name in built_in_names:
            raise PolicyValidationError(f"custom detector name '{name}' conflicts with built-in detector")
        if not isinstance(pattern, str) or not pattern.strip():
            raise PolicyValidationError(f"custom detector '{name}' must have a non-empty regex string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PolicyValidationError(f"invalid regex for custom detector '{name}': {exc}") from exc
        custom_detectors[name] = pattern

    detectors = set(detectors_raw) | set(custom_detectors.keys())

    detector_modes_raw = config.get("detector_modes", {})
    if not isinstance(detector_modes_raw, dict):
        raise PolicyValidationError("policy detector_modes must be an object of {detector: mode}")
    detector_modes = _validate_detector_modes(detector_modes_raw)

    allow_patterns_raw = config.get("allow_patterns", {})
    if not isinstance(allow_patterns_raw, dict):
        raise PolicyValidationError("policy allow_patterns must be an object of {detector: [pattern, ...]}")
    allow_patterns = _validate_allow_patterns(allow_patterns_raw)

    return Policy(
        mode=mode,
        detectors=detectors,
        custom_detectors=custom_detectors,
        detector_modes=detector_modes,
        allow_patterns=allow_patterns,
    )


def unknown_detector_names(policy: Policy) -> list[str]:
    built_in_names = {detector.name for detector in DETECTORS}
    allowed = built_in_names | set(policy.custom_detectors.keys())
    return sorted(name for name in policy.detectors if name not in allowed)


# ---------------------------------------------------------------------------
# URL-based policy fetching
# ---------------------------------------------------------------------------


def _is_url(ref: str) -> bool:
    parsed = urlparse(ref)
    return parsed.scheme in ("http", "https")


def _fetch_url_policy(url: str, timeout: int = 10) -> dict[str, Any]:
    """Fetch a policy JSON from a URL (HTTPS only in production).

    This enables centralized policy distribution — a security team hosts
    one canonical URL and all developer machines extend it:

        { "extends": "https://policy.corp.com/soc2-baseline.json" }

    The fetch uses stdlib urllib — no third-party dependencies.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise PolicyValidationError(f"policy URL must use http or https scheme: {url}")

    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"contextduty/{_get_version()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
    except Exception as exc:
        raise PolicyValidationError(f"failed to fetch policy from {url}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyValidationError(f"policy at {url} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise PolicyValidationError(f"policy at {url} must contain a JSON object")
    return data


def _get_version() -> str:
    try:
        from . import __version__

        return __version__
    except Exception:
        return "0.0.0"


def _resolve_policy_config_with_urls(
    ref: str,
    base_path: Path,
    seen_files: set[Path],
    seen_urls: set[str],
) -> dict[str, Any]:
    """Resolve a policy ref that may be either a file path or a URL."""
    if _is_url(ref):
        if ref in seen_urls:
            raise PolicyValidationError(f"policy extends cycle detected at URL: {ref}")
        seen_urls.add(ref)
        config = _fetch_url_policy(ref)
        parent_refs = _normalize_extends(config.get("extends"))
        merged: dict[str, Any] = {
            "mode": DEFAULT_POLICY["mode"],
            "detectors": list(DEFAULT_POLICY["detectors"]),
            "custom_detectors": dict(DEFAULT_POLICY["custom_detectors"]),
            "detector_modes": {},
            "allow_patterns": {},
        }
        for parent_ref in parent_refs:
            parent_config = _resolve_policy_config_with_urls(
                parent_ref, base_path, seen_files, seen_urls
            )
            merged = _merge_policy_configs(merged, parent_config)
        local_config = dict(config)
        local_config.pop("extends", None)
        merged = _merge_policy_configs(merged, local_config)
        seen_urls.discard(ref)
        return merged
    else:
        # Relative file path — resolve relative to base_path
        parent_path = (base_path / ref).resolve()
        return _resolve_policy_config(parent_path, seen_files)
