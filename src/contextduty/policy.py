"""Simple policy loading for ContextDuty."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detectors import DETECTORS


@dataclass(frozen=True)
class Policy:
    mode: str
    detectors: set[str]
    custom_detectors: dict[str, str]


DEFAULT_POLICY = {
    "mode": "redact",
    "detectors": ["email", "phone", "api_key", "aws_key", "bearer_token"],
    "custom_detectors": {},
}


def write_default_policy(path: Path) -> None:
    path.write_text(json.dumps(DEFAULT_POLICY, indent=2) + "\n", encoding="utf-8")


def _read_policy_config(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"policy file must contain a JSON object: {path}")
    return raw


def _normalize_extends(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise ValueError("policy extends must be a string or list of strings")


def _merge_policy_configs(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = dict(base)

    base_detectors = base.get("detectors", [])
    override_detectors = override.get("detectors", [])
    if not isinstance(base_detectors, list) or not all(
        isinstance(name, str) for name in base_detectors
    ):
        raise ValueError("policy detectors must be a list of strings")
    if not isinstance(override_detectors, list) or not all(
        isinstance(name, str) for name in override_detectors
    ):
        raise ValueError("policy detectors must be a list of strings")
    merged["detectors"] = list(dict.fromkeys(base_detectors + override_detectors))

    base_custom = base.get("custom_detectors", {})
    override_custom = override.get("custom_detectors", {})
    if not isinstance(base_custom, dict) or not isinstance(override_custom, dict):
        raise ValueError("policy custom_detectors must be an object of {name: regex}")
    merged["custom_detectors"] = {**base_custom, **override_custom}

    if "mode" in override:
        merged["mode"] = override["mode"]

    return merged


def _resolve_policy_config(path: Path, seen: set[Path] | None = None) -> dict[str, Any]:
    seen = seen or set()
    resolved_path = path.resolve()
    if resolved_path in seen:
        raise ValueError(f"policy extends cycle detected at: {resolved_path}")
    seen.add(resolved_path)

    config = _read_policy_config(resolved_path)
    parent_refs = _normalize_extends(config.get("extends"))

    merged: dict[str, Any] = {
        "mode": DEFAULT_POLICY["mode"],
        "detectors": list(DEFAULT_POLICY["detectors"]),
        "custom_detectors": dict(DEFAULT_POLICY["custom_detectors"]),
    }

    for parent_ref in parent_refs:
        parent_path = (resolved_path.parent / parent_ref).resolve()
        parent_config = _resolve_policy_config(parent_path, seen)
        merged = _merge_policy_configs(merged, parent_config)

    local_config = dict(config)
    local_config.pop("extends", None)
    merged = _merge_policy_configs(merged, local_config)

    seen.remove(resolved_path)
    return merged


def load_policy(path: Path | None) -> Policy:
    if path is None:
        config = DEFAULT_POLICY
    else:
        config = _resolve_policy_config(path)
    mode = str(config.get("mode", "redact")).lower()
    if mode not in {"redact", "warn", "block"}:
        raise ValueError("policy mode must be one of: redact, warn, block")
    detectors_raw = config.get("detectors", DEFAULT_POLICY["detectors"])
    if not isinstance(detectors_raw, list) or not all(
        isinstance(name, str) for name in detectors_raw
    ):
        raise ValueError("policy detectors must be a list of strings")

    custom_raw = config.get("custom_detectors", {})
    if not isinstance(custom_raw, dict):
        raise ValueError("policy custom_detectors must be an object of {name: regex}")

    built_in_names = {detector.name for detector in DETECTORS}
    custom_detectors: dict[str, str] = {}
    for name, pattern in custom_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise ValueError("custom detector names must be non-empty strings")
        if name in built_in_names:
            raise ValueError(f"custom detector name '{name}' conflicts with built-in detector")
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError(f"custom detector '{name}' must have a non-empty regex string")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex for custom detector '{name}': {exc}") from exc
        custom_detectors[name] = pattern

    # Automatically activate custom detectors so users only need to define regex once.
    detectors = set(detectors_raw) | set(custom_detectors.keys())
    return Policy(mode=mode, detectors=detectors, custom_detectors=custom_detectors)


def unknown_detector_names(policy: Policy) -> list[str]:
    built_in_names = {detector.name for detector in DETECTORS}
    allowed = built_in_names | set(policy.custom_detectors.keys())
    return sorted(name for name in policy.detectors if name not in allowed)
