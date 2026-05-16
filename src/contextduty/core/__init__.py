"""Core domain logic — scanning, detection, redaction, policy.

This package contains ZERO I/O dependencies. It operates on strings and
dataclasses only. All file I/O, network I/O, and terminal output live
in the adapters/ and cli/ layers.

Public API:
    from contextduty.core import scan_text, scan_file, scan_dir
    from contextduty.core import ScanResult, Finding
    from contextduty.core import Policy, load_policy
    from contextduty.core import ContextDutyError
"""

from .exceptions import (
    CertificateError,
    ContextDutyError,
    FileAccessError,
    PolicyCycleError,
    PolicyError,
    PolicyValidationError,
    ProxyAlreadyRunningError,
    ProxyError,
    ProxyNotInstalledError,
    ScanError,
)


def __getattr__(name: str):  # noqa: C901
    """Lazy imports to avoid circular dependency with engine/policy."""
    _engine_names = {
        "Finding", "ScanResult", "redact_file",
        "report_to_json", "scan_dir", "scan_file",
    }
    _policy_names = {"Policy", "load_policy"}

    if name in _engine_names:
        import importlib
        mod = importlib.import_module("contextduty.engine")
        return getattr(mod, name)
    if name in _policy_names:
        import importlib
        mod = importlib.import_module("contextduty.policy")
        return getattr(mod, name)
    raise AttributeError(f"module 'contextduty.core' has no attribute {name!r}")


__all__ = [
    "CertificateError",
    "ContextDutyError",
    "FileAccessError",
    "Finding",
    "Policy",
    "PolicyCycleError",
    "PolicyError",
    "PolicyValidationError",
    "ProxyAlreadyRunningError",
    "ProxyError",
    "ProxyNotInstalledError",
    "ScanError",
    "load_policy",
    "redact_file",
    "report_to_json",
    "scan_dir",
    "scan_file",
]
