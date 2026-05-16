"""Exception hierarchy for ContextDuty.

All custom exceptions inherit from ContextDutyError. Callers can catch
the base class to handle any ContextDuty-specific error, or catch
specific subclasses for finer control.
"""

from __future__ import annotations


class ContextDutyError(Exception):
    """Base exception for all ContextDuty errors."""


class PolicyError(ContextDutyError, ValueError):
    """Raised when a policy file is invalid or cannot be loaded."""


class PolicyValidationError(PolicyError):
    """Raised when policy content fails validation."""

    def __init__(self, message: str, field: str | None = None):
        self.field = field
        super().__init__(message)


class PolicyCycleError(PolicyError):
    """Raised when policy inheritance creates a cycle."""

    def __init__(self, chain: list[str]):
        self.chain = chain
        super().__init__(f"Policy inheritance cycle: {' → '.join(chain)}")


class ScanError(ContextDutyError):
    """Raised when a scan operation fails."""


class FileAccessError(ScanError):
    """Raised when a target file cannot be read."""

    def __init__(self, path: str, reason: str):
        self.path = path
        super().__init__(f"Cannot read {path}: {reason}")


class ProxyError(ContextDutyError):
    """Raised when proxy operations fail."""


class ProxyNotInstalledError(ProxyError):
    """Raised when mitmproxy is not available."""

    def __init__(self):
        super().__init__(
            "mitmproxy not found. Install it: pip install 'contextduty[proxy]'"
        )


class ProxyAlreadyRunningError(ProxyError):
    """Raised when attempting to start a proxy that's already running."""

    def __init__(self, pid: int):
        self.pid = pid
        super().__init__(f"Proxy already running (PID {pid})")


class CertificateError(ProxyError):
    """Raised when CA certificate operations fail."""
