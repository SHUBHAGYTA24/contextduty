"""Typed exception hierarchy for ContextDuty."""


class ContextDutyError(Exception):
    """Base class for all ContextDuty errors."""


class PolicyError(ContextDutyError):
    """Policy file is missing or unreadable."""


class PolicyValidationError(PolicyError):
    """Policy file fails schema validation."""


class PolicyCycleError(PolicyError):
    """Policy inheritance cycle detected."""


class ScanError(ContextDutyError):
    """Error during scanning or redaction."""


class FileAccessError(ContextDutyError):
    """File could not be opened or read."""


class ProxyError(ContextDutyError):
    """Base proxy error."""


class ProxyAlreadyRunningError(ProxyError):
    """Proxy is already running."""


class ProxyNotInstalledError(ProxyError):
    """mitmproxy is not installed."""


class CertificateError(ProxyError):
    """CA certificate error."""
