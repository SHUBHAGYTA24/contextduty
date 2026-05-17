"""ContextDuty — policy-driven context firewall for AI workflows."""

try:
    from importlib.metadata import PackageNotFoundError, version

    __version__ = version("contextduty")
except PackageNotFoundError:
    __version__ = "0.2.2"  # fallback for editable installs
