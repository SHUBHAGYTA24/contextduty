"""Local HTTPS proxy — intercepts AI API traffic and redacts secrets.

Package structure:
    scope.py        — AI API host registry + prompt path detection
    ca.py           — CA certificate generation and system trust installation
    system.py       — macOS/Linux/Windows proxy configuration
    server.py       — Proxy lifecycle: setup, start, stop, status, daemon
    interceptor.py  — Declarative JSON field walker for arbitrary AI request bodies
    addon.py        — mitmproxy addon (the request handler)
    feed.py         — Live terminal feed of interception events
"""

from .server import proxy_setup, proxy_start, proxy_status, proxy_stop

__all__ = ["proxy_setup", "proxy_start", "proxy_status", "proxy_stop"]
