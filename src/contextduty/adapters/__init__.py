"""Adapters — integration points with external systems.

Each adapter wraps the core scanning/redaction engine for a specific
integration surface:

    git     — Pre-commit hooks
    mcp     — Model Context Protocol server
    ide     — IDE ignore file generation (.cursorignore, .copilotignore, etc.)
    audit   — Structured audit logging + reports + dashboard

The proxy adapter lives in its own top-level package (contextduty.proxy)
due to its size and independent deployment model.
"""
