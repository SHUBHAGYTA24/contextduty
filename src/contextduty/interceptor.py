"""Backward-compatible shim — canonical implementation at proxy/interceptor.py."""

from .proxy.interceptor import (  # noqa: F401
    PROVIDER_FIELDS,
    _get_fields_for_host,
    extract_texts,
    redact_body,
)
