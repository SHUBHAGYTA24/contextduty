"""Backward-compatible shim — canonical implementation at proxy/feed.py."""

from .proxy.feed import (  # noqa: F401
    InterceptionEvent,
    LiveFeed,
    get_feed,
    record_interception,
)
