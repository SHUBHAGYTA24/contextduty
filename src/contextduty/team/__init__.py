"""Team layer — metadata-only fleet visibility (the paid tier).

Everything here transmits metadata only (counts, hashes, detector names) and
never matched content — see model.sanitize_event.
"""

from .aggregate import aggregate_fleet
from .collector import serve
from .model import is_content_free, sanitize_event
from .report import report_bypass, report_scan

__all__ = [
    "serve",
    "aggregate_fleet",
    "sanitize_event",
    "is_content_free",
    "report_scan",
    "report_bypass",
]
