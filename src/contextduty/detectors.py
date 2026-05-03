"""Built-in detectors for secrets and PII."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: re.Pattern[str]


DETECTORS: list[Detector] = [
    Detector("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector(
        "phone", re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?){2,4}\d{2,4}\b")
    ),
    Detector("api_key", re.compile(r"\b(?:sk|rk|pk)_[A-Za-z0-9_]{16,}\b")),
    Detector("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Detector("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", re.IGNORECASE)),
]


def stable_mask(detector_name: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"<{detector_name.upper()}_{digest}>"
