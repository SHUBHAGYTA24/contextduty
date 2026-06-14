"""
contextduty.nlp
~~~~~~~~~~~~~~~
NLP-based PII detection with automatic backend selection.

Backends (auto-detected, best-first):
    1. **Presidio** — 50+ built-in recognizers, hybrid regex+NLP (recommended).
    2. **spaCy** — raw NER with context-aware confidence scoring (fallback).

Both run 100% locally — no data leaves the machine.

Quick start::

    pip install contextduty[presidio]   # recommended
    pip install contextduty[nlp]        # spaCy-only fallback

Enterprise fine-tuning::

    from contextduty.nlp import load_model
    load_model("/path/to/custom-model")

Submodules
----------
_presidio  Presidio analyzer backend
_model     spaCy model loading and lifecycle
_extract   Text segment extraction
_scoring   Context-aware confidence scoring (spaCy backend)
_scanner   Core scanning orchestration + backend selection
_types     Data classes (NLPFinding, NLPScanResult)
"""

from ._extract import extract_notebook_text, extract_text_segments
from ._model import load_model, reset_model
from ._scanner import get_backend, reset_backend, scan_file_nlp, scan_text_nlp, set_backend
from ._types import NLPFinding, NLPScanResult

__all__ = [
    "extract_notebook_text",
    "extract_text_segments",
    "get_backend",
    "load_model",
    "reset_backend",
    "reset_model",
    "scan_file_nlp",
    "scan_text_nlp",
    "set_backend",
    "NLPFinding",
    "NLPScanResult",
]
