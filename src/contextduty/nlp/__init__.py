"""
contextduty.nlp
~~~~~~~~~~~~~~~
NLP-based PII detection using spaCy NER with context-aware scoring.

Architecture
------------
1. **Extract** — pull natural-language segments from code
   (strings, comments, docstrings, notebook cells).
2. **Detect** — run spaCy NER on each segment.
3. **Score** — apply context-aware boost/suppress rules.
4. **Return** — findings compatible with the existing scan pipeline.

Quick start::

    pip install contextduty[nlp]
    python -m spacy download en_core_web_sm

Enterprise fine-tuning::

    from contextduty.nlp import load_model
    load_model("/path/to/custom-model")

Submodules
----------
_model     Model loading and lifecycle
_extract   Text segment extraction
_scoring   Context-aware confidence scoring
_scanner   Core NER scanning orchestration
_types     Data classes (NLPFinding, NLPScanResult)
"""

from ._extract import extract_notebook_text, extract_text_segments
from ._model import load_model, reset_model
from ._scanner import scan_file_nlp, scan_text_nlp
from ._types import NLPFinding, NLPScanResult

__all__ = [
    "extract_notebook_text",
    "extract_text_segments",
    "load_model",
    "reset_model",
    "scan_file_nlp",
    "scan_text_nlp",
    "NLPFinding",
    "NLPScanResult",
]
