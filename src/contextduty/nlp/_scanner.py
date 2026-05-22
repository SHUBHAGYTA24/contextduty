"""Core NER scanning orchestration.

Ties together model loading, text extraction, and confidence scoring
into two high-level entry points:

* :func:`scan_text_nlp` — scan a string (source code, config, markdown).
* :func:`scan_file_nlp` — scan a file on disk, auto-detecting format.
"""

from __future__ import annotations

from pathlib import Path

from ._extract import extract_notebook_text, extract_text_segments
from ._model import get_model
from ._scoring import PII_ENTITY_LABELS, compute_confidence
from ._types import NLPFinding, NLPScanResult


def scan_text_nlp(
    text: str,
    *,
    model_name: str = "en_core_web_sm",
    min_confidence: float = 0.5,
    extract_segments: bool = True,
) -> NLPScanResult:
    """Scan text for PII using spaCy NER with context-aware scoring.

    Args:
        text: Source code, config, markdown, or plain text.
        model_name: spaCy model to use.
        min_confidence: Minimum threshold to include a finding (0.0–1.0).
        extract_segments: When ``True``, pull strings/comments from code
            first.  Set to ``False`` for already-extracted prose.

    Returns:
        :class:`NLPScanResult` with findings, counts, and suppression stats.
    """
    nlp = get_model(model_name)
    result = NLPScanResult()

    segments = extract_text_segments(text) if extract_segments else [(text, "raw")]
    if not segments:
        return result

    result.segments_scanned = len(segments)

    for seg_text, seg_type in segments:
        if not seg_text.strip():
            continue
        _scan_segment(nlp, seg_text, seg_type, min_confidence, result)

    return result


def scan_file_nlp(
    file_path: str,
    *,
    model_name: str = "en_core_web_sm",
    min_confidence: float = 0.5,
) -> NLPScanResult:
    """Scan a file for PII using NLP.

    Dispatches to the correct extraction strategy based on file suffix:

    * ``.ipynb`` → notebook cell extraction
    * ``.md / .txt / .rst`` → raw prose (no segment extraction)
    * everything else → source-code segment extraction
    """
    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return NLPScanResult()

    suffix = path.suffix.lower()

    if suffix == ".ipynb":
        return _scan_notebook(content, model_name, min_confidence)

    return scan_text_nlp(
        content,
        model_name=model_name,
        min_confidence=min_confidence,
        extract_segments=suffix not in (".md", ".txt", ".rst"),
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _scan_segment(
    nlp,
    seg_text: str,
    seg_type: str,
    min_confidence: float,
    result: NLPScanResult,
) -> None:
    """Run NER on a single segment and append qualifying findings to *result*."""
    doc = nlp(seg_text)

    for ent in doc.ents:
        if ent.label_ not in PII_ENTITY_LABELS:
            continue

        result.entities_found += 1

        confidence = compute_confidence(
            entity_text=ent.text,
            entity_label=ent.label_,
            segment_text=seg_text,
            segment_type=seg_type,
        )

        if confidence < min_confidence:
            result.entities_suppressed += 1
            continue

        ctx_start = max(0, ent.start_char - 50)
        ctx_end = min(len(seg_text), ent.end_char + 50)

        result.findings.append(
            NLPFinding(
                entity_text=ent.text,
                entity_label=ent.label_,
                detector_name=f"nlp_{ent.label_.lower()}",
                confidence=confidence,
                context=seg_text[ctx_start:ctx_end],
                start=ent.start_char,
                end=ent.end_char,
            )
        )


def _scan_notebook(
    content: str,
    model_name: str,
    min_confidence: float,
) -> NLPScanResult:
    """Scan a Jupyter notebook by iterating over extracted segments."""
    segments = extract_notebook_text(content)
    if not segments:
        return NLPScanResult()

    result = NLPScanResult(segments_scanned=len(segments))

    for seg_text, seg_type in segments:
        sub = scan_text_nlp(
            seg_text,
            model_name=model_name,
            min_confidence=min_confidence,
            extract_segments=False,
        )
        result.findings.extend(sub.findings)
        result.entities_found += sub.entities_found
        result.entities_suppressed += sub.entities_suppressed

    return result
