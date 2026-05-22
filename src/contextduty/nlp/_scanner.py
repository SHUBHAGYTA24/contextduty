"""Core NER scanning orchestration.

Ties together model loading, text extraction, and confidence scoring
into two high-level entry points:

* :func:`scan_text_nlp` — scan a string (source code, config, markdown).
* :func:`scan_file_nlp` — scan a file on disk, auto-detecting format.

Performance notes:
    - Uses ``nlp.pipe()`` for batch processing when multiple segments exist,
      which is significantly faster than calling ``nlp()`` per segment.
    - Only NER component is run (``nlp.pipe(..., disable=[...])``),
      skipping unnecessary pipeline stages.
"""

from __future__ import annotations

from pathlib import Path

from ._extract import extract_notebook_text, extract_text_segments
from ._model import get_model
from ._scoring import PII_ENTITY_LABELS, compute_confidence
from ._types import NLPFinding, NLPScanResult

# spaCy pipeline components we don't need for NER-only scanning.
_DISABLED_COMPONENTS = ["tok2vec", "tagger", "parser", "attribute_ruler", "lemmatizer"]


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

    # Filter empty segments before sending to the model.
    active = [(seg_text, seg_type) for seg_text, seg_type in segments if seg_text.strip()]
    if not active:
        result.segments_scanned = len(segments)
        return result

    result.segments_scanned = len(segments)

    # Determine which pipeline components can be disabled for speed.
    # Only disable components that actually exist in this model.
    disable = [c for c in _DISABLED_COMPONENTS if c in nlp.pipe_names]

    if len(active) == 1:
        # Single segment — direct call is cheaper than pipe() overhead.
        seg_text, seg_type = active[0]
        doc = nlp(seg_text, disable=disable)
        _collect_entities(doc, seg_text, seg_type, min_confidence, result)
    else:
        # Batch processing — nlp.pipe() is ~2-3x faster for multiple segments.
        texts = [seg_text for seg_text, _ in active]
        docs = nlp.pipe(texts, disable=disable, batch_size=32)
        for doc, (seg_text, seg_type) in zip(docs, active):
            _collect_entities(doc, seg_text, seg_type, min_confidence, result)

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


def _collect_entities(
    doc,
    seg_text: str,
    seg_type: str,
    min_confidence: float,
    result: NLPScanResult,
) -> None:
    """Extract qualifying PII entities from a processed spaCy Doc."""
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
    """Scan a Jupyter notebook — extracts all segments, then batch-processes."""
    segments = extract_notebook_text(content)
    if not segments:
        return NLPScanResult()

    # Process all notebook segments in a single scan_text_nlp call
    # by concatenating with segment boundaries preserved.
    result = NLPScanResult(segments_scanned=len(segments))
    nlp = get_model(model_name)
    disable = [c for c in _DISABLED_COMPONENTS if c in nlp.pipe_names]

    active = [(t, ty) for t, ty in segments if t.strip()]
    if not active:
        return result

    texts = [t for t, _ in active]
    docs = nlp.pipe(texts, disable=disable, batch_size=32)
    for doc, (seg_text, seg_type) in zip(docs, active):
        _collect_entities(doc, seg_text, seg_type, min_confidence, result)

    return result
