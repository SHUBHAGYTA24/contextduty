"""Core NER scanning orchestration.

Ties together model loading, text extraction, and confidence scoring
into two high-level entry points:

* :func:`scan_text_nlp` — scan a string (source code, config, markdown).
* :func:`scan_file_nlp` — scan a file on disk, auto-detecting format.

Backend selection (automatic):
    1. **Presidio** — preferred when installed (50+ recognizers, hybrid regex+NLP).
    2. **spaCy** — fallback when only spaCy is available.

Both backends run 100% locally. Install with::

    pip install contextduty[presidio]   # recommended
    pip install contextduty[nlp]        # spaCy-only fallback
"""

from __future__ import annotations

from pathlib import Path

from ._extract import extract_notebook_text, extract_text_segments
from ._presidio import is_available as _presidio_available
from ._types import NLPFinding, NLPScanResult

# spaCy pipeline components we don't need for NER-only scanning.
_DISABLED_COMPONENTS = ["tok2vec", "tagger", "parser", "attribute_ruler", "lemmatizer"]

_BACKEND: str | None = None


def get_backend() -> str:
    """Return the active NLP backend name: 'presidio' or 'spacy'."""
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    _BACKEND = "presidio" if _presidio_available() else "spacy"
    return _BACKEND


def set_backend(name: str) -> None:
    """Force a specific backend ('presidio' or 'spacy')."""
    global _BACKEND
    if name not in ("presidio", "spacy"):
        raise ValueError(f"Unknown NLP backend: {name!r}. Use 'presidio' or 'spacy'.")
    _BACKEND = name


def reset_backend() -> None:
    """Reset backend to auto-detect (useful in tests)."""
    global _BACKEND
    _BACKEND = None


def scan_text_nlp(
    text: str,
    *,
    model_name: str = "en_core_web_sm",
    min_confidence: float = 0.5,
    extract_segments: bool = True,
    backend: str | None = None,
) -> NLPScanResult:
    """Scan text for PII using the best available NLP backend.

    Args:
        text: Source code, config, markdown, or plain text.
        model_name: spaCy model to use (ignored when backend is presidio).
        min_confidence: Minimum threshold to include a finding (0.0-1.0).
        extract_segments: When True, pull strings/comments from code first.
        backend: Force a specific backend ('presidio' or 'spacy').

    Returns:
        NLPScanResult with findings, counts, and suppression stats.
    """
    active_backend = backend or get_backend()

    segments = extract_text_segments(text) if extract_segments else [(text, "raw")]
    if not segments:
        return NLPScanResult()

    active = [(seg_text, seg_type) for seg_text, seg_type in segments if seg_text.strip()]
    if not active:
        return NLPScanResult(segments_scanned=len(segments))

    if active_backend == "presidio":
        from ._presidio import analyze_segments

        return analyze_segments(active, min_confidence=min_confidence)

    return _scan_spacy(active, segments, model_name, min_confidence)


def scan_file_nlp(
    file_path: str,
    *,
    model_name: str = "en_core_web_sm",
    min_confidence: float = 0.5,
    backend: str | None = None,
) -> NLPScanResult:
    """Scan a file for PII using NLP.

    Dispatches to the correct extraction strategy based on file suffix:
    * .ipynb -> notebook cell extraction
    * .md / .txt / .rst -> raw prose (no segment extraction)
    * everything else -> source-code segment extraction
    """
    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return NLPScanResult()

    suffix = path.suffix.lower()

    if suffix == ".ipynb":
        return _scan_notebook(content, model_name, min_confidence, backend)

    return scan_text_nlp(
        content,
        model_name=model_name,
        min_confidence=min_confidence,
        extract_segments=suffix not in (".md", ".txt", ".rst"),
        backend=backend,
    )


# ---------------------------------------------------------------------------
# spaCy backend (fallback)
# ---------------------------------------------------------------------------


def _scan_spacy(
    active: list[tuple[str, str]],
    all_segments: list[tuple[str, str]],
    model_name: str,
    min_confidence: float,
) -> NLPScanResult:
    """Run NER using the spaCy backend."""
    from ._model import get_model
    from ._scoring import PII_ENTITY_LABELS, compute_confidence

    nlp = get_model(model_name)
    result = NLPScanResult(segments_scanned=len(all_segments))

    disable = [c for c in _DISABLED_COMPONENTS if c in nlp.pipe_names]

    if len(active) == 1:
        seg_text, seg_type = active[0]
        doc = nlp(seg_text, disable=disable)
        _collect_entities(doc, seg_text, seg_type, min_confidence, result)
    else:
        texts = [seg_text for seg_text, _ in active]
        docs = nlp.pipe(texts, disable=disable, batch_size=32)
        for doc, (seg_text, seg_type) in zip(docs, active):
            _collect_entities(doc, seg_text, seg_type, min_confidence, result)

    return result


def _collect_entities(
    doc,
    seg_text: str,
    seg_type: str,
    min_confidence: float,
    result: NLPScanResult,
) -> None:
    """Extract qualifying PII entities from a processed spaCy Doc."""
    from ._scoring import PII_ENTITY_LABELS, compute_confidence

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
    backend: str | None = None,
) -> NLPScanResult:
    """Scan a Jupyter notebook."""
    segments = extract_notebook_text(content)
    if not segments:
        return NLPScanResult()

    active_backend = backend or get_backend()
    active = [(t, ty) for t, ty in segments if t.strip()]
    if not active:
        return NLPScanResult(segments_scanned=len(segments))

    if active_backend == "presidio":
        from ._presidio import analyze_segments

        result = analyze_segments(active, min_confidence=min_confidence)
        result.segments_scanned = len(segments)
        return result

    from ._model import get_model

    result = NLPScanResult(segments_scanned=len(segments))
    nlp = get_model(model_name)
    disable = [c for c in _DISABLED_COMPONENTS if c in nlp.pipe_names]

    texts = [t for t, _ in active]
    docs = nlp.pipe(texts, disable=disable, batch_size=32)
    for doc, (seg_text, seg_type) in zip(docs, active):
        _collect_entities(doc, seg_text, seg_type, min_confidence, result)

    return result
