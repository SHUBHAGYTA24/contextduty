"""Presidio-backed PII detection engine.

Uses Microsoft Presidio's AnalyzerEngine for entity recognition,
mapping results into ContextDuty's NLPFinding format. Runs 100% local
— no data leaves the machine.

When available, Presidio is preferred over raw spaCy NER because it
provides 50+ built-in recognizers (regex + NLP hybrid), handles
multiple languages, and is battle-tested in enterprise deployments.
"""

from __future__ import annotations

from typing import Any

from ._types import NLPFinding, NLPScanResult

_analyzer: Any | None = None

PRESIDIO_TO_DETECTOR: dict[str, str] = {
    "PERSON": "nlp_person",
    "EMAIL_ADDRESS": "nlp_email",
    "PHONE_NUMBER": "nlp_phone",
    "CREDIT_CARD": "nlp_credit_card",
    "CRYPTO": "nlp_crypto_address",
    "IP_ADDRESS": "nlp_ip_address",
    "IBAN_CODE": "nlp_iban",
    "US_SSN": "nlp_ssn",
    "US_DRIVER_LICENSE": "nlp_driver_license",
    "US_PASSPORT": "nlp_passport",
    "US_BANK_NUMBER": "nlp_bank_account",
    "US_ITIN": "nlp_itin",
    "UK_NHS": "nlp_nhs_number",
    "MEDICAL_LICENSE": "nlp_medical_license",
    "URL": "nlp_url",
    "DATE_TIME": "nlp_datetime",
    "NRP": "nlp_nationality",
    "LOCATION": "nlp_location",
    "ORGANIZATION": "nlp_organization",
}


def is_available() -> bool:
    """Return True if Presidio is installed and the required spaCy model is present."""
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine  # noqa: F401

        return spacy.util.is_package("en_core_web_sm")
    except ImportError:
        return False


def get_analyzer() -> Any:
    """Return the cached AnalyzerEngine, creating it on first call."""
    global _analyzer
    if _analyzer is not None:
        return _analyzer

    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    nlp_engine = provider.create_engine()
    _analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
    return _analyzer


def reset_analyzer() -> None:
    """Clear the cached analyzer (useful in tests)."""
    global _analyzer
    _analyzer = None


def analyze_text(
    text: str,
    *,
    min_confidence: float = 0.5,
    language: str = "en",
) -> NLPScanResult:
    """Analyze text for PII using Presidio.

    Args:
        text: Text to scan.
        min_confidence: Minimum score threshold (0.0-1.0).
        language: Language code for analysis.

    Returns:
        NLPScanResult with findings above the confidence threshold.
    """
    analyzer = get_analyzer()
    result = NLPScanResult(segments_scanned=1)

    results = analyzer.analyze(
        text=text,
        language=language,
        score_threshold=min_confidence,
    )

    result.entities_found = len(results)

    for r in results:
        entity_text = text[r.start : r.end]
        detector_name = PRESIDIO_TO_DETECTOR.get(r.entity_type, f"nlp_{r.entity_type.lower()}")

        ctx_start = max(0, r.start - 50)
        ctx_end = min(len(text), r.end + 50)

        result.findings.append(
            NLPFinding(
                entity_text=entity_text,
                entity_label=r.entity_type,
                detector_name=detector_name,
                confidence=r.score,
                context=text[ctx_start:ctx_end],
                start=r.start,
                end=r.end,
            )
        )

    return result


def analyze_segments(
    segments: list[tuple[str, str]],
    *,
    min_confidence: float = 0.5,
    language: str = "en",
) -> NLPScanResult:
    """Analyze multiple text segments, aggregating results.

    Args:
        segments: List of (text, segment_type) tuples.
        min_confidence: Minimum score threshold.
        language: Language code.

    Returns:
        Aggregated NLPScanResult.
    """
    combined = NLPScanResult(segments_scanned=len(segments))

    for seg_text, _seg_type in segments:
        if not seg_text.strip():
            continue
        partial = analyze_text(seg_text, min_confidence=min_confidence, language=language)
        combined.findings.extend(partial.findings)
        combined.entities_found += partial.entities_found
        combined.entities_suppressed += partial.entities_suppressed

    return combined
