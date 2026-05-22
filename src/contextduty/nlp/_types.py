"""Data structures for NLP-based PII detection."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NLPFinding:
    """A single NLP-detected PII entity.

    Attributes:
        entity_text: The detected text (e.g., "John Smith").
        entity_label: spaCy NER label (e.g., "PERSON", "ORG").
        detector_name: Normalized name for the scan pipeline (e.g., "nlp_person").
        confidence: Context-adjusted score between 0.0 and 1.0.
        context: Surrounding text snippet for audit trail.
        start: Character offset (start) within the scanned segment.
        end: Character offset (end) within the scanned segment.
    """

    entity_text: str
    entity_label: str
    detector_name: str
    confidence: float
    context: str
    start: int
    end: int


@dataclass
class NLPScanResult:
    """Aggregated results from an NLP scan pass.

    Attributes:
        findings: PII entities that passed the confidence threshold.
        segments_scanned: Number of text segments processed.
        entities_found: Total entities detected by NER (before filtering).
        entities_suppressed: Entities dropped below the confidence threshold.
    """

    findings: list[NLPFinding] = field(default_factory=list)
    segments_scanned: int = 0
    entities_found: int = 0
    entities_suppressed: int = 0
