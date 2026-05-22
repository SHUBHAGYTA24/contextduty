"""Context-aware confidence scoring for NLP-detected entities.

The scorer adjusts raw NER output using two signal families:

* **Suppress patterns** — lower confidence when the surrounding text
  looks like boilerplate code (imports, config keys, test domains).
* **Boost patterns** — raise confidence when PII-adjacent keywords
  appear nearby (patient, SSN, SQL, financial terms).

Additional heuristics handle short tokens, single-word names in code
strings, and multi-word person names.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Entity-label classification
# ---------------------------------------------------------------------------

#: spaCy labels we treat as potential PII.
PII_ENTITY_LABELS: frozenset[str] = frozenset(
    {
        "PERSON",  # Person names
        "ORG",  # Organizations (sensitive in context)
        "GPE",  # Geopolitical entities (countries, cities)
        "LOC",  # Non-GPE locations
        "DATE",  # Dates (DOB, appointments)
        "MONEY",  # Monetary values
        "CARDINAL",  # Numerals (account numbers in context)
    }
)

#: Labels assigned high base confidence regardless of context.
HIGH_CONFIDENCE_LABELS: frozenset[str] = frozenset({"PERSON"})

#: Labels that need contextual evidence to be flagged.
CONTEXT_DEPENDENT_LABELS: frozenset[str] = frozenset(PII_ENTITY_LABELS - HIGH_CONFIDENCE_LABELS)

# ---------------------------------------------------------------------------
# Pattern banks
# ---------------------------------------------------------------------------

_SUPPRESS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"^import\s+",
        r"^from\s+\S+\s+import",
        r"^\s*class\s+",
        r"^\s*def\s+",
        r"timezone|locale|encoding|charset",
        r"font|color|theme|style",
        r"version|release|tag",
        r"localhost|127\.0\.0\.\d|0\.0\.0\.0",
        r"example\.com|test\.com|foo\.bar",
        r"TODO|FIXME|HACK|NOTE|XXX",
    )
]

_BOOST_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"customer|patient|user|client|employee|student",
        r"name|address|phone|email|ssn|dob|birth",
        r"SELECT|INSERT|UPDATE|DELETE|FROM|WHERE",
        r"password|secret|credential|token",
        r'"role"\s*:\s*"(user|system|assistant)"',
        r"diagnosis|prescription|treatment|medical",
        r"account|routing|swift|iban|transaction",
    )
]

# ---------------------------------------------------------------------------
# Confidence weights (centralised for easy tuning)
# ---------------------------------------------------------------------------

_BASE_HIGH = 0.70
_BASE_CONTEXT_DEP = 0.40
_BASE_OTHER = 0.30

_SEGMENT_NATURAL = 0.10  # docstring / markdown / output
_SEGMENT_COMMENT = 0.05

_SUPPRESS_PENALTY = 0.30
_BOOST_PER_MATCH = 0.10
_BOOST_CAP = 0.30

_SHORT_ENTITY_PENALTY = 0.30  # len(text) <= 2
_SINGLE_WORD_PERSON_PENALTY = 0.20
_MULTI_WORD_PERSON_BONUS = 0.15


# ---------------------------------------------------------------------------
# Public scoring function
# ---------------------------------------------------------------------------


def compute_confidence(
    entity_text: str,
    entity_label: str,
    segment_text: str,
    segment_type: str,
) -> float:
    """Return a confidence score in ``[0.0, 1.0]`` for a detected entity.

    The score starts from a label-dependent base and is then adjusted by
    segment type, suppress/boost pattern matches, and entity-length
    heuristics.
    """
    # --- base ---
    if entity_label in HIGH_CONFIDENCE_LABELS:
        score = _BASE_HIGH
    elif entity_label in CONTEXT_DEPENDENT_LABELS:
        score = _BASE_CONTEXT_DEP
    else:
        score = _BASE_OTHER

    # --- segment type ---
    if segment_type in ("docstring", "markdown", "output"):
        score += _SEGMENT_NATURAL
    elif segment_type == "comment":
        score += _SEGMENT_COMMENT

    # --- suppress ---
    for pat in _SUPPRESS_PATTERNS:
        if pat.search(segment_text):
            score -= _SUPPRESS_PENALTY
            break  # one suppress hit is enough

    # --- boost ---
    hits = sum(1 for pat in _BOOST_PATTERNS if pat.search(segment_text))
    score += min(hits * _BOOST_PER_MATCH, _BOOST_CAP)

    # --- entity-length heuristics ---
    if len(entity_text) <= 2:
        score -= _SHORT_ENTITY_PENALTY

    if entity_label == "PERSON" and " " not in entity_text and segment_type == "string":
        score -= _SINGLE_WORD_PERSON_PENALTY

    if entity_label == "PERSON" and " " in entity_text:
        score += _MULTI_WORD_PERSON_BONUS

    return max(0.0, min(1.0, score))
