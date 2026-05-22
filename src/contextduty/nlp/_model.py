"""spaCy model loading and lifecycle management.

Handles lazy-loading of the default model and swapping in enterprise
fine-tuned models at runtime.  The module-level ``_nlp`` singleton
ensures the (relatively expensive) model load happens only once.
"""

from __future__ import annotations

from typing import Any

# Module-level singleton — shared across all scan calls in the process.
_nlp: Any | None = None


def get_model(model_name: str = "en_core_web_sm") -> Any:
    """Return the cached spaCy ``Language`` pipeline, loading it on first call.

    Raises:
        ImportError: If spaCy is not installed.
        OSError: If the requested model is not downloaded.
    """
    global _nlp
    if _nlp is not None:
        return _nlp

    try:
        import spacy  # noqa: F811
    except ImportError:
        raise ImportError(
            "NLP features require spaCy. Install with:\n"
            "  pip install contextduty[nlp]\n"
            "  python -m spacy download en_core_web_sm"
        )

    try:
        _nlp = spacy.load(model_name)
    except OSError:
        raise OSError(
            f"spaCy model '{model_name}' not found. Install with:\n"
            f"  python -m spacy download {model_name}"
        )
    return _nlp


def load_model(model_path: str) -> None:
    """Replace the cached model with a custom / fine-tuned one.

    Args:
        model_path: Filesystem path or installed package name
                    (e.g. ``"/opt/models/bank-ner"``).

    Example::

        from contextduty.nlp import load_model
        load_model("/path/to/bank-custom-model")
    """
    global _nlp
    import spacy

    _nlp = spacy.load(model_path)


def reset_model() -> None:
    """Clear the cached model (useful in tests)."""
    global _nlp
    _nlp = None
