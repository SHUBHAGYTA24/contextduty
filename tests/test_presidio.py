"""Tests for Presidio NLP backend integration."""

from __future__ import annotations

import pytest

from contextduty.nlp._types import NLPFinding, NLPScanResult

# ---------------------------------------------------------------------------
# Check if Presidio is installed
# ---------------------------------------------------------------------------

try:
    from contextduty.nlp._presidio import (
        analyze_segments,
        analyze_text,
        is_available,
        reset_analyzer,
    )

    HAS_PRESIDIO = is_available()
except ImportError:
    HAS_PRESIDIO = False

skip_no_presidio = pytest.mark.skipif(not HAS_PRESIDIO, reason="presidio not installed")


# ---------------------------------------------------------------------------
# Backend selection tests (always run)
# ---------------------------------------------------------------------------


class TestBackendSelection:
    def test_get_backend_returns_string(self):
        from contextduty.nlp._scanner import get_backend, reset_backend

        reset_backend()
        backend = get_backend()
        assert backend in ("presidio", "spacy")
        reset_backend()

    def test_set_backend_validates(self):
        from contextduty.nlp._scanner import reset_backend, set_backend

        with pytest.raises(ValueError, match="Unknown"):
            set_backend("tensorflow")
        reset_backend()

    def test_set_backend_overrides(self):
        from contextduty.nlp._scanner import get_backend, reset_backend, set_backend

        set_backend("spacy")
        assert get_backend() == "spacy"
        reset_backend()

    def test_presidio_available_returns_bool(self):
        from contextduty.nlp._presidio import is_available

        assert isinstance(is_available(), bool)


# ---------------------------------------------------------------------------
# Presidio detection tests (only when installed)
# ---------------------------------------------------------------------------


@skip_no_presidio
class TestPresidioAnalyzer:
    def setup_method(self):
        reset_analyzer()

    def teardown_method(self):
        reset_analyzer()

    def test_detect_email(self):
        result = analyze_text("Contact john.doe@example.com for details")
        assert isinstance(result, NLPScanResult)
        emails = [f for f in result.findings if f.detector_name == "nlp_email"]
        assert len(emails) >= 1
        assert "john.doe@example.com" in emails[0].entity_text

    def test_detect_phone(self):
        result = analyze_text("Call me at +1-212-555-1234 tomorrow", min_confidence=0.3)
        phones = [f for f in result.findings if f.detector_name == "nlp_phone"]
        assert len(phones) >= 1

    def test_detect_credit_card(self):
        result = analyze_text("Card number: 4111-1111-1111-1111")
        cards = [f for f in result.findings if f.detector_name == "nlp_credit_card"]
        assert len(cards) >= 1

    def test_detect_person_name(self):
        result = analyze_text("Patient John Smith was admitted on Monday")
        persons = [f for f in result.findings if f.detector_name == "nlp_person"]
        assert len(persons) >= 1

    def test_detect_ip_address(self):
        result = analyze_text("Server is running on 192.168.1.100 port 8080")
        ips = [f for f in result.findings if f.detector_name == "nlp_ip_address"]
        assert len(ips) >= 1

    def test_confidence_threshold(self):
        result_low = analyze_text("Contact john@example.com", min_confidence=0.1)
        result_high = analyze_text("Contact john@example.com", min_confidence=0.99)
        assert len(result_low.findings) >= len(result_high.findings)

    def test_empty_text(self):
        result = analyze_text("")
        assert result.findings == []
        assert result.entities_found == 0

    def test_no_pii_text(self):
        result = analyze_text("The weather is nice today")
        # May or may not detect "today" as datetime — just verify it runs
        assert isinstance(result, NLPScanResult)

    def test_analyze_segments(self):
        segments = [
            ("Email: alice@corp.com", "string"),
            ("Phone: 555-000-1234", "comment"),
        ]
        result = analyze_segments(segments, min_confidence=0.3)
        assert result.segments_scanned == 2
        assert len(result.findings) >= 2

    def test_context_window(self):
        text = "x" * 100 + "john@example.com" + "y" * 100
        result = analyze_text(text, min_confidence=0.3)
        for f in result.findings:
            # Context is at most 50 chars before + entity + 50 chars after
            assert len(f.context) <= len(f.entity_text) + 100


@skip_no_presidio
class TestPresidioIntegration:
    """Test Presidio through the main scan_text_nlp API."""

    def setup_method(self):
        from contextduty.nlp._scanner import reset_backend, set_backend

        reset_backend()
        set_backend("presidio")

    def teardown_method(self):
        from contextduty.nlp._scanner import reset_backend

        reset_backend()
        reset_analyzer()

    def test_scan_text_nlp_uses_presidio(self):
        from contextduty.nlp import scan_text_nlp

        result = scan_text_nlp(
            'user_email = "alice@example.com"',
            extract_segments=True,
            backend="presidio",
        )
        assert isinstance(result, NLPScanResult)

    def test_scan_text_nlp_backend_override(self):
        from contextduty.nlp import scan_text_nlp

        result = scan_text_nlp(
            "Contact bob@test.com",
            extract_segments=False,
            backend="presidio",
        )
        emails = [f for f in result.findings if "email" in f.detector_name]
        assert len(emails) >= 1

    def test_crypto_address_detection(self):
        result = analyze_text("Send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        crypto = [f for f in result.findings if "crypto" in f.detector_name]
        assert len(crypto) >= 1

    def test_iban_detection(self):
        result = analyze_text("IBAN: DE89370400440532013000")
        ibans = [f for f in result.findings if "iban" in f.detector_name]
        assert len(ibans) >= 1
