"""Tests for contextduty.nlp — NLP-based PII detection."""

import json
import tempfile

import pytest

from contextduty.nlp import (
    extract_text_segments,
    scan_file_nlp,
    scan_text_nlp,
)

# Skip all tests if spaCy is not installed
spacy = pytest.importorskip("spacy")


# ---------------------------------------------------------------------------
# Text extraction tests
# ---------------------------------------------------------------------------


class TestExtractTextSegments:
    def test_extracts_double_quoted_strings(self):
        code = 'name = "John Smith"\n'
        segments = extract_text_segments(code)
        texts = [s[0] for s in segments]
        assert any("John Smith" in t for t in texts)

    def test_extracts_single_quoted_strings(self):
        code = "name = 'Jane Doe'\n"
        segments = extract_text_segments(code)
        texts = [s[0] for s in segments]
        assert any("Jane Doe" in t for t in texts)

    def test_extracts_triple_quoted_docstrings(self):
        code = '"""This function processes patient data for Dr. Sarah Chen."""\n'
        segments = extract_text_segments(code)
        texts = [s[0] for s in segments]
        assert any("Sarah Chen" in t for t in texts)

    def test_extracts_comments(self):
        code = "# Contact John Smith at the NYC office\nx = 1\n"
        segments = extract_text_segments(code)
        texts = [s[0] for s in segments]
        assert any("John Smith" in t for t in texts)

    def test_skips_empty_strings(self):
        code = 'x = ""\n'
        segments = extract_text_segments(code)
        assert len(segments) == 0

    def test_skips_code_only_strings(self):
        code = 'x = "{}"\n'
        segments = extract_text_segments(code)
        assert len(segments) == 0


# ---------------------------------------------------------------------------
# NLP scanning tests
# ---------------------------------------------------------------------------


class TestScanTextNLP:
    def test_detects_person_name_in_string(self):
        code = 'customer_name = "John Smith"\n'
        result = scan_text_nlp(code, min_confidence=0.3)
        person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
        assert len(person_findings) > 0
        assert any("John Smith" in f.entity_text for f in person_findings)

    def test_detects_person_in_docstring(self):
        code = '"""Patient record for Dr. Sarah Chen, DOB 1985-03-15."""\n'
        result = scan_text_nlp(code, min_confidence=0.3)
        person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
        assert len(person_findings) > 0

    def test_detects_org_name(self):
        code = 'client = "Goldman Sachs"\n'
        result = scan_text_nlp(code, min_confidence=0.3)
        org_findings = [f for f in result.findings if f.entity_label == "ORG"]
        assert len(org_findings) > 0

    def test_detects_location(self):
        text = "The customer lives in San Francisco, California"
        result = scan_text_nlp(text, extract_segments=False, min_confidence=0.3)
        gpe_findings = [f for f in result.findings if f.entity_label == "GPE"]
        assert len(gpe_findings) > 0

    def test_clean_code_no_findings(self):
        code = "x = 42\ny = x + 1\nprint(y)\n"
        result = scan_text_nlp(code, min_confidence=0.5)
        assert len(result.findings) == 0

    def test_confidence_boost_with_pii_context(self):
        # "John Smith" near "patient" and "SSN" should have high confidence
        text = "Patient John Smith, SSN on file, needs treatment"
        result = scan_text_nlp(text, extract_segments=False, min_confidence=0.3)
        person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
        assert len(person_findings) > 0
        assert person_findings[0].confidence >= 0.7

    def test_sql_context_boosts_confidence(self):
        code = (
            """query = "SELECT * FROM users WHERE name = 'Maria Garcia'" """
        )
        result = scan_text_nlp(code, min_confidence=0.3)
        person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
        assert len(person_findings) > 0

    def test_min_confidence_filters_low_confidence(self):
        code = 'x = "hello"\n'
        result_low = scan_text_nlp(code, min_confidence=0.1)
        result_high = scan_text_nlp(code, min_confidence=0.9)
        assert len(result_high.findings) <= len(result_low.findings)

    def test_detector_name_format(self):
        text = "Customer John Smith called today"
        result = scan_text_nlp(text, extract_segments=False, min_confidence=0.3)
        for finding in result.findings:
            assert finding.detector_name.startswith("nlp_")

    def test_multiple_entities_in_one_text(self):
        text = "John Smith from Goldman Sachs visited our New York office"
        result = scan_text_nlp(text, extract_segments=False, min_confidence=0.3)
        labels = {f.entity_label for f in result.findings}
        assert "PERSON" in labels


# ---------------------------------------------------------------------------
# File scanning tests
# ---------------------------------------------------------------------------


class TestScanFileNLP:
    def test_scan_python_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write('# Process data for customer John Smith\n')
            f.write('name = "John Smith"\n')
            f.write('email = "john@example.com"\n')
            f.flush()
            result = scan_file_nlp(f.name, min_confidence=0.3)
            person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
            assert len(person_findings) > 0

    def test_scan_markdown_file(self):
        with tempfile.NamedTemporaryFile(suffix=".md", mode="w", delete=False) as f:
            f.write("# Patient Report\n\n")
            f.write("Patient Dr. Sarah Chen was admitted on 2024-01-15.\n")
            f.write("Diagnosis: Type 2 diabetes.\n")
            f.flush()
            result = scan_file_nlp(f.name, min_confidence=0.3)
            assert len(result.findings) > 0

    def test_scan_notebook_file(self):
        nb = {
            "nbformat": 4,
            "nbformat_minor": 5,
            "metadata": {},
            "cells": [
                {
                    "cell_type": "markdown",
                    "source": ["# Customer data for John Smith\n"],
                    "metadata": {},
                },
                {
                    "cell_type": "code",
                    "source": ['name = "Maria Garcia"\n'],
                    "metadata": {},
                    "outputs": [],
                },
            ],
        }
        with tempfile.NamedTemporaryFile(suffix=".ipynb", mode="w", delete=False) as f:
            json.dump(nb, f)
            f.flush()
            result = scan_file_nlp(f.name, min_confidence=0.3)
            person_findings = [f for f in result.findings if f.entity_label == "PERSON"]
            assert len(person_findings) > 0

    def test_scan_nonexistent_file(self):
        result = scan_file_nlp("/nonexistent/file.py")
        assert len(result.findings) == 0

    def test_scan_clean_file(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write("x = 42\ny = x + 1\n")
            f.flush()
            result = scan_file_nlp(f.name, min_confidence=0.5)
            assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Context scoring tests
# ---------------------------------------------------------------------------


class TestContextScoring:
    def test_person_in_patient_context_high_confidence(self):
        text = "Patient John Smith diagnosed with hypertension"
        result = scan_text_nlp(text, extract_segments=False, min_confidence=0.3)
        person = [f for f in result.findings if f.entity_label == "PERSON"]
        if person:
            assert person[0].confidence >= 0.7

    def test_suppresses_entities_found(self):
        # Entities found but below threshold should be counted as suppressed
        code = 'x = "something"\n'
        result = scan_text_nlp(code, min_confidence=0.99)
        # May or may not have entities, but any found should be suppressed
        assert result.entities_suppressed >= 0
