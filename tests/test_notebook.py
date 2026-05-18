"""Tests for Jupyter notebook (.ipynb) scanning and redaction."""

import json
import tempfile
from pathlib import Path

from contextduty.engine import scan_file, redact_file
from contextduty.policy import Policy


def _policy(mode="warn"):
    return Policy(mode=mode, detectors={"aws_key", "api_key"}, custom_detectors={})


def _make_notebook(cells):
    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": cells,
    }


def _write_notebook(tmp_dir, name, nb_dict):
    p = Path(tmp_dir) / name
    p.write_text(json.dumps(nb_dict), encoding="utf-8")
    return p


def test_scan_notebook_detects_aws_key():
    nb = _make_notebook([
        {
            "cell_type": "code",
            "source": ["import boto3\n", "key = 'AKIAIOSFODNN7EXAMPLE'\n"],
            "metadata": {},
            "outputs": [],
        }
    ])
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_notebook(tmp, "secrets.ipynb", nb)
        result = scan_file(path, _policy())
        assert result.findings_count > 0
        assert "aws_key" in result.detector_counts


def test_scan_notebook_detects_secret_in_output():
    nb = _make_notebook([
        {
            "cell_type": "code",
            "source": ["print(key)\n"],
            "metadata": {},
            "outputs": [
                {
                    "output_type": "stream",
                    "name": "stdout",
                    "text": ["AKIAIOSFODNN7EXAMPLE\n"],
                }
            ],
        }
    ])
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_notebook(tmp, "output_leak.ipynb", nb)
        result = scan_file(path, _policy())
        assert result.findings_count > 0
        assert "aws_key" in result.detector_counts


def test_scan_notebook_clean():
    nb = _make_notebook([
        {
            "cell_type": "code",
            "source": ["x = 42\n"],
            "metadata": {},
            "outputs": [],
        }
    ])
    with tempfile.TemporaryDirectory() as tmp:
        path = _write_notebook(tmp, "clean.ipynb", nb)
        result = scan_file(path, _policy())
        assert result.findings_count == 0


def test_redact_notebook_preserves_structure():
    nb = _make_notebook([
        {
            "cell_type": "code",
            "source": ["key = 'AKIAIOSFODNN7EXAMPLE'\n"],
            "metadata": {},
            "outputs": [],
        },
        {
            "cell_type": "markdown",
            "source": ["# Clean cell\n"],
            "metadata": {},
        },
    ])
    with tempfile.TemporaryDirectory() as tmp:
        inp = _write_notebook(tmp, "in.ipynb", nb)
        out = Path(tmp) / "out.ipynb"
        result = redact_file(inp, out, _policy("redact"))
        assert result.findings_count > 0

        redacted_nb = json.loads(out.read_text())
        assert redacted_nb["nbformat"] == 4
        assert len(redacted_nb["cells"]) == 2
        code_source = "".join(redacted_nb["cells"][0]["source"])
        assert "AKIAIOSFODNN7EXAMPLE" not in code_source
        assert "<AWS_KEY_" in code_source
        assert redacted_nb["cells"][1]["source"] == ["# Clean cell\n"]


def test_redact_notebook_output():
    nb = _make_notebook([
        {
            "cell_type": "code",
            "source": ["print(key)\n"],
            "metadata": {},
            "outputs": [
                {
                    "output_type": "stream",
                    "name": "stdout",
                    "text": ["AKIAIOSFODNN7EXAMPLE\n"],
                }
            ],
        }
    ])
    with tempfile.TemporaryDirectory() as tmp:
        inp = _write_notebook(tmp, "in.ipynb", nb)
        out = Path(tmp) / "out.ipynb"
        result = redact_file(inp, out, _policy("redact"))
        assert result.findings_count > 0

        redacted_nb = json.loads(out.read_text())
        output_text = "".join(redacted_nb["cells"][0]["outputs"][0]["text"])
        assert "AKIAIOSFODNN7EXAMPLE" not in output_text
        assert "<AWS_KEY_" in output_text
