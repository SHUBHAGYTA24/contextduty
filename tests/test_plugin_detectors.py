"""Tests for the ``contextduty.detectors`` plugin entry-point mechanism.

The plugin hook must be strictly additive: with no plugin installed the engine
behaves exactly as before, and a registered plugin's detectors become available
to scanning and policy validation.
"""

from __future__ import annotations

import re

import pytest

from contextduty import detectors as det
from contextduty.detectors import Detector, get_all_detectors
from contextduty.engine import scan_text
from contextduty.policy import Policy, unknown_detector_names


@pytest.fixture(autouse=True)
def _clear_plugin_cache():
    """Ensure each test starts and ends with a clean plugin cache."""
    det._reset_plugin_cache()
    yield
    det._reset_plugin_cache()


def test_no_plugins_leaves_detectors_unchanged():
    # With nothing registered, get_all_detectors() is exactly the built-ins.
    assert get_all_detectors() == det.DETECTORS
    assert det.load_plugin_detectors() == ()


class _FakeEntryPoint:
    def __init__(self, factory):
        self._factory = factory

    def load(self):
        return self._factory


def _install_fake_plugin(monkeypatch, factory):
    monkeypatch.setattr(det, "entry_points", lambda group=None: [_FakeEntryPoint(factory)])
    det._reset_plugin_cache()


def test_plugin_detector_is_discovered(monkeypatch):
    premium = Detector(name="acme_badge_id", pattern=re.compile(r"\bACME-\d{4}\b"))
    _install_fake_plugin(monkeypatch, lambda: [premium])

    names = {d.name for d in get_all_detectors()}
    assert "acme_badge_id" in names
    # Built-ins are still all present — the plugin is additive.
    assert {d.name for d in det.DETECTORS} <= names


def test_plugin_detector_fires_in_scan(monkeypatch):
    premium = Detector(name="acme_badge_id", pattern=re.compile(r"\bACME-\d{4}\b"))
    _install_fake_plugin(monkeypatch, lambda: [premium])

    policy = Policy(mode="warn", detectors={"acme_badge_id"}, custom_detectors={})
    result = scan_text("employee ACME-1234 checked in", policy).scan
    assert result.findings_count == 1
    assert result.detector_counts.get("acme_badge_id") == 1


def test_plugin_detector_name_counts_as_known(monkeypatch):
    premium = Detector(name="acme_badge_id", pattern=re.compile(r"\bACME-\d{4}\b"))
    _install_fake_plugin(monkeypatch, lambda: [premium])

    policy = Policy(mode="warn", detectors={"acme_badge_id"}, custom_detectors={})
    # Should NOT be reported as an unknown/typo detector name.
    assert unknown_detector_names(policy) == []


def test_broken_plugin_is_skipped_not_fatal(monkeypatch):
    def _explode():
        raise RuntimeError("plugin blew up")

    _install_fake_plugin(monkeypatch, _explode)
    # A malfunctioning plugin must never break scanning.
    assert get_all_detectors() == det.DETECTORS
