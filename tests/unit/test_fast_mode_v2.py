"""Tests for the improved --fast mode with exponential decay and per-category selection."""

import json
import math
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from evadex.feedback.fast_mode import (
    _decay_weight,
    _load_history_bypass_with_decay,
    pick_fast_techniques,
    DEFAULT_DECAY_HALF_LIFE,
)


# ── Exponential decay ──────────────────────────────────────────────────────────

def test_decay_weight_newest_is_one():
    # The newest entry (position = total-1) should have weight 1.0
    w = _decay_weight(position=4, total=5, half_life=5)
    assert abs(w - 1.0) < 1e-9


def test_decay_weight_older_is_less():
    # An older entry should have weight < 1.0
    newest = _decay_weight(position=9, total=10, half_life=5)
    older = _decay_weight(position=4, total=10, half_life=5)
    assert older < newest


def test_decay_weight_half_life_halves():
    # At exactly half_life entries old, weight should be ~0.5
    half_life = 5
    w = _decay_weight(position=0, total=half_life + 1, half_life=half_life)
    assert abs(w - 0.5) < 0.01


def test_decay_weighted_history_loaded(tmp_path):
    audit = tmp_path / "audit.jsonl"
    entry = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "technique_success_rates": {"base64": 0.2, "homoglyph": 0.8},
    }
    audit.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    bypass = _load_history_bypass_with_decay(str(audit))
    # base64 detection=0.2 → bypass=0.8; homoglyph detection=0.8 → bypass=0.2
    assert "base64" in bypass
    assert "homoglyph" in bypass
    assert bypass["base64"] > bypass["homoglyph"]


def test_decay_recent_entries_dominate(tmp_path):
    audit = tmp_path / "audit.jsonl"
    # Old entry: base64 has bypass 0.9 (detection 0.1)
    old = {"timestamp": "2025-01-01T00:00:00+00:00", "technique_success_rates": {"base64": 0.1}}
    # Recent entry: base64 has bypass 0.1 (detection 0.9) — complete reversal
    new = {"timestamp": "2026-01-01T00:00:00+00:00", "technique_success_rates": {"base64": 0.9}}
    audit.write_text(
        json.dumps(old) + "\n" + json.dumps(new) + "\n", encoding="utf-8"
    )
    bypass = _load_history_bypass_with_decay(str(audit), half_life=1)
    # With half_life=1, newest entry dominates heavily
    # New entry says bypass=0.1; old says bypass=0.9
    # Result should be closer to 0.1 than to 0.9
    assert bypass["base64"] < 0.5


# ── pick_fast_techniques with decay ───────────────────────────────────────────

def _make_mock_gen(name: str, techniques: list[str]):
    """Create a mock generator that yields variants for the given techniques."""
    gen = MagicMock()
    gen.name = name
    variants = []
    for t in techniques:
        v = MagicMock()
        v.technique = t
        variants.append(v)
    gen.generate = MagicMock(return_value=variants)
    return gen


def test_pick_fast_techniques_cold_start_uses_seeds():
    gen = _make_mock_gen("unicode_encoding", ["homoglyph_substitution", "fullwidth_digits"])
    allowed, diag = pick_fast_techniques([gen], audit_log=None)
    assert len(allowed) > 0
    assert not diag["has_history"]


def test_pick_fast_techniques_verbose_includes_weights():
    gen = _make_mock_gen("encoding", ["base64", "rot13", "url_double_encode"])
    allowed, diag = pick_fast_techniques([gen], audit_log=None, verbose=True)
    assert "verbose_weights" in diag
    assert "encoding" in diag["verbose_weights"]
