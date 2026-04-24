"""Tests for --fast mode technique selection."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from evadex.core.registry import load_builtins, all_generators
from evadex.feedback.fast_mode import (
    pick_fast_techniques,
    DEFAULT_TOP_PER_GENERATOR,
    DEFAULT_MIN_BYPASS,
)


@pytest.fixture(autouse=True)
def _load_gens():
    load_builtins()


def test_fast_mode_reduces_variant_pool(tmp_path):
    """Fast mode must produce a strictly smaller technique set than the
    exhaustive default when there are more than TOP_PER_GENERATOR options."""
    gens = all_generators()
    allowed, diag = pick_fast_techniques(gens, audit_log=None)
    assert allowed, "Fast mode should keep at least some techniques"
    assert diag["kept"] < diag["total_enumerated"], (
        "Fast mode must drop something — otherwise there's no speedup"
    )
    # Sanity: at most TOP_PER_GENERATOR × #generators techniques.
    assert diag["kept"] <= DEFAULT_TOP_PER_GENERATOR * len(gens)


def test_fast_mode_respects_min_bypass_floor():
    """Techniques with estimated bypass below the floor must not be kept."""
    gens = all_generators()
    # Set the floor absurdly high — no technique should survive.
    allowed, diag = pick_fast_techniques(
        gens, audit_log=None, top_per_generator=10, min_bypass=0.999,
    )
    assert len(allowed) == 0
    assert diag["dropped"] >= diag["total_enumerated"]


def test_fast_mode_uses_audit_history_when_available(tmp_path):
    """History blend must change the selection when ``has_history`` is true."""
    audit = tmp_path / "audit.jsonl"
    # Craft history where "zero_width_space" — a normally high-weight
    # technique — has been catching 100% of the time (i.e. scanner always
    # detects it → 0 % bypass). Fast mode should drop it in favour of
    # something else.
    entry = {
        "timestamp": "2026-04-24T00:00:00+00:00",
        "technique_success_rates": {
            # scanner always catches these → low bypass
            "zero_width_space": 0.99,
            "unicode_nbsp":     0.99,
            # scanner always misses these → high bypass
            "homoglyph_substitution": 0.0,
            "rlo_override":           0.0,
        },
    }
    audit.write_text(json.dumps(entry) + "\n", encoding="utf-8")

    gens = all_generators()
    allowed, diag = pick_fast_techniques(gens, audit_log=str(audit))
    assert diag["has_history"] is True
    # Observed high-bypass technique must be kept, observed low-bypass dropped.
    assert "homoglyph_substitution" in allowed
    assert "zero_width_space" not in allowed


def test_fast_mode_cold_start_without_history(tmp_path):
    """Missing audit log must fall back to pure seed weights, no crash."""
    audit = tmp_path / "missing.jsonl"
    assert not audit.exists()
    gens = all_generators()
    allowed, diag = pick_fast_techniques(gens, audit_log=str(audit))
    assert diag["has_history"] is False
    assert len(allowed) > 0
