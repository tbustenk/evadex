"""Tests for the v3.13.0 --evasion-mode + technique-history machinery."""
from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

import pytest

from evadex.feedback.technique_history import (
    has_history, load_technique_history,
)


class _FakeGen:
    """Lightweight stand-in for a real variant generator."""
    def __init__(self, name: str, applicable_categories=None):
        self.name = name
        self.applicable_categories = applicable_categories
        self.auto_applicable = True

    def generate(self, value: str):
        # Yield exactly one variant tagged with the generator name so
        # _pick_variant's downstream filtering sees something.
        from evadex.core.result import Variant
        yield Variant(
            value=f"{self.name}:{value}",
            generator=self.name,
            technique=self.name,
            transform_name="t",
        )


# ── Audit-history loader ────────────────────────────────────────────────────

def _write_audit(path: Path, *runs: dict):
    """Write one JSON line per run into *path*."""
    with open(path, "w", encoding="utf-8") as fh:
        for r in runs:
            fh.write(json.dumps(r) + "\n")


def test_history_aggregates_average_and_latest(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_audit(
        log,
        {"timestamp": "t1", "technique_success_rates": {"alpha": 0.10, "beta": 0.90}},
        {"timestamp": "t2", "technique_success_rates": {"alpha": 0.30, "beta": 0.80}},
        {"timestamp": "t3", "technique_success_rates": {"alpha": 0.50, "beta": 0.70}},
    )
    stats = load_technique_history(str(log))
    assert pytest.approx(stats["alpha"].average_success, abs=1e-6) == 0.30
    assert pytest.approx(stats["beta"].average_success, abs=1e-6) == 0.80
    assert stats["alpha"].latest_success == 0.50
    assert pytest.approx(stats["alpha"].trend, abs=1e-6) == 0.20
    assert stats["alpha"].runs == 3


def test_has_history_false_for_legacy_entries(tmp_path):
    log = tmp_path / "audit.jsonl"
    # Legacy entries (no technique_success_rates field) should not count.
    _write_audit(
        log,
        {"timestamp": "old", "scanner_label": "x", "pass_rate": 50.0},
    )
    assert has_history(str(log)) is False


def test_has_history_true_with_modern_entries(tmp_path):
    log = tmp_path / "audit.jsonl"
    _write_audit(
        log,
        {"timestamp": "t1", "technique_success_rates": {"alpha": 0.5}},
    )
    assert has_history(str(log)) is True


def test_has_history_false_for_missing_file(tmp_path):
    assert has_history(str(tmp_path / "does_not_exist.jsonl")) is False


# ── _pick_variant evasion modes ─────────────────────────────────────────────

def _make_gens(*names: str):
    return [_FakeGen(n) for n in names]


def test_random_mode_uniform_selection_seeded():
    """random mode picks deterministically given a seed."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("a", "b", "c", "d")
    rng = random.Random(0)
    v = _pick_variant(rng, "value", None, gens, allowed_techniques=None,
                      evasion_mode="random")
    assert v is not None and v.technique in {"a", "b", "c", "d"}


def test_weighted_mode_favours_low_detection_techniques():
    """Over many trials, weighted mode picks low-detection techniques
    (= high evasion success) more often than high-detection ones."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("evader", "detected")
    history = {"evader": 0.10, "detected": 0.90}
    counts = Counter()
    for seed in range(2000):
        rng = random.Random(seed)
        v = _pick_variant(
            rng, "v", None, gens, allowed_techniques=None,
            evasion_mode="weighted", technique_history=history,
        )
        if v is not None:
            counts[v.technique] += 1
    # weight(evader) = 0.9, weight(detected) = 0.1 → ~9x ratio expected.
    assert counts["evader"] > counts["detected"] * 3, (
        f"weighted mode failed to favour low-detection technique: {counts}"
    )


def test_adversarial_mode_excludes_above_threshold_techniques():
    """Generators with scanner-detection > 0.5 must be excluded."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("good_evader", "borderline", "bad_evader")
    history = {
        "good_evader": 0.10,    # caught only 10% of the time → keep
        "borderline":  0.49,    # → keep
        "bad_evader":  0.95,    # caught 95% → exclude
    }
    seen = Counter()
    for seed in range(500):
        rng = random.Random(seed)
        v = _pick_variant(
            rng, "v", None, gens, allowed_techniques=None,
            evasion_mode="adversarial", technique_history=history,
        )
        if v is not None:
            seen[v.technique] += 1
    assert seen["bad_evader"] == 0, f"bad_evader leaked through: {seen}"
    assert seen["good_evader"] > 0
    assert seen["borderline"] > 0


def test_adversarial_mode_falls_back_when_filter_empty():
    """If every technique exceeds 50 %, adversarial must still emit
    something (fall back to the unfiltered pool)."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("a", "b")
    history = {"a": 0.95, "b": 0.99}
    rng = random.Random(0)
    v = _pick_variant(
        rng, "v", None, gens, allowed_techniques=None,
        evasion_mode="adversarial", technique_history=history,
    )
    assert v is not None
    assert v.technique in {"a", "b"}


def test_weighted_mode_cold_start_falls_back_to_random():
    """No history → behaves like random (always returns something)."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("a", "b", "c")
    rng = random.Random(0)
    v = _pick_variant(
        rng, "v", None, gens, allowed_techniques=None,
        evasion_mode="weighted", technique_history=None,
    )
    assert v is not None
    assert v.technique in {"a", "b", "c"}


def test_exhaustive_mode_picks_first_alphabetical():
    """exhaustive returns the first applicable generator after the
    name-sort already enforced for reproducibility."""
    from evadex.generate.generator import _pick_variant
    gens = _make_gens("z_gen", "a_gen", "m_gen")
    rng = random.Random(123)
    v = _pick_variant(
        rng, "v", None, gens, allowed_techniques=None,
        evasion_mode="exhaustive",
    )
    assert v is not None
    assert v.technique == "a_gen"
