"""Unit tests for evadex.generate.generator and evadex.generate.filler."""
import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import (
    GenerateConfig,
    GeneratedEntry,
    _generate_cc,
    _luhn_check_digit,
    generate_entries,
)
from evadex.generate.filler import get_keyword_sentence
import random


# ── Luhn helpers ───────────────────────────────────────────────────────────────

def _is_valid_luhn(number: str) -> bool:
    digits = [int(d) for d in number]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def test_luhn_check_digit_known():
    # 453201511283036 → check digit 6 → full: 4532015112830366
    digits = [4, 5, 3, 2, 0, 1, 5, 1, 1, 2, 8, 3, 0, 3, 6]
    assert _luhn_check_digit(digits) == 6


def test_generate_cc_visa_passes_luhn():
    rng = random.Random(42)
    for _ in range(20):
        cc = _generate_cc(rng, "4", 16)
        assert len(cc) == 16
        assert cc.startswith("4")
        assert _is_valid_luhn(cc)


def test_generate_cc_amex_passes_luhn():
    rng = random.Random(7)
    for _ in range(10):
        cc = _generate_cc(rng, "37", 15)
        assert len(cc) == 15
        assert cc.startswith("37")
        assert _is_valid_luhn(cc)


# ── generate_entries — basic smoke ─────────────────────────────────────────────

def _simple_config(**kwargs) -> GenerateConfig:
    defaults = dict(
        fmt="csv",
        categories=[PayloadCategory.CREDIT_CARD],
        count=10,
        evasion_rate=0.5,
        keyword_rate=0.5,
        seed=0,
    )
    defaults.update(kwargs)
    return GenerateConfig(**defaults)


def test_generate_returns_list():
    entries = generate_entries(_simple_config())
    assert isinstance(entries, list)


def test_generate_count_per_category():
    entries = generate_entries(_simple_config(count=20))
    assert len(entries) == 20


def test_generate_multi_category_count():
    config = _simple_config(
        categories=[PayloadCategory.CREDIT_CARD, PayloadCategory.SSN],
        count=15,
    )
    entries = generate_entries(config)
    assert len(entries) == 30  # 15 per category


def test_generate_entries_are_generated_entry():
    entries = generate_entries(_simple_config())
    for e in entries:
        assert isinstance(e, GeneratedEntry)


def test_generate_category_matches_config():
    config = _simple_config(categories=[PayloadCategory.SSN], count=5)
    entries = generate_entries(config)
    assert all(e.category == PayloadCategory.SSN for e in entries)


# ── evasion_rate ──────────────────────────────────────────────────────────────

def test_evasion_rate_zero_means_no_variants():
    config = _simple_config(count=50, evasion_rate=0.0, seed=1)
    entries = generate_entries(config)
    assert all(e.technique is None for e in entries)
    assert all(e.plain_value == e.variant_value for e in entries)


def test_evasion_rate_one_means_all_variants():
    config = _simple_config(count=50, evasion_rate=1.0, seed=2)
    entries = generate_entries(config)
    # Every entry should have a technique (all credit cards have applicable generators)
    assert all(e.technique is not None for e in entries)


def test_evasion_rate_half_approximately():
    config = _simple_config(count=200, evasion_rate=0.5, seed=99)
    entries = generate_entries(config)
    evasion = sum(1 for e in entries if e.technique is not None)
    # Accept 25%–75% range for 200 samples
    assert 0.25 <= evasion / len(entries) <= 0.75


# ── keyword_rate ──────────────────────────────────────────────────────────────

def test_keyword_rate_zero_leaves_bare_value():
    config = _simple_config(count=30, evasion_rate=0.0, keyword_rate=0.0, seed=3)
    entries = generate_entries(config)
    for e in entries:
        assert e.embedded_text == e.variant_value


# ── seed reproducibility ──────────────────────────────────────────────────────

def test_same_seed_same_output():
    cfg_a = _simple_config(count=20, seed=123)
    cfg_b = _simple_config(count=20, seed=123)
    a = generate_entries(cfg_a)
    b = generate_entries(cfg_b)
    assert [e.plain_value for e in a] == [e.plain_value for e in b]
    assert [e.variant_value for e in a] == [e.variant_value for e in b]
    assert [e.technique for e in a] == [e.technique for e in b]


def test_different_seeds_give_different_output():
    cfg_a = _simple_config(count=20, seed=1)
    cfg_b = _simple_config(count=20, seed=2)
    a = generate_entries(cfg_a)
    b = generate_entries(cfg_b)
    # With 20 credit card samples it's virtually impossible to be identical
    assert [e.plain_value for e in a] != [e.plain_value for e in b]


# ── technique filtering ───────────────────────────────────────────────────────

def test_technique_filter_respected():
    config = _simple_config(
        count=30,
        evasion_rate=1.0,
        techniques=["homoglyph_substitution"],
        seed=5,
    )
    entries = generate_entries(config)
    for e in entries:
        if e.technique is not None:
            assert e.technique == "homoglyph_substitution"


def test_multiple_techniques_filter():
    config = _simple_config(
        count=50,
        evasion_rate=1.0,
        techniques=["homoglyph_substitution", "zero_width_zwsp"],
        seed=6,
    )
    entries = generate_entries(config)
    allowed = {"homoglyph_substitution", "zero_width_zwsp"}
    for e in entries:
        if e.technique is not None:
            assert e.technique in allowed


# ── random mode ───────────────────────────────────────────────────────────────

def test_random_mode_produces_entries():
    config = GenerateConfig(fmt="csv", count=10, random_mode=True, seed=77)
    entries = generate_entries(config)
    assert len(entries) > 0


def test_random_mode_seed_reproducible():
    cfg_a = GenerateConfig(fmt="csv", count=10, random_mode=True, seed=42)
    cfg_b = GenerateConfig(fmt="csv", count=10, random_mode=True, seed=42)
    a = generate_entries(cfg_a)
    b = generate_entries(cfg_b)
    assert [e.category for e in a] == [e.category for e in b]


# ── no-category (all structured) ─────────────────────────────────────────────

def test_no_category_uses_all_structured():
    config = GenerateConfig(fmt="csv", count=2, seed=0)
    entries = generate_entries(config)
    cats = {e.category for e in entries}
    # Should include multiple structured categories
    assert len(cats) > 1
    # Should NOT include heuristic categories by default
    from evadex.payloads.builtins import HEURISTIC_CATEGORIES
    assert not cats.intersection(HEURISTIC_CATEGORIES)


def test_include_heuristic_adds_heuristic_cats():
    config = GenerateConfig(
        fmt="csv", count=2, seed=0, include_heuristic=True,
        categories=[PayloadCategory.AWS_KEY],
    )
    entries = generate_entries(config)
    assert all(e.category == PayloadCategory.AWS_KEY for e in entries)


# ── empty result ──────────────────────────────────────────────────────────────

def test_empty_when_no_matching_payloads():
    # UNKNOWN category has no builtin payloads
    config = GenerateConfig(
        fmt="csv", count=10, seed=0,
        categories=[PayloadCategory.UNKNOWN],
    )
    entries = generate_entries(config)
    assert entries == []


# ── credit card validity ──────────────────────────────────────────────────────

def test_generated_cc_values_are_luhn_valid():
    config = _simple_config(categories=[PayloadCategory.CREDIT_CARD], count=50,
                            evasion_rate=0.0, seed=7)
    entries = generate_entries(config)
    for e in entries:
        digits = e.plain_value.replace(" ", "").replace("-", "")
        assert digits.isdigit()
        assert _is_valid_luhn(digits), f"Luhn failed: {e.plain_value}"


# ── filler sentences ──────────────────────────────────────────────────────────

def test_filler_contains_value():
    rng = random.Random(0)
    value = "4532015112830366"
    sentence = get_keyword_sentence(rng, PayloadCategory.CREDIT_CARD, value)
    assert value in sentence


def test_filler_all_categories_covered():
    rng = random.Random(0)
    for cat in PayloadCategory:
        if cat == PayloadCategory.UNKNOWN:
            continue
        sentence = get_keyword_sentence(rng, cat, "TESTVALUE")
        assert "TESTVALUE" in sentence
        assert len(sentence) > 10


def test_filler_reproducible():
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    a = get_keyword_sentence(rng_a, PayloadCategory.SSN, "123-45-6789")
    b = get_keyword_sentence(rng_b, PayloadCategory.SSN, "123-45-6789")
    assert a == b
