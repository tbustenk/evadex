"""Tests for false positive generators — values that look sensitive but aren't."""
import re

import pytest

from evadex.falsepos.generators import (
    generate_false_credit_cards,
    generate_false_ssns,
    generate_false_sins,
    generate_false_ibans,
    generate_false_emails,
    generate_false_phones,
    generate_false_ramqs,
    is_match_relevant,
    FALSEPOS_GENERATORS,
    RELEVANT_SCANNER_LABELS,
)
from evadex.synthetic.validators import luhn_check, sin_valid, iban_valid


# ── Credit card ───────────────────────────────────────────────────────────────

def test_false_credit_cards_count():
    assert len(generate_false_credit_cards(50, seed=0)) == 50


def test_false_credit_cards_fail_luhn():
    for v in generate_false_credit_cards(100, seed=1):
        assert not luhn_check(v), f"Expected Luhn failure for {v!r}"


def test_false_credit_cards_16_digits():
    for v in generate_false_credit_cards(20, seed=2):
        assert v.isdigit() and len(v) == 16, f"Expected 16 digits: {v!r}"


def test_false_credit_cards_seeded():
    assert generate_false_credit_cards(10, seed=42) == generate_false_credit_cards(10, seed=42)


# ── SSN ───────────────────────────────────────────────────────────────────────

_INVALID_SSN_AREAS = {"000", "666"} | {f"{n:03d}" for n in range(900, 1000)}

def test_false_ssns_count():
    assert len(generate_false_ssns(50, seed=0)) == 50


def test_false_ssns_format():
    pattern = re.compile(r'^\d{3}-\d{2}-\d{4}$')
    for v in generate_false_ssns(20, seed=3):
        assert pattern.match(v), f"SSN format mismatch: {v!r}"


def test_false_ssns_invalid_area_codes():
    for v in generate_false_ssns(100, seed=4):
        area = v.split("-")[0]
        assert area in _INVALID_SSN_AREAS, f"Expected invalid area code in {v!r}"


# ── SIN ───────────────────────────────────────────────────────────────────────

def test_false_sins_count():
    assert len(generate_false_sins(50, seed=0)) == 50


def test_false_sins_format():
    pattern = re.compile(r'^\d{3} \d{3} \d{3}$')
    for v in generate_false_sins(20, seed=5):
        assert pattern.match(v), f"SIN format mismatch: {v!r}"


def test_false_sins_fail_checksum():
    for v in generate_false_sins(100, seed=6):
        assert not sin_valid(v.replace(" ", "")), f"Expected SIN checksum failure for {v!r}"


def test_false_sins_valid_first_digit():
    """First digit should still be in 1-7 (looks realistic)."""
    for v in generate_false_sins(20, seed=7):
        assert v[0] in "1234567", f"Unexpected first digit in {v!r}"


# ── IBAN ──────────────────────────────────────────────────────────────────────

def test_false_ibans_count():
    assert len(generate_false_ibans(50, seed=0)) == 50


def test_false_ibans_fail_checksum():
    for v in generate_false_ibans(100, seed=8):
        assert not iban_valid(v), f"Expected IBAN checksum failure for {v!r}"


def test_false_ibans_known_country_prefix():
    valid_prefixes = {"GB", "DE", "FR"}
    for v in generate_false_ibans(20, seed=9):
        assert v[:2] in valid_prefixes, f"Unexpected country code in {v!r}"


# ── Email ─────────────────────────────────────────────────────────────────────

def test_false_emails_count():
    assert len(generate_false_emails(50, seed=0)) == 50


def test_false_emails_have_at_symbol():
    for v in generate_false_emails(20, seed=10):
        assert "@" in v, f"Expected @ in {v!r}"


def test_false_emails_invalid_tld():
    _INVALID_TLDS = {".invalid", ".test", ".example", ".localhost", ".local",
                     ".123", ".x"}
    for v in generate_false_emails(100, seed=11):
        domain_part = v.split("@")[1]
        has_invalid_tld = any(domain_part.endswith(tld) for tld in _INVALID_TLDS)
        assert has_invalid_tld, f"Expected invalid TLD in {v!r}"


# ── Phone ─────────────────────────────────────────────────────────────────────

def test_false_phones_count():
    assert len(generate_false_phones(50, seed=0)) == 50


def test_false_phones_start_with_plus1():
    for v in generate_false_phones(20, seed=12):
        assert v.startswith("+1-"), f"Expected +1- prefix in {v!r}"


def test_false_phones_invalid_area_codes():
    _INVALID = {"000", "001", "011", "100", "101", "111",
                "200", "201", "211", "300", "400",
                "500", "555", "600", "700", "800", "900", "911"}
    for v in generate_false_phones(50, seed=13):
        area = v.split("-")[1]
        assert area in _INVALID, f"Expected invalid area code in {v!r}"


# ── CA RAMQ ───────────────────────────────────────────────────────────────────

_VALID_MONTHS = set(range(1, 13)) | set(range(51, 63))

def test_false_ramqs_count():
    assert len(generate_false_ramqs(50, seed=0)) == 50


def test_false_ramqs_format():
    pattern = re.compile(r'^[A-Z]{4} \d{4} \d{4}$')
    for v in generate_false_ramqs(20, seed=14):
        assert pattern.match(v), f"RAMQ format mismatch: {v!r}"


def test_false_ramqs_invalid_month():
    """All generated RAMQ values should have invalid birth month codes."""
    for v in generate_false_ramqs(100, seed=15):
        # format: ABCD YYMM DDSS → digits portion is index 5 onward (after "ABCD ")
        # YYMM occupies positions 5-8 in the full string (after the "ABCD ")
        digits = v.replace(" ", "")[4:]  # strip 4-letter name prefix
        month = int(digits[2:4])
        assert month not in _VALID_MONTHS, (
            f"Month {month} is valid but should be invalid in {v!r}"
        )


# ── Registry ──────────────────────────────────────────────────────────────────

def test_all_expected_categories_in_registry():
    expected = {"credit_card", "ssn", "sin", "iban", "email", "phone", "ca_ramq"}
    assert expected.issubset(FALSEPOS_GENERATORS.keys())


def test_all_generators_callable():
    for name, fn in FALSEPOS_GENERATORS.items():
        values = fn(5, seed=0)
        assert len(values) == 5, f"{name}: expected 5 values, got {len(values)}"


# ── Category-relevance filter ────────────────────────────────────────────────

def test_relevant_map_covers_generators():
    """Every FP-generator category should have a relevance list. Missing
    entries default to 'any match counts' — safe, but the whole point of
    the map is to prevent that."""
    missing = set(FALSEPOS_GENERATORS.keys()) - set(RELEVANT_SCANNER_LABELS.keys())
    assert not missing, f"Generators without relevance entries: {missing}"


def test_on_target_match_counts():
    m = {"category": "North America - United States", "sub_category": "USA SSN"}
    assert is_match_relevant("ssn", m) is True


def test_off_target_match_does_not_count():
    # Corporate-Classification "Do Not Distribute" fires on wrap-template
    # prose ("please handle with care and do not distribute"). It must NOT
    # be counted as an SSN false positive.
    m = {"category": "Corporate Classification", "sub_category": "Do Not Distribute"}
    assert is_match_relevant("ssn", m) is False


def test_mrn_does_not_count_as_ramq_fp():
    # Siphon's Medical Record Number rule fires on the RAMQ digit portion
    # when French medical-context keywords are in the wrap. That is not a
    # Quebec HC false positive.
    m = {"category": "Medical Identifiers", "sub_category": "Medical Record Number"}
    assert is_match_relevant("ca_ramq", m) is False


def test_case_insensitive_match():
    m = {"category": "Credit Card Numbers", "sub_category": "VISA"}
    assert is_match_relevant("credit_card", m) is True


def test_category_fallback_when_subcategory_missing():
    # Some scanner matches only set 'category' (no sub_category). The
    # filter should still accept them when the category is on the list.
    m = {"category": "Credit Card Numbers"}
    assert is_match_relevant("credit_card", m) is True


def test_unknown_category_defaults_to_permissive():
    # A category that has no entry in RELEVANT_SCANNER_LABELS falls back
    # to accepting any match (preserves backwards compatibility).
    m = {"category": "whatever", "sub_category": "whatever"}
    assert is_match_relevant("not_a_real_evadex_category", m) is True
