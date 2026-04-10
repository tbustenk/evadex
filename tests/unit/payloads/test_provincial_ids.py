"""Tests for remaining Canadian provincial ID payloads and their synthetic generators."""
import re
import pytest
from evadex.payloads.builtins import get_payloads
from evadex.core.result import PayloadCategory, CATEGORY_TYPES, CategoryType


# ── Health cards ─────────────────────────────────────────────────────────────

def test_mb_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_MB_HEALTH})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 9, (
            f"MB health card should be 9 digits: {p.value!r}"
        )


def test_sk_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_SK_HEALTH})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 9, (
            f"SK health card should be 9 digits: {p.value!r}"
        )


def test_ns_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NS_HEALTH})
    assert payloads
    pattern = re.compile(r'^\d{4} \d{3} \d{3}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"NS health card should be NNNN NNN NNN: {p.value!r}"
        )


def test_nb_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NB_HEALTH})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 10, (
            f"NB health card should be 10 digits: {p.value!r}"
        )


def test_pei_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_PEI_HEALTH})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 12, (
            f"PEI health card should be 12 digits: {p.value!r}"
        )


def test_nl_health_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NL_HEALTH})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 10, (
            f"NL health card should be 10 digits: {p.value!r}"
        )


# ── Driver's licences ─────────────────────────────────────────────────────────

def test_mb_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_MB_DRIVERS})
    assert payloads
    pattern = re.compile(r'^[A-Z]{2}-\d{3}-\d{3}-\d{3}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"MB driver's licence should be LL-NNN-NNN-NNN: {p.value!r}"
        )


def test_sk_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_SK_DRIVERS})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 8, (
            f"SK driver's licence should be 8 digits: {p.value!r}"
        )


def test_ns_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NS_DRIVERS})
    assert payloads
    pattern = re.compile(r'^[A-Z]{2}\d{7}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"NS driver's licence should be LL + 7 digits: {p.value!r}"
        )


def test_nb_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NB_DRIVERS})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 7, (
            f"NB driver's licence should be 7 digits: {p.value!r}"
        )


def test_pei_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_PEI_DRIVERS})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 6, (
            f"PEI driver's licence should be 6 digits: {p.value!r}"
        )


def test_nl_drivers_payload_format():
    payloads = get_payloads({PayloadCategory.CA_NL_DRIVERS})
    assert payloads
    pattern = re.compile(r'^[A-Z]\d{9}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"NL driver's licence should be 1 letter + 9 digits: {p.value!r}"
        )


# ── Corporate identifiers ────────────────────────────────────────────────────

def test_business_number_payload_format():
    payloads = get_payloads({PayloadCategory.CA_BUSINESS_NUMBER})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and len(p.value) == 9, (
            f"Business Number should be 9 digits: {p.value!r}"
        )


def test_gst_hst_payload_format():
    payloads = get_payloads({PayloadCategory.CA_GST_HST})
    assert payloads
    pattern = re.compile(r'^\d{9}RT\d{4}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"GST/HST should be 9 digits + RT + 4 digits: {p.value!r}"
        )


def test_transit_number_payload_format():
    payloads = get_payloads({PayloadCategory.CA_TRANSIT_NUMBER})
    assert payloads
    pattern = re.compile(r'^\d{5}-\d{3}$')
    for p in payloads:
        assert pattern.match(p.value), (
            f"Transit number should be NNNNN-NNN: {p.value!r}"
        )


def test_bank_account_payload_format():
    payloads = get_payloads({PayloadCategory.CA_BANK_ACCOUNT})
    assert payloads
    for p in payloads:
        assert p.value.isdigit() and 7 <= len(p.value) <= 12, (
            f"Bank account should be 7-12 digits: {p.value!r}"
        )


# ── All new categories are STRUCTURED ────────────────────────────────────────

_NEW_CATS = [
    PayloadCategory.CA_MB_HEALTH,
    PayloadCategory.CA_SK_HEALTH,
    PayloadCategory.CA_NS_HEALTH,
    PayloadCategory.CA_NB_HEALTH,
    PayloadCategory.CA_PEI_HEALTH,
    PayloadCategory.CA_NL_HEALTH,
    PayloadCategory.CA_MB_DRIVERS,
    PayloadCategory.CA_SK_DRIVERS,
    PayloadCategory.CA_NS_DRIVERS,
    PayloadCategory.CA_NB_DRIVERS,
    PayloadCategory.CA_PEI_DRIVERS,
    PayloadCategory.CA_NL_DRIVERS,
    PayloadCategory.CA_BUSINESS_NUMBER,
    PayloadCategory.CA_GST_HST,
    PayloadCategory.CA_TRANSIT_NUMBER,
    PayloadCategory.CA_BANK_ACCOUNT,
]


def test_all_new_categories_are_structured():
    for cat in _NEW_CATS:
        assert CATEGORY_TYPES[cat] == CategoryType.STRUCTURED, (
            f"{cat} should be STRUCTURED"
        )


def test_all_new_categories_have_payloads():
    for cat in _NEW_CATS:
        payloads = get_payloads({cat})
        assert payloads, f"No built-in payload for {cat}"


def test_new_categories_delimiter_variants():
    """All new Canadian ID categories should produce delimiter variants."""
    from evadex.core.registry import load_builtins, get_generator
    load_builtins()
    gen = get_generator("delimiter")
    for cat in _NEW_CATS:
        payloads = get_payloads({cat})
        value = payloads[0].value
        variants = list(gen.generate(value))
        assert variants, f"No delimiter variants for {cat} value {value!r}"


# ── Synthetic generators ──────────────────────────────────────────────────────

def _get_synthetic(cat):
    from evadex.synthetic.registry import load_synthetic_generators, get_synthetic_generator
    load_synthetic_generators()
    return get_synthetic_generator(cat)


@pytest.mark.parametrize("cat,expected_len,strip_spaces", [
    (PayloadCategory.CA_MB_HEALTH, 9, True),
    (PayloadCategory.CA_SK_HEALTH, 9, True),
    (PayloadCategory.CA_NB_HEALTH, 10, True),
    (PayloadCategory.CA_PEI_HEALTH, 12, True),
    (PayloadCategory.CA_NL_HEALTH, 10, True),
])
def test_health_card_synthetic_digit_length(cat, expected_len, strip_spaces):
    gen = _get_synthetic(cat)
    assert gen is not None, f"No synthetic generator for {cat}"
    values = gen.generate(10, seed=0)
    assert len(values) == 10
    for v in values:
        digits = v.replace(" ", "")
        assert digits.isdigit() and len(digits) == expected_len, (
            f"{cat}: expected {expected_len} digits, got {v!r}"
        )


def test_ns_health_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_NS_HEALTH)
    assert gen is not None
    pattern = re.compile(r'^\d{4} \d{3} \d{3}$')
    for v in gen.generate(20, seed=1):
        assert pattern.match(v), f"NS health card format mismatch: {v!r}"


def test_mb_drivers_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_MB_DRIVERS)
    assert gen is not None
    pattern = re.compile(r'^[A-Z]{2}-\d{3}-\d{3}-\d{3}$')
    for v in gen.generate(20, seed=2):
        assert pattern.match(v), f"MB driver's licence format mismatch: {v!r}"


def test_ns_drivers_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_NS_DRIVERS)
    assert gen is not None
    pattern = re.compile(r'^[A-Z]{2}\d{7}$')
    for v in gen.generate(20, seed=3):
        assert pattern.match(v), f"NS driver's licence format mismatch: {v!r}"


def test_nl_drivers_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_NL_DRIVERS)
    assert gen is not None
    pattern = re.compile(r'^[A-Z]\d{9}$')
    for v in gen.generate(20, seed=4):
        assert pattern.match(v), f"NL driver's licence format mismatch: {v!r}"


def test_gst_hst_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_GST_HST)
    assert gen is not None
    pattern = re.compile(r'^\d{9}RT\d{4}$')
    for v in gen.generate(20, seed=5):
        assert pattern.match(v), f"GST/HST format mismatch: {v!r}"


def test_transit_number_synthetic_format():
    gen = _get_synthetic(PayloadCategory.CA_TRANSIT_NUMBER)
    assert gen is not None
    pattern = re.compile(r'^\d{5}-\d{3}$')
    for v in gen.generate(20, seed=6):
        assert pattern.match(v), f"Transit number format mismatch: {v!r}"


def test_bank_account_synthetic_length():
    gen = _get_synthetic(PayloadCategory.CA_BANK_ACCOUNT)
    assert gen is not None
    for v in gen.generate(50, seed=7):
        assert v.isdigit() and 7 <= len(v) <= 12, (
            f"Bank account should be 7-12 digits: {v!r}"
        )


def test_synthetic_generators_are_seeded():
    """Same seed should produce same values."""
    gen = _get_synthetic(PayloadCategory.CA_MB_HEALTH)
    assert gen.generate(5, seed=99) == gen.generate(5, seed=99)
