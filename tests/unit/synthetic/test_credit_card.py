"""Tests for synthetic credit card generator."""
import pytest
from evadex.synthetic.credit_card import CreditCardSyntheticGenerator
from evadex.synthetic.validators import luhn_check


def _is_valid_luhn(number: str) -> bool:
    return luhn_check(number)


@pytest.fixture
def gen():
    return CreditCardSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_luhn_valid(gen):
    values = gen.generate(200, seed=42)
    for v in values:
        assert _is_valid_luhn(v), f"Luhn check failed: {v}"


def test_generate_visa_prefix(gen):
    values = gen.generate(100, seed=1)
    visa = [v for v in values if v.startswith("4") and len(v) == 16]
    assert len(visa) > 0, "Expected some Visa numbers"


def test_generate_amex_prefix(gen):
    values = gen.generate(200, seed=2)
    amex = [v for v in values if v.startswith(("34", "37")) and len(v) == 15]
    assert len(amex) > 0, "Expected some Amex numbers"


def test_generate_discover_prefix(gen):
    values = gen.generate(200, seed=3)
    discover = [v for v in values if v.startswith("6011") and len(v) == 16]
    assert len(discover) > 0, "Expected some Discover numbers"


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=99)
    b = gen.generate(30, seed=99)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b


def test_generate_all_digits(gen):
    values = gen.generate(50, seed=7)
    for v in values:
        assert v.isdigit(), f"Non-digit characters in CC: {v!r}"


def test_generate_length_15_or_16(gen):
    values = gen.generate(100, seed=8)
    for v in values:
        assert len(v) in (15, 16), f"Unexpected CC length: {len(v)}"
