"""Tests for synthetic Canadian phone number generator."""
import pytest
from evadex.synthetic.phone import CanadianPhoneSyntheticGenerator


@pytest.fixture
def gen():
    return CanadianPhoneSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_start_with_canada_country_code(gen):
    values = gen.generate(100, seed=42)
    for v in values:
        assert v.startswith("+1-"), f"Expected +1- prefix: {v!r}"


def test_generate_format_e164_like(gen):
    values = gen.generate(100, seed=1)
    for v in values:
        parts = v.split("-")
        assert len(parts) == 4, f"Expected +1-NPA-NXX-XXXX format: {v!r}"
        assert parts[0] == "+1"
        assert parts[1].isdigit() and len(parts[1]) == 3
        assert parts[2].isdigit() and len(parts[2]) == 3
        assert parts[3].isdigit() and len(parts[3]) == 4


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=77)
    b = gen.generate(30, seed=77)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b


def test_generate_all_distinct_or_large_set(gen):
    # With 500 values and a real RNG, expect significant diversity
    values = gen.generate(500, seed=5)
    unique = set(values)
    assert len(unique) > 100, f"Expected diverse output, got {len(unique)} unique values"
