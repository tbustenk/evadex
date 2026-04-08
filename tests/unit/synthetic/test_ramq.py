"""Tests for synthetic Quebec RAMQ health card generator."""
import re
import pytest
from evadex.synthetic.ramq import RAMQSyntheticGenerator

# RAMQ pattern: 4 uppercase letters, space, 4 digits, space, 4 digits
_RAMQ_RE = re.compile(r'^[A-Z]{4} \d{4} \d{4}$')


@pytest.fixture
def gen():
    return RAMQSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_match_format(gen):
    values = gen.generate(200, seed=42)
    for v in values:
        assert _RAMQ_RE.match(v), f"RAMQ format mismatch: {v!r}"


def test_generate_name_prefix_uppercase(gen):
    values = gen.generate(50, seed=1)
    for v in values:
        prefix = v[:4]
        assert prefix.isupper() and prefix.isalpha(), f"Name prefix not uppercase alpha: {v!r}"


def test_generate_digit_groups_valid(gen):
    values = gen.generate(50, seed=2)
    for v in values:
        _, grp1, grp2 = v.split(" ")
        assert grp1.isdigit() and len(grp1) == 4
        assert grp2.isdigit() and len(grp2) == 4


def test_generate_month_in_valid_range(gen):
    """Month field (digits 3-4 of numeric part) should be 01-12 (male) or 51-62 (female)."""
    values = gen.generate(500, seed=3)
    for v in values:
        _, grp1, _ = v.split(" ")
        month = int(grp1[2:4])
        assert (1 <= month <= 12) or (51 <= month <= 62), (
            f"Month out of range for RAMQ: {month} in {v!r}"
        )


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=99)
    b = gen.generate(30, seed=99)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b
