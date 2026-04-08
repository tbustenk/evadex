"""Tests for synthetic Canadian SIN generator."""
import pytest
from evadex.synthetic.sin import SINSyntheticGenerator
from evadex.synthetic.validators import sin_valid, luhn_check


@pytest.fixture
def gen():
    return SINSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_sin_valid(gen):
    values = gen.generate(200, seed=42)
    for v in values:
        digits = v.replace(" ", "")
        assert sin_valid(digits), f"SIN checksum failed: {v}"


def test_generate_format_nnn_nnn_nnn(gen):
    values = gen.generate(50, seed=1)
    for v in values:
        parts = v.split(" ")
        assert len(parts) == 3, f"Expected 3 space-separated groups: {v!r}"
        assert all(len(p) == 3 and p.isdigit() for p in parts), (
            f"Expected NNN NNN NNN format: {v!r}"
        )


def test_generate_first_digit_not_zero(gen):
    values = gen.generate(100, seed=2)
    for v in values:
        assert v[0] != "0", f"SIN should not start with 0: {v}"


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=77)
    b = gen.generate(30, seed=77)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b


def test_generate_nine_digits_total(gen):
    values = gen.generate(50, seed=5)
    for v in values:
        digits = v.replace(" ", "")
        assert len(digits) == 9 and digits.isdigit(), f"Expected 9 digits: {v!r}"
