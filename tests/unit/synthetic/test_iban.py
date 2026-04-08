"""Tests for synthetic IBAN generator."""
import pytest
from evadex.synthetic.iban import IBANSyntheticGenerator
from evadex.synthetic.validators import iban_valid


@pytest.fixture
def gen():
    return IBANSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_iban_checksums_valid(gen):
    values = gen.generate(300, seed=42)
    for v in values:
        assert iban_valid(v), f"IBAN checksum failed: {v}"


def test_generate_gb_format(gen):
    values = gen.generate(300, seed=1)
    gb = [v for v in values if v.startswith("GB")]
    assert len(gb) > 0
    for v in gb:
        assert len(v) == 22, f"GB IBAN should be 22 chars: {v}"


def test_generate_de_format(gen):
    values = gen.generate(300, seed=2)
    de = [v for v in values if v.startswith("DE")]
    assert len(de) > 0
    for v in de:
        assert len(v) == 22, f"DE IBAN should be 22 chars: {v}"


def test_generate_fr_format(gen):
    values = gen.generate(300, seed=3)
    fr = [v for v in values if v.startswith("FR")]
    assert len(fr) > 0
    for v in fr:
        assert len(v) == 27, f"FR IBAN should be 27 chars: {v}"


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=99)
    b = gen.generate(30, seed=99)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b
