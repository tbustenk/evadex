"""Tests for synthetic email address generator."""
import pytest
from evadex.synthetic.email import EmailSyntheticGenerator


@pytest.fixture
def gen():
    return EmailSyntheticGenerator()


def test_generate_returns_correct_count(gen):
    assert len(gen.generate(50)) == 50


def test_generate_all_valid_email_format(gen):
    values = gen.generate(200, seed=42)
    for v in values:
        assert "@" in v, f"Missing @ in email: {v!r}"
        local, domain = v.split("@", 1)
        assert local, f"Empty local part: {v!r}"
        assert "." in domain, f"Domain has no dot: {v!r}"


def test_generate_seed_reproducible(gen):
    a = gen.generate(30, seed=99)
    b = gen.generate(30, seed=99)
    assert a == b


def test_generate_different_seeds_differ(gen):
    a = gen.generate(30, seed=1)
    b = gen.generate(30, seed=2)
    assert a != b


def test_generate_includes_canadian_domains(gen):
    values = gen.generate(500, seed=5)
    ca_domains = {"yahoo.ca", "bell.ca", "rogers.com", "telus.net", "shaw.ca",
                  "videotron.ca", "cogeco.ca", "sympatico.ca"}
    found = {v.split("@")[1] for v in values}
    assert found & ca_domains, f"Expected at least one Canadian domain, got: {found}"


def test_generate_all_lowercase(gen):
    values = gen.generate(50, seed=3)
    for v in values:
        assert v == v.lower(), f"Email should be lowercase: {v!r}"
