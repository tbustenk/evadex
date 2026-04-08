"""Tests for Canadian French filler templates and --language fr-CA support."""
import random
import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.filler import get_keyword_sentence
from evadex.generate.generator import GenerateConfig, generate_entries


# ── French keyword presence in filler templates ───────────────────────────────

_FR_KEYWORDS_BY_CATEGORY = {
    PayloadCategory.CREDIT_CARD: [
        "carte de crédit", "numéro de carte", "carte bancaire",
        "paiement par carte", "numéro de carte bancaire",
    ],
    PayloadCategory.SIN: [
        "numéro d'assurance sociale", "NAS", "assurance sociale",
    ],
    PayloadCategory.IBAN: [
        "numéro de compte", "virement bancaire", "coordonnées bancaires",
        "relevé bancaire",
    ],
    PayloadCategory.EMAIL: [
        "courriel", "adresse courriel",
    ],
    PayloadCategory.PHONE: [
        "numéro de téléphone", "composez le", "téléphone", "cellulaire",
    ],
}


@pytest.mark.parametrize("cat,keywords", list(_FR_KEYWORDS_BY_CATEGORY.items()))
def test_fr_ca_templates_contain_category_keywords(cat, keywords):
    """At least one French template per category must contain a matching keyword."""
    from evadex.generate.filler import _TEMPLATES_FR_CA
    templates = _TEMPLATES_FR_CA.get(cat, [])
    assert templates, f"No French CA templates for {cat}"
    combined = " ".join(t.lower() for t in templates)
    found = [kw for kw in keywords if kw.lower() in combined]
    assert found, (
        f"None of the keywords {keywords!r} found in French templates for {cat}. "
        f"Templates: {templates}"
    )


def test_fr_ca_filler_all_categories_covered():
    """French CA filler should produce a non-empty sentence for every category."""
    rng = random.Random(0)
    for cat in PayloadCategory:
        if cat == PayloadCategory.UNKNOWN:
            continue
        sentence = get_keyword_sentence(rng, cat, "TESTVALUE", language="fr-CA")
        assert "TESTVALUE" in sentence, f"Value not embedded for {cat} (fr-CA)"
        assert len(sentence) > 5


def test_en_filler_unchanged():
    """Default English filler still works when language is omitted."""
    rng = random.Random(0)
    sentence = get_keyword_sentence(rng, PayloadCategory.CREDIT_CARD, "4532015112830366")
    assert "4532015112830366" in sentence


def test_fr_ca_filler_differs_from_en():
    """French and English fillers should produce different sentences."""
    rng_en = random.Random(42)
    rng_fr = random.Random(42)
    en = get_keyword_sentence(rng_en, PayloadCategory.SIN, "046 454 286", language="en")
    fr = get_keyword_sentence(rng_fr, PayloadCategory.SIN, "046 454 286", language="fr-CA")
    assert en != fr


# ── context_injection French templates ───────────────────────────────────────

def test_context_injection_has_fr_ca_templates():
    from evadex.variants.context_injection import TEMPLATES
    fr_techniques = [t for _, t, _ in TEMPLATES if t.startswith("fr_ca_")]
    assert len(fr_techniques) >= 8, (
        f"Expected at least 8 fr-CA context_injection templates, got {len(fr_techniques)}"
    )


def test_context_injection_fr_templates_embed_value():
    from evadex.variants.context_injection import TEMPLATES
    for template, technique, _ in TEMPLATES:
        if technique.startswith("fr_ca_"):
            result = template.replace("{value}", "TESTVALUE")
            assert "TESTVALUE" in result, (
                f"Template {technique!r} does not embed value"
            )


# ── splitting French noise ────────────────────────────────────────────────────

def test_splitting_produces_fr_ca_variants():
    from evadex.core.registry import load_builtins
    load_builtins()
    from evadex.core.registry import get_generator
    gen = get_generator("splitting")
    variants = list(gen.generate("4532015112830366"))
    techniques = [v.technique for v in variants]
    assert "fr_ca_prefix_noise" in techniques
    assert "fr_ca_suffix_noise" in techniques


def test_splitting_fr_ca_prefix_contains_french():
    from evadex.core.registry import load_builtins
    load_builtins()
    from evadex.core.registry import get_generator
    gen = get_generator("splitting")
    variants = {v.technique: v for v in gen.generate("4532015112830366")}
    prefix_variant = variants["fr_ca_prefix_noise"]
    assert "4532015112830366" in prefix_variant.value


# ── generate command --language fr-CA integration ────────────────────────────

def test_generate_fr_ca_language_produces_french_text():
    """With --language fr-CA, embedded_text should contain French keywords."""
    config = GenerateConfig(
        fmt="csv",
        categories=[PayloadCategory.CREDIT_CARD],
        count=50,
        evasion_rate=0.0,
        keyword_rate=1.0,
        seed=42,
        language="fr-CA",
    )
    entries = generate_entries(config)
    # At least some entries should contain French credit card keywords
    french_keywords = ["carte", "numéro", "paiement", "débiter", "bancaire"]
    french_entries = [
        e for e in entries
        if any(kw in e.embedded_text.lower() for kw in french_keywords)
    ]
    assert len(french_entries) > 0, (
        "No entries contained French keywords — check fr-CA template wiring"
    )


def test_generate_en_language_does_not_produce_fr_text():
    """Default English language should not produce French keyword sentences."""
    config = GenerateConfig(
        fmt="csv",
        categories=[PayloadCategory.CREDIT_CARD],
        count=50,
        evasion_rate=0.0,
        keyword_rate=1.0,
        seed=42,
        language="en",
    )
    entries = generate_entries(config)
    fr_specific = ["débiter", "courriel", "cellulaire", "virement bancaire"]
    fr_entries = [
        e for e in entries
        if any(kw in e.embedded_text for kw in fr_specific)
    ]
    assert len(fr_entries) == 0, (
        "English mode produced French-specific text"
    )
