"""Unit tests for wrap-context behaviour in filler.py."""
from __future__ import annotations

import random

import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.filler import get_keyword_sentence


# ── get_keyword_sentence ───────────────────────────────────────────────────────

class TestGetKeywordSentence:
    def test_value_embedded_in_sentence_en(self):
        rng = random.Random(1)
        sentence = get_keyword_sentence(rng, PayloadCategory.CREDIT_CARD, "4111111111111111")
        assert "4111111111111111" in sentence

    def test_value_embedded_in_sentence_frca(self):
        rng = random.Random(1)
        sentence = get_keyword_sentence(
            rng, PayloadCategory.CREDIT_CARD, "4111111111111111", language="fr-CA"
        )
        assert "4111111111111111" in sentence

    def test_sentence_not_just_value(self):
        """The sentence must contain more than just the bare value."""
        rng = random.Random(1)
        value = "4111111111111111"
        sentence = get_keyword_sentence(rng, PayloadCategory.CREDIT_CARD, value)
        assert sentence != value
        assert len(sentence) > len(value) + 2

    def test_unknown_category_uses_fallback(self):
        """Categories without a template should fall back gracefully."""
        rng = random.Random(1)
        sentence = get_keyword_sentence(rng, PayloadCategory.UNKNOWN, "TEST-VALUE")
        assert "TEST-VALUE" in sentence

    def test_all_en_categories_produce_output(self):
        rng = random.Random(42)
        for cat in PayloadCategory:
            sentence = get_keyword_sentence(rng, cat, "TESTVAL")
            assert "TESTVAL" in sentence, f"Value not embedded for category {cat}"
            assert len(sentence) > 5

    def test_all_frca_categories_produce_output(self):
        rng = random.Random(42)
        for cat in PayloadCategory:
            sentence = get_keyword_sentence(rng, cat, "TESTVAL", language="fr-CA")
            assert "TESTVAL" in sentence, f"Value not embedded for fr-CA category {cat}"

    def test_frca_sentences_encode_to_latin1(self):
        """All fr-CA sentences must survive Latin-1 encoding (for PDF writer)."""
        rng = random.Random(42)
        for cat in PayloadCategory:
            for _ in range(10):
                sentence = get_keyword_sentence(rng, cat, "TESTVAL", language="fr-CA")
                # Apply the same mapping as pdf_writer._safe
                mapped = (
                    sentence
                    .replace("\u2014", "--")
                    .replace("\u2013", "-")
                    .replace("\u2018", "'")
                    .replace("\u2019", "'")
                    .replace("\u201c", '"')
                    .replace("\u201d", '"')
                )
                try:
                    mapped.encode("latin-1")
                except UnicodeEncodeError as e:
                    pytest.fail(
                        f"fr-CA sentence for {cat} not Latin-1 safe after mapping: {e}\n"
                        f"Sentence: {sentence!r}"
                    )

    def test_seed_reproducibility(self):
        rng_a = random.Random(99)
        rng_b = random.Random(99)
        for cat in [PayloadCategory.CREDIT_CARD, PayloadCategory.SSN, PayloadCategory.IBAN]:
            a = get_keyword_sentence(rng_a, cat, "VAL123")
            b = get_keyword_sentence(rng_b, cat, "VAL123")
            assert a == b

    def test_different_seeds_produce_varied_output(self):
        """Multiple draws from the same category should produce different sentences
        (for categories with ≥ 2 templates)."""
        rng = random.Random(0)
        sentences = {
            get_keyword_sentence(rng, PayloadCategory.CREDIT_CARD, "4111111111111111")
            for _ in range(20)
        }
        # With 12+ templates there should be at least 3 distinct sentences in 20 draws
        assert len(sentences) >= 3
