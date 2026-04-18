"""Unit tests for the barcode_evasion variant generator.

The generator produces four variants per value. They're mostly markers
that the barcode writer interprets at image-render time, but they also
need to work as plain text variants (different strings, tracked in
results) so the pipeline is uniform.
"""
import pytest

from evadex.variants.barcode_evasion import (
    BARCODE_EVASION_TECHNIQUES,
    BarcodeEvasionGenerator,
)


SEED_VALUE = "4532015112830366"


@pytest.fixture
def gen():
    return BarcodeEvasionGenerator()


def test_generator_emits_all_four_techniques(gen):
    techniques = [v.technique for v in gen.generate(SEED_VALUE)]
    assert set(techniques) == set(BARCODE_EVASION_TECHNIQUES)
    assert len(techniques) == 4


def test_generator_variants_have_distinct_values(gen):
    """Each technique must produce a string distinct from the others."""
    values = [v.value for v in gen.generate(SEED_VALUE)]
    assert len(set(values)) == 4


def test_barcode_split_uses_record_separator(gen):
    """Split marker must be ASCII \\x1e (record separator), NOT a newline —
    a newline would inflate line counts in CSV/JSON/log pipelines."""
    variants = {v.technique: v for v in gen.generate(SEED_VALUE)}
    split = variants["barcode_split"].value
    assert "\n" not in split, "split marker must not break lines in text output"
    assert "\x1e" in split
    left, right = split.split("\x1e", 1)
    assert left + right == SEED_VALUE


def test_barcode_noise_preserves_logical_value(gen):
    """Noise variant just tags the value with a zero-width space."""
    variants = {v.technique: v for v in gen.generate(SEED_VALUE)}
    noise = variants["barcode_noise"].value
    # Strip zero-width chars and we should have the original back.
    stripped = noise.replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    assert stripped == SEED_VALUE


def test_empty_value_emits_nothing(gen):
    assert list(gen.generate("")) == []


def test_applies_to_all_categories(gen):
    # Barcodes can encode any category — the generator should not restrict.
    assert gen.applicable_categories is None


def test_generator_registered():
    """Registry import side-effect should make the generator discoverable."""
    from evadex.core.registry import _GENERATORS, load_builtins
    load_builtins()
    assert "barcode_evasion" in _GENERATORS
