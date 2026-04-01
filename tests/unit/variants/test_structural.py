from evadex.variants.structural import StructuralGenerator


def test_padding_variants():
    gen = StructuralGenerator()
    variants = list(gen.generate("4532015112830366"))
    techniques = {v.technique for v in variants}
    assert "left_pad_spaces" in techniques
    assert "right_pad_spaces" in techniques
    assert "left_pad_zeros" in techniques


def test_partial_variants():
    gen = StructuralGenerator()
    variants = list(gen.generate("4532015112830366"))
    partial = [v for v in variants if v.technique == "partial_first_half"]
    assert partial
    assert len(partial[0].value) < len("4532015112830366")


def test_case_variants():
    gen = StructuralGenerator()
    variants = list(gen.generate("AKIAIOSFODNN7EXAMPLE"))
    lower = [v for v in variants if v.technique == "lowercase"]
    assert lower
    assert lower[0].value == "akiaiosfodnn7example"
