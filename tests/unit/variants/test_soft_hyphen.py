from evadex.variants.soft_hyphen import SoftHyphenGenerator, SHY, WJ
from evadex.core.result import PayloadCategory

CC = "4111111111111111"
SSN = "123-45-6789"

SHY = '\u00AD'
WJ  = '\u2060'


def _variants(value=CC):
    return list(SoftHyphenGenerator().generate(value))


def _get(technique, value=CC):
    return next(v for v in _variants(value) if v.technique == technique)


def test_generates_six_variants():
    assert len(_variants()) == 6


def test_shy_group_boundaries_contains_shy():
    v = _get("shy_group_boundaries")
    assert SHY in v.value


def test_shy_group_boundaries_digits_intact():
    v = _get("shy_group_boundaries")
    assert ''.join(c for c in v.value if c != SHY) == CC


def test_shy_group_boundaries_groups_of_4():
    v = _get("shy_group_boundaries")
    groups = v.value.split(SHY)
    assert all(len(g) == 4 for g in groups)


def test_shy_2char_boundaries():
    v = _get("shy_2char_boundaries")
    groups = v.value.split(SHY)
    assert all(len(g) == 2 for g in groups)


def test_shy_between_every_char():
    v = _get("shy_between_every_char")
    assert v.value.count(SHY) == len(CC) - 1
    assert ''.join(c for c in v.value if c != SHY) == CC


def test_wj_group_boundaries():
    v = _get("wj_group_boundaries")
    assert WJ in v.value
    assert SHY not in v.value
    assert ''.join(c for c in v.value if c != WJ) == CC


def test_wj_between_every_char():
    v = _get("wj_between_every_char")
    assert v.value.count(WJ) == len(CC) - 1
    assert ''.join(c for c in v.value if c != WJ) == CC


def test_mixed_shy_wj_alternates():
    v = _get("mixed_shy_wj")
    # Extract only the separator chars (positions 1, 3, 5, ... in the joined string)
    separators = [c for c in v.value if c in (SHY, WJ)]
    assert separators[0] == SHY
    assert separators[1] == WJ
    assert separators[0::2] == [SHY] * len(separators[0::2])
    assert separators[1::2] == [WJ]  * len(separators[1::2])


def test_ssn_with_dashes():
    # Hyphens in SSN should be stripped before group boundary injection
    v = _get("shy_group_boundaries", SSN)
    assert '-' not in v.value
    assert SHY in v.value


def test_generator_name():
    for v in _variants():
        assert v.generator == "soft_hyphen"


def test_applicable_to_credit_card():
    assert PayloadCategory.CREDIT_CARD in SoftHyphenGenerator().applicable_categories


def test_applicable_to_aws_key():
    assert PayloadCategory.AWS_KEY in SoftHyphenGenerator().applicable_categories


def test_not_applicable_to_jwt():
    assert PayloadCategory.JWT not in SoftHyphenGenerator().applicable_categories


def test_technique_names_are_unique():
    techniques = [v.technique for v in _variants()]
    assert len(techniques) == len(set(techniques))
