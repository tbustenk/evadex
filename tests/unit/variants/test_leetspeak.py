from evadex.variants.leetspeak import LeetspeakGenerator
from evadex.core.result import PayloadCategory


def test_minimal_leet():
    gen = LeetspeakGenerator()
    variants = list(gen.generate("test@example.com"))
    minimal = [v for v in variants if v.technique == "leet_minimal"]
    assert minimal
    assert '3' in minimal[0].value  # e -> 3


def test_not_applicable_to_credit_card():
    gen = LeetspeakGenerator()
    assert PayloadCategory.CREDIT_CARD not in gen.applicable_categories


def test_pure_digit_input_no_change():
    gen = LeetspeakGenerator()
    # Pure digits won't match leet substitutions (which target letters)
    variants = list(gen.generate("1234567890"))
    # Should yield nothing or all variants equal input
    for v in variants:
        assert v.value == "1234567890"
