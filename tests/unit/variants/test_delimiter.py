from evadex.variants.delimiter import DelimiterGenerator
from evadex.core.result import PayloadCategory


def test_no_delimiter():
    gen = DelimiterGenerator()
    variants = list(gen.generate("4532-0151-1283-0366"))
    no_delim = [v for v in variants if v.technique == "no_delimiter"]
    assert no_delim
    assert no_delim[0].value == "4532015112830366"


def test_space_delimiter():
    gen = DelimiterGenerator()
    variants = list(gen.generate("4532015112830366"))
    space = [v for v in variants if v.technique == "space_delimiter"]
    assert space
    assert ' ' in space[0].value


def test_not_applicable_to_jwt():
    gen = DelimiterGenerator()
    assert PayloadCategory.JWT not in gen.applicable_categories


def test_applicable_to_credit_card():
    gen = DelimiterGenerator()
    assert PayloadCategory.CREDIT_CARD in gen.applicable_categories
