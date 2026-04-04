from evadex.variants.bidirectional import BidirectionalGenerator, RLO, LRO, RLE, PDF, RLI, PDI, ALM

VALUE = "4111111111111111"

RLO = '\u202E'
LRO = '\u202D'
RLE = '\u202B'
PDF = '\u202C'
RLI = '\u2067'
PDI = '\u2069'
ALM = '\u061C'


def _variants(value=VALUE):
    return list(BidirectionalGenerator().generate(value))


def _get(technique, value=VALUE):
    return next(v for v in _variants(value) if v.technique == technique)


def test_generates_six_variants():
    assert len(_variants()) == 6


def test_rlo_wrap_starts_with_rlo():
    v = _get("rlo_wrap")
    assert v.value.startswith(RLO)


def test_rlo_wrap_ends_with_pdf():
    v = _get("rlo_wrap")
    assert v.value.endswith(PDF)


def test_rlo_wrap_contains_original_value():
    v = _get("rlo_wrap")
    assert VALUE in v.value


def test_lro_wrap():
    v = _get("lro_wrap")
    assert v.value.startswith(LRO)
    assert v.value.endswith(PDF)
    assert VALUE in v.value


def test_rle_embed():
    v = _get("rle_embed")
    assert v.value.startswith(RLE)
    assert v.value.endswith(PDF)
    assert VALUE in v.value


def test_mid_rlo_inject_splits_at_midpoint():
    v = _get("mid_rlo_inject")
    mid = len(VALUE) // 2
    assert v.value.startswith(VALUE[:mid])
    assert v.value[mid] == RLO
    assert VALUE[mid:] in v.value
    assert v.value.endswith(PDF)


def test_rli_isolate():
    v = _get("rli_isolate")
    assert v.value.startswith(RLI)
    assert v.value.endswith(PDI)
    assert VALUE in v.value


def test_alm_between_chars():
    v = _get("alm_between_chars")
    # ALM appears between every character: len(VALUE)-1 ALMs expected
    assert v.value.count(ALM) == len(VALUE) - 1
    # Original chars are still all present in order
    assert ''.join(c for c in v.value if c != ALM) == VALUE


def test_generator_name():
    for v in _variants():
        assert v.generator == "bidirectional"


def test_no_applicable_categories_restriction():
    gen = BidirectionalGenerator()
    assert gen.applicable_categories is None


def test_technique_names_are_unique():
    techniques = [v.technique for v in _variants()]
    assert len(techniques) == len(set(techniques))
