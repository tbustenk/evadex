from evadex.variants.unicode_encoding import UnicodeEncodingGenerator


def test_generates_variants(visa_payload):
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    assert len(variants) > 5


def test_zero_width_variants():
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    zw_variants = [v for v in variants if "zero_width" in v.technique]
    assert len(zw_variants) == 3  # ZWSP, ZWNJ, ZWJ


def test_zero_width_technique_names_are_unique():
    """Each zero-width variant must have its own technique name."""
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    zw_techniques = [v.technique for v in variants if "zero_width" in v.technique]
    assert len(zw_techniques) == len(set(zw_techniques)), "Duplicate zero-width technique names"
    assert "zero_width_zwsp" in zw_techniques
    assert "zero_width_zwnj" in zw_techniques
    assert "zero_width_zwj" in zw_techniques


def test_fullwidth_digits():
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    fw = [v for v in variants if v.technique == "fullwidth_digits"]
    assert fw
    assert '\uFF14' in fw[0].value  # fullwidth '4'


def test_homoglyph_substitution():
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    hg = [v for v in variants if v.technique == "homoglyph_substitution"]
    assert hg
    assert hg[0].value != "4532015112830366"


def test_url_encoding_full():
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("4532"))
    url = [v for v in variants if v.technique == "url_percent_encoding_full"]
    assert url
    assert url[0].value == "%34%35%33%32"


def test_html_entity_decimal():
    gen = UnicodeEncodingGenerator()
    variants = list(gen.generate("AB"))
    ent = [v for v in variants if v.technique == "html_entity_decimal"]
    assert ent
    assert "&#65;" in ent[0].value


def test_all_variants_have_metadata():
    gen = UnicodeEncodingGenerator()
    for v in gen.generate("test@example.com"):
        assert v.generator == "unicode_encoding"
        assert v.technique
        assert v.transform_name
