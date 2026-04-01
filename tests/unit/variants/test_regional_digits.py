from evadex.variants.regional_digits import RegionalDigitsGenerator


def test_arabic_indic():
    gen = RegionalDigitsGenerator()
    variants = list(gen.generate("123"))
    arabic = [v for v in variants if v.technique == "regional_arabic_indic"]
    assert arabic
    # Arabic-Indic 1=U+0661, 2=U+0662, 3=U+0663
    assert arabic[0].value == '\u0661\u0662\u0663'


def test_no_digits_yields_nothing():
    gen = RegionalDigitsGenerator()
    variants = list(gen.generate("abc"))
    assert variants == []


def test_mixed_alternating():
    gen = RegionalDigitsGenerator()
    variants = list(gen.generate("1234"))
    mixed = [v for v in variants if v.technique == "regional_mixed_alternating"]
    assert mixed


def test_all_scripts_present():
    gen = RegionalDigitsGenerator()
    variants = list(gen.generate("4532015112830366"))
    techniques = {v.technique for v in variants}
    assert "regional_devanagari" in techniques
    assert "regional_thai" in techniques
    assert "regional_bengali" in techniques
