import base64
import codecs
from evadex.variants.encoding import EncodingGenerator


def test_base64_standard():
    gen = EncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    b64 = [v for v in variants if v.technique == "base64_standard"]
    assert b64
    assert b64[0].value == base64.b64encode(b"4532015112830366").decode("ascii")


def test_base64_no_padding():
    gen = EncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    nopad = [v for v in variants if v.technique == "base64_no_padding"]
    assert nopad
    assert "=" not in nopad[0].value


def test_base64_double():
    gen = EncodingGenerator()
    variants = list(gen.generate("123"))
    double = [v for v in variants if v.technique == "base64_double"]
    assert double
    # Should be decodable twice
    inner = base64.b64decode(double[0].value.encode()).decode("ascii")
    recovered = base64.b64decode(inner.encode()).decode("utf-8")
    assert recovered == "123"


def test_rot13_on_aws_key():
    gen = EncodingGenerator()
    variants = list(gen.generate("AKIAIOSFODNN7EXAMPLE"))
    rot = [v for v in variants if v.technique == "rot13"]
    assert rot
    # Applying ROT13 twice returns original
    assert codecs.encode(rot[0].value, "rot_13") == "AKIAIOSFODNN7EXAMPLE"


def test_rot13_skipped_for_pure_digits():
    gen = EncodingGenerator()
    variants = list(gen.generate("1234567890"))
    rot = [v for v in variants if "rot13" in v.technique]
    assert rot == []


def test_reversed_full():
    gen = EncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    rev = [v for v in variants if v.technique == "reversed_full"]
    assert rev
    assert rev[0].value == "6630382115102354"


def test_reversed_within_groups():
    gen = EncodingGenerator()
    variants = list(gen.generate("4532015112830366"))
    rg = [v for v in variants if v.technique == "reversed_within_groups"]
    assert rg
    # First group "4532" reversed → "2354"
    assert rg[0].value.startswith("2354")


def test_double_url_encoding():
    gen = EncodingGenerator()
    variants = list(gen.generate("AB"))
    double = [v for v in variants if v.technique == "double_url_encoding"]
    assert double
    assert "%2541" in double[0].value or "%2561" in double[0].value.lower()


def test_mixed_normalization_produces_variants():
    gen = EncodingGenerator()
    # Pure ASCII is unchanged by normalization — correct to yield nothing
    ascii_variants = list(gen.generate("test@example.com"))
    assert [v for v in ascii_variants if "normalization" in v.technique] == []

    # A string with a combining character does change under NFD/NFC
    # é as a single precomposed codepoint (U+00E9) decomposes under NFD
    unicode_value = "caf\u00e9@example.com"
    unicode_variants = list(gen.generate(unicode_value))
    norm = [v for v in unicode_variants if "normalization" in v.technique]
    assert len(norm) >= 1


def test_all_variants_have_metadata():
    gen = EncodingGenerator()
    for v in gen.generate("AKIAIOSFODNN7EXAMPLE"):
        assert v.generator == "encoding"
        assert v.technique
        assert v.transform_name


def test_base64_mime_linebreaks_only_for_long_values():
    gen = EncodingGenerator()
    # Short value — base64 will be < 76 chars, no MIME variant
    short_variants = list(gen.generate("AB"))
    mime_short = [v for v in short_variants if v.technique == "base64_mime_linebreaks"]
    assert mime_short == []

    # Long enough value — MIME variant should appear
    long_value = "A" * 60
    long_variants = list(gen.generate(long_value))
    mime_long = [v for v in long_variants if v.technique == "base64_mime_linebreaks"]
    assert mime_long
    assert "\n" in mime_long[0].value
