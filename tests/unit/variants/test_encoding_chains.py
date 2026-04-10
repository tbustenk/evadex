"""Tests for the encoding_chains variant generator."""
import base64
import binascii
import codecs
from urllib.parse import unquote

from evadex.variants.encoding_chains import EncodingChainsGenerator


VALUE = "046 454 286"   # Canada SIN seed payload — contains letters (spaces) and digits


def _get_variants(value=VALUE):
    gen = EncodingChainsGenerator()
    return {v.technique: v.value for v in gen.generate(value)}


def test_all_seven_techniques_present():
    variants = _get_variants()
    expected = {
        "base64_of_rot13",
        "base64_of_hex",
        "hex_of_base64",
        "rot13_of_base64",
        "url_of_base64",
        "base64_of_base64",
        "base64_of_rot13_of_hex",
    }
    assert expected.issubset(variants.keys()), (
        f"Missing techniques: {expected - variants.keys()}"
    )


def test_base64_of_rot13_roundtrip():
    variants = _get_variants()
    encoded = variants["base64_of_rot13"]
    # Decode: base64 → rot13 reverse → original
    after_b64 = base64.b64decode(encoded.encode()).decode("utf-8")
    recovered = codecs.decode(after_b64, "rot_13")
    assert recovered == VALUE


def test_base64_of_hex_roundtrip():
    variants = _get_variants()
    encoded = variants["base64_of_hex"]
    hex_str = base64.b64decode(encoded.encode()).decode("ascii")
    recovered = binascii.unhexlify(hex_str).decode("utf-8")
    assert recovered == VALUE


def test_hex_of_base64_roundtrip():
    variants = _get_variants()
    encoded = variants["hex_of_base64"]
    b64_str = binascii.unhexlify(encoded).decode("ascii")
    recovered = base64.b64decode(b64_str.encode()).decode("utf-8")
    assert recovered == VALUE


def test_rot13_of_base64_roundtrip():
    variants = _get_variants()
    encoded = variants["rot13_of_base64"]
    b64_str = codecs.decode(encoded, "rot_13")
    recovered = base64.b64decode(b64_str.encode()).decode("utf-8")
    assert recovered == VALUE


def test_url_of_base64_roundtrip():
    variants = _get_variants()
    encoded = variants["url_of_base64"]
    b64_str = unquote(encoded)
    recovered = base64.b64decode(b64_str.encode()).decode("utf-8")
    assert recovered == VALUE


def test_base64_of_base64_roundtrip():
    variants = _get_variants()
    encoded = variants["base64_of_base64"]
    inner = base64.b64decode(encoded.encode()).decode("ascii")
    recovered = base64.b64decode(inner.encode()).decode("utf-8")
    assert recovered == VALUE


def test_triple_chain_roundtrip():
    variants = _get_variants()
    encoded = variants["base64_of_rot13_of_hex"]
    rot13_hex = base64.b64decode(encoded.encode()).decode("ascii")
    hex_str = codecs.decode(rot13_hex, "rot_13")
    recovered = binascii.unhexlify(hex_str).decode("utf-8")
    assert recovered == VALUE


def test_generator_name():
    gen = EncodingChainsGenerator()
    variants = list(gen.generate(VALUE))
    assert all(v.generator == "encoding_chains" for v in variants)


def test_works_on_pure_digit_value():
    """Pure digit values should still produce all 7 techniques."""
    variants = _get_variants("4532015112830366")
    assert len(variants) == 7


def test_registered_in_registry():
    from evadex.core.registry import load_builtins, get_generator
    load_builtins()
    gen = get_generator("encoding_chains")
    assert gen is not None
    assert gen.name == "encoding_chains"
