from evadex.core.registry import load_builtins, _GENERATORS, _ADAPTERS


def test_generators_registered():
    load_builtins()
    assert "unicode_encoding" in _GENERATORS
    assert "delimiter" in _GENERATORS
    assert "splitting" in _GENERATORS
    assert "leetspeak" in _GENERATORS
    assert "regional_digits" in _GENERATORS
    assert "structural" in _GENERATORS


def test_adapter_registered():
    load_builtins()
    assert "dlpscan" in _ADAPTERS
    assert "dlpscan-cli" in _ADAPTERS


def test_encoding_generator_registered():
    load_builtins()
    assert "encoding" in _GENERATORS
