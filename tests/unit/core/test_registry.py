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


def test_http_generic_and_netskope_adapters_registered():
    """http_generic (v3.31.0) and netskope (v3.32.0) must be discoverable."""
    load_builtins()
    assert "http_generic" in _ADAPTERS
    assert "netskope" in _ADAPTERS


def test_scan_tool_help_lists_all_builtin_adapters():
    """The ``scan --tool`` help string must not drift from the built-in adapters.

    Iterating the live ``_ADAPTERS`` dict is unsafe here because other tests
    register mock adapters into it, so we assert against the fixed built-in set.
    """
    load_builtins()
    from evadex.cli.commands.scan import scan

    help_text = next(p.help for p in scan.params if getattr(p, "name", None) == "tool")
    builtin_adapters = {
        "dlpscan",
        "dlpscan-cli",
        "siphon",
        "siphon-cli",
        "presidio",
        "http_generic",
        "netskope",
    }
    for name in builtin_adapters:
        assert name in help_text, f"{name} missing from scan --tool help"


def test_encoding_generator_registered():
    load_builtins()
    assert "encoding" in _GENERATORS
