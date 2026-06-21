_GENERATORS: dict = {}
_ADAPTERS: dict = {}


def register_generator(name: str):
    def decorator(cls):
        _GENERATORS[name] = cls
        return cls

    return decorator


def register_adapter(name: str):
    def decorator(cls):
        _ADAPTERS[name] = cls
        return cls

    return decorator


def get_generator(name: str):
    if name not in _GENERATORS:
        raise KeyError(f"No generator registered: {name!r}")
    return _GENERATORS[name]()


def get_adapter(name: str, config=None):
    if name not in _ADAPTERS:
        raise KeyError(f"No adapter registered: {name!r}. Available: {list(_ADAPTERS)}")
    return _ADAPTERS[name](config or {})


def all_generators():
    return [cls() for cls in _GENERATORS.values()]


def load_builtins():
    # The imports below are intentional side-effect imports: each module
    # registers itself via @register_generator / @register_adapter when
    # imported. Do NOT remove the noqa markers — ruff/pyflakes will flag
    # them as unused otherwise.
    import evadex.variants.unicode_encoding  # noqa: F401
    import evadex.variants.delimiter  # noqa: F401
    import evadex.variants.splitting  # noqa: F401
    import evadex.variants.leetspeak  # noqa: F401
    import evadex.variants.regional_digits  # noqa: F401
    import evadex.variants.structural  # noqa: F401
    import evadex.variants.encoding  # noqa: F401
    import evadex.variants.encoding_chains  # noqa: F401
    import evadex.variants.context_injection  # noqa: F401
    import evadex.variants.unicode_whitespace  # noqa: F401
    import evadex.variants.bidirectional  # noqa: F401
    import evadex.variants.soft_hyphen  # noqa: F401
    import evadex.variants.morse_code  # noqa: F401
    import evadex.variants.entropy_evasion  # noqa: F401
    import evadex.variants.barcode_evasion  # noqa: F401
    import evadex.variants.archive_evasion  # noqa: F401
    import evadex.adapters.dlpscan.adapter  # noqa: F401
    import evadex.adapters.dlpscan_cli.adapter  # noqa: F401
    import evadex.adapters.presidio.adapter  # noqa: F401
    import evadex.adapters.siphon.adapter  # noqa: F401
    import evadex.adapters.siphon_cli.adapter  # noqa: F401
    import evadex.adapters.http_generic.adapter  # noqa: F401
