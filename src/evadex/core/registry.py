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
    # Import all variant modules so their @register_generator decorators fire
    import evadex.variants.unicode_encoding
    import evadex.variants.delimiter
    import evadex.variants.splitting
    import evadex.variants.leetspeak
    import evadex.variants.regional_digits
    import evadex.variants.structural
    import evadex.variants.encoding
    import evadex.variants.encoding_chains
    import evadex.variants.context_injection
    import evadex.variants.unicode_whitespace
    import evadex.variants.bidirectional
    import evadex.variants.soft_hyphen
    import evadex.variants.morse_code
    # Import adapters
    import evadex.adapters.dlpscan.adapter
    import evadex.adapters.dlpscan_cli.adapter
    import evadex.adapters.presidio.adapter
    import evadex.adapters.siphon.adapter
