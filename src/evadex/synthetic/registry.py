"""Registry for synthetic value generators, keyed by PayloadCategory."""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from evadex.synthetic.base import BaseSyntheticGenerator

_SYNTHETIC_GENERATORS: dict = {}


def register_synthetic(category):
    """Decorator: register a BaseSyntheticGenerator class for *category*.

    Usage::

        @register_synthetic(PayloadCategory.SIN)
        class SINSyntheticGenerator(BaseSyntheticGenerator):
            ...
    """
    def decorator(cls):
        _SYNTHETIC_GENERATORS[category] = cls
        return cls
    return decorator


def get_synthetic_generator(category) -> Optional["BaseSyntheticGenerator"]:
    """Return an instantiated generator for *category*, or ``None`` if none registered."""
    cls = _SYNTHETIC_GENERATORS.get(category)
    if cls is None:
        return None
    return cls()


def load_synthetic_generators() -> None:
    """Import all synthetic generator modules so their decorators register them."""
    import evadex.synthetic.credit_card        # noqa: F401
    import evadex.synthetic.sin               # noqa: F401
    import evadex.synthetic.iban              # noqa: F401
    import evadex.synthetic.phone             # noqa: F401
    import evadex.synthetic.email             # noqa: F401
    import evadex.synthetic.ramq              # noqa: F401
    import evadex.synthetic.ca_health_cards   # noqa: F401
    import evadex.synthetic.ca_drivers_licences  # noqa: F401
    import evadex.synthetic.ca_corporate      # noqa: F401
    import evadex.synthetic.ssn               # noqa: F401
    import evadex.synthetic.uk_nin            # noqa: F401
    import evadex.synthetic.br_cpf            # noqa: F401
    import evadex.synthetic.au_medicare       # noqa: F401
    import evadex.synthetic.de_tax_id         # noqa: F401
    import evadex.synthetic.us_dl             # noqa: F401
    import evadex.synthetic.capital_markets   # noqa: F401
    # All imports above are side-effect: each module's @register_synthetic
    # decorator populates _SYNTHETIC_GENERATORS at import time.
