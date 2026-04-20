"""Synthetic email address generator with common Canadian domains."""
from __future__ import annotations

import random
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic

_FIRST_NAMES = [
    "jean", "marie", "pierre", "anne", "luc", "sophie", "marc", "julie",
    "paul", "claire", "john", "emily", "michael", "sarah", "david", "laura",
    "robert", "linda", "james", "patricia", "william", "jennifer", "richard",
    "alexandre", "isabelle", "francois", "nathalie", "christian", "stephanie",
]

_LAST_NAMES = [
    "tremblay", "gagnon", "roy", "cote", "bouchard", "gauthier", "morin",
    "lavoie", "fortin", "gagnier", "smith", "jones", "brown", "wilson",
    "taylor", "anderson", "martin", "lee", "thompson", "white", "harris",
    "clark", "lewis", "robinson", "walker", "hall", "allen", "young",
    "hernandez", "king", "wright", "lopez", "hill", "scott", "green",
]

# Common Canadian and international email domains
_DOMAINS = [
    "gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "yahoo.ca",
    "icloud.com", "videotron.ca", "bell.ca", "rogers.com", "telus.net",
    "shaw.ca", "cogeco.ca", "sympatico.ca", "eastlink.ca", "sasktel.net",
    "mts.net", "nb.aibn.com",
]


def _generate_one(rng: random.Random) -> str:
    first = rng.choice(_FIRST_NAMES)
    last = rng.choice(_LAST_NAMES)
    domain = rng.choice(_DOMAINS)
    # Use one of several common username patterns
    pattern = rng.choice(["dot", "underscore", "firstlast", "lastfirst"])
    if pattern == "dot":
        local = f"{first}.{last}"
    elif pattern == "underscore":
        local = f"{first}_{last}"
    elif pattern == "firstlast":
        local = f"{first[0]}{last}"
    else:
        local = f"{last}{first[0]}"
    # Occasionally append a short number suffix for uniqueness
    if rng.random() < 0.3:
        local += str(rng.randint(1, 99))
    return f"{local}@{domain}"


@register_synthetic(PayloadCategory.EMAIL)
class EmailSyntheticGenerator(BaseSyntheticGenerator):
    """Generates realistic email addresses with common Canadian and international domains."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]
