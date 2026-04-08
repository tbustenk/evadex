"""Synthetic Quebec RAMQ (Régie de l'assurance maladie du Québec) health card generator.

RAMQ health card format (12 alphanumeric characters, displayed with spaces):
  XXXX YYMM DDSS
  - XXXX : first 3 letters of surname + first letter of given name (uppercase)
  - YY   : last 2 digits of birth year (00-99)
  - MM   : birth month (01-12 male; 51-62 female — month + 50)
  - DD   : birth day (01-28 conservative range for synthetic values)
  - SS   : administrative sequence (01-99)

Display format: ``ABCD YYMM DDSS`` (two spaces separating groups of 4).
"""
from __future__ import annotations

import random
import string
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic

# Consonant-heavy letter sets that appear in French-Canadian surnames
_SURNAME_CHARS = "BCDFGHJKLMNPQRSTVWXYZ"
_VOWELS = "AEIOU"

# Mix of consonants and vowels for more realistic name prefixes
_NAME_LETTERS = string.ascii_uppercase


def _generate_name_prefix(rng: random.Random) -> str:
    """Generate a 4-letter name prefix that looks like a French-Canadian surname."""
    # Pattern: consonant, vowel, consonant, vowel/consonant for surname (3) + first (1)
    chars = []
    for i in range(4):
        if i % 2 == 0:
            chars.append(rng.choice(_SURNAME_CHARS))
        else:
            chars.append(rng.choice(_NAME_LETTERS))
    return "".join(chars)


def _generate_one(rng: random.Random) -> str:
    name = _generate_name_prefix(rng)
    year = rng.randint(0, 99)
    # Randomly assign sex: male (01-12) or female (51-62)
    month = rng.randint(1, 12)
    if rng.random() < 0.5:
        month += 50   # female
    day = rng.randint(1, 28)
    seq = rng.randint(1, 99)
    # Format: ABCD YYMM DDSS
    digits = f"{year:02d}{month:02d}{day:02d}{seq:02d}"
    return f"{name} {digits[:4]} {digits[4:]}"


@register_synthetic(PayloadCategory.CA_RAMQ)
class RAMQSyntheticGenerator(BaseSyntheticGenerator):
    """Generates Quebec RAMQ health card numbers in ``ABCD YYMM DDSS`` format."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]
