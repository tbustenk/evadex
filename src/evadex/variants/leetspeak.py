from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import PayloadCategory
from evadex.variants.base import BaseVariantGenerator

MINIMAL = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5'}
MODERATE = {**MINIMAL, 't': '7', 'l': '1', 'g': '9', 'b': '8', 'z': '2'}
AGGRESSIVE = {
    **MODERATE,
    'q': '9', 'r': '\u042F', 'k': '|<', 'x': '><', 'h': '#',
    'w': 'vv', 'm': '|v|', 'n': '|\\|', 'u': 'v', 'c': '(',
    'd': '|)', 'f': '|=', 'j': '_|', 'p': '|\xb0', 'v': '\\/',
    'y': '`/',
}


@register_generator("leetspeak")
class LeetspeakGenerator(BaseVariantGenerator):
    name = "leetspeak"
    applicable_categories = {
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.EMAIL,
        PayloadCategory.PHONE,
        PayloadCategory.UNKNOWN,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        for table, technique, desc in [
            (MINIMAL,     "leet_minimal",    "Minimal leetspeak substitution (a\u21924, e\u21923, i\u21921, o\u21920, s\u21925)"),
            (MODERATE,    "leet_moderate",   "Moderate leetspeak substitution"),
            (AGGRESSIVE,  "leet_aggressive", "Aggressive leetspeak substitution"),
        ]:
            result = ''.join(table.get(c.lower(), c) for c in value)
            if result != value:
                yield self._make_variant(result, technique, desc)
