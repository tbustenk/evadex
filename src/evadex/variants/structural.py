from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


@register_generator("structural")
class StructuralGenerator(BaseVariantGenerator):
    name = "structural"

    def generate(self, value: str) -> Iterator[Variant]:
        mid = len(value) // 2

        yield self._make_variant(' ' * 10 + value, "left_pad_spaces", "10 spaces prepended")
        yield self._make_variant(value + ' ' * 10, "right_pad_spaces", "10 spaces appended")
        yield self._make_variant('0' * 5 + value, "left_pad_zeros", "5 zeros prepended")
        yield self._make_variant(value + '0' * 5, "right_pad_zeros", "5 zeros appended")
        yield self._make_variant('X' * 10 + value + 'X' * 10, "noise_embedded", "Value surrounded by noise characters")
        yield self._make_variant('test_value_' + value, "overlapping_prefix", "Noise prefix prepended")
        if mid > 0:
            yield self._make_variant(value[:mid], "partial_first_half", "First half of value only (tests partial detection)")
        if value[mid:] != value:  # skip when mid == 0 (same as original)
            yield self._make_variant(value[mid:], "partial_last_half", "Last half of value only")
        truncated = value[:-1]
        if truncated:  # skip when value is a single character (would be empty)
            yield self._make_variant(truncated, "partial_minus_one", "Last character removed")
        yield self._make_variant(value + ' ' + value, "repeated", "Value repeated twice with space separator")

        upper = value.upper()
        if upper != value:
            yield self._make_variant(upper, "uppercase", "Entire value uppercased")

        lower = value.lower()
        if lower != value:
            yield self._make_variant(lower, "lowercase", "Entire value lowercased")

        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(value))
        if mixed != value and mixed != upper and mixed != lower:
            yield self._make_variant(mixed, "mixed_case", "Alternating upper/lower case")
