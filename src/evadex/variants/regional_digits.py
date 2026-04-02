from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator

DIGIT_SCRIPTS = {
    "arabic_indic":          (0x0660, "Arabic-Indic digits"),
    "extended_arabic_indic": (0x06F0, "Extended Arabic-Indic digits (Urdu/Persian)"),
    "devanagari":            (0x0966, "Devanagari digits"),
    "bengali":               (0x09E6, "Bengali digits"),
    "thai":                  (0x0E50, "Thai digits"),
    "myanmar":               (0x1040, "Myanmar digits"),
    "khmer":                 (0x17E0, "Khmer digits"),
    "mongolian":             (0x1810, "Mongolian digits"),
    "nko":                   (0x07C0, "NKo digits"),
    "tibetan":               (0x0F20, "Tibetan digits"),
}


def _replace_digits(value: str, base: int) -> str:
    return ''.join(chr(base + int(c)) if c.isdigit() else c for c in value)


@register_generator("regional_digits")
class RegionalDigitsGenerator(BaseVariantGenerator):
    name = "regional_digits"

    def generate(self, value: str) -> Iterator[Variant]:
        if not any(c.isdigit() for c in value):
            return

        for script_name, (base, label) in DIGIT_SCRIPTS.items():
            result = _replace_digits(value, base)
            yield self._make_variant(
                result,
                f"regional_{script_name}",
                f"Digits replaced with {label}",
            )

        # Mixed: alternating Arabic-Indic and Devanagari
        arabic_base = DIGIT_SCRIPTS["arabic_indic"][0]
        devanagari_base = DIGIT_SCRIPTS["devanagari"][0]
        digit_idx = 0
        mixed_chars = []
        for c in value:
            if c.isdigit():
                base = arabic_base if digit_idx % 2 == 0 else devanagari_base
                mixed_chars.append(chr(base + int(c)))
                digit_idx += 1
            else:
                mixed_chars.append(c)
        yield self._make_variant(
            ''.join(mixed_chars),
            "regional_mixed_alternating",
            "Alternating Arabic-Indic and Devanagari digits",
        )

        # Partial: first half Thai, second half Bengali
        digits_in_value = [(i, c) for i, c in enumerate(value) if c.isdigit()]
        half = len(digits_in_value) // 2
        chars = list(value)
        thai_base = DIGIT_SCRIPTS["thai"][0]
        bengali_base = DIGIT_SCRIPTS["bengali"][0]
        for idx, (pos, c) in enumerate(digits_in_value):
            base = thai_base if idx < half else bengali_base
            chars[pos] = chr(base + int(c))
        yield self._make_variant(
            ''.join(chars),
            "regional_mixed_partial",
            "First half Thai digits, second half Bengali digits",
        )
