import unicodedata
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


HOMOGLYPHS = {
    '0': '\u039F',   # Greek capital omicron
    '1': '\u0406',   # Cyrillic I
    '2': '\u0198',   # Latin letter reversed esh (using Ƙ as placeholder — actual: Ƨ U+01A8)
    '3': '\u01B7',   # Latin letter ezh (Ʒ)
    '5': '\u01BC',   # Latin letter five (Ƽ)
    '6': '\u0431',   # Cyrillic be (б)
    '8': '\u0222',   # Latin letter OU (Ȣ)
    'A': '\u0410',   # Cyrillic A
    'B': '\u0412',   # Cyrillic Ve (В)
    'C': '\u0421',   # Cyrillic Es (С)
    'E': '\u0415',   # Cyrillic Ie (Е)
    'H': '\u041D',   # Cyrillic En (Н)
    'I': '\u0406',   # Cyrillic I (І)
    'K': '\u041A',   # Cyrillic Ka (К)
    'M': '\u041C',   # Cyrillic Em (М)
    'O': '\u041E',   # Cyrillic O (О)
    'P': '\u0420',   # Cyrillic Er (Р)
    'T': '\u0422',   # Cyrillic Te (Т)
    'X': '\u0425',   # Cyrillic Kha (Х)
}

FULLWIDTH_DIGITS = {str(i): chr(0xFF10 + i) for i in range(10)}


@register_generator("unicode_encoding")
class UnicodeEncodingGenerator(BaseVariantGenerator):
    name = "unicode_encoding"

    def generate(self, value: str) -> Iterator[Variant]:
        yield from self._zero_width_injection(value)
        yield from self._fullwidth_digits(value)
        yield from self._homoglyph_substitution(value)
        yield from self._normalization(value)
        yield from self._html_entities(value)
        yield from self._url_encoding(value)

    def _zero_width_injection(self, value: str) -> Iterator[Variant]:
        for char, name in [('\u200B', 'ZWSP'), ('\u200C', 'ZWNJ'), ('\u200D', 'ZWJ')]:
            result = char.join(value)
            yield self._make_variant(
                result,
                "zero_width_injection",
                f"Zero-width {name} between every character",
            )

    def _fullwidth_digits(self, value: str) -> Iterator[Variant]:
        result = ''.join(FULLWIDTH_DIGITS.get(c, c) for c in value)
        if result != value:
            yield self._make_variant(
                result,
                "fullwidth_digits",
                "ASCII digits replaced with fullwidth equivalents (U+FF10\u2013FF19)",
            )

    def _homoglyph_substitution(self, value: str) -> Iterator[Variant]:
        result = ''.join(HOMOGLYPHS.get(c, HOMOGLYPHS.get(c.upper(), c)) for c in value)
        if result != value:
            yield self._make_variant(
                result,
                "homoglyph_substitution",
                "Visually similar Cyrillic/Greek characters substituted",
            )

    def _normalization(self, value: str) -> Iterator[Variant]:
        for form in ('NFD', 'NFC', 'NFKC', 'NFKD'):
            result = unicodedata.normalize(form, value)
            yield self._make_variant(
                result,
                f"{form.lower()}_normalization",
                f"Unicode normalization form {form}",
            )

    def _html_entities(self, value: str) -> Iterator[Variant]:
        decimal = ''.join(f'&#{ord(c)};' for c in value)
        yield self._make_variant(decimal, "html_entity_decimal", "HTML decimal entities for every character")
        hexent = ''.join(f'&#x{ord(c):x};' for c in value)
        yield self._make_variant(hexent, "html_entity_hex", "HTML hex entities for every character")

    def _url_encoding(self, value: str) -> Iterator[Variant]:
        full = ''.join(f'%{ord(c):02X}' for c in value)
        yield self._make_variant(full, "url_percent_encoding_full", "All characters percent-encoded")

        partial = ''.join(f'%{ord(c):02X}' if c.isdigit() else c for c in value)
        if partial != value:
            yield self._make_variant(partial, "url_percent_encoding_digits", "Only digits percent-encoded")

        mixed = ''.join(
            f'%{ord(c):02X}' if i % 2 == 0 and c.isalnum() else c
            for i, c in enumerate(value)
        )
        if mixed != value and mixed != partial:
            yield self._make_variant(mixed, "url_percent_encoding_mixed", "Alternating percent-encoding")
