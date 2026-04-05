"""Morse code evasion generator.

Encodes digit characters in a value to their International Morse Code
representations. Non-digit characters are passed through unchanged.

Digit encodings (ITU-R M.1677-1):
    0 = -----   1 = .----   2 = ..---   3 = ...--   4 = ....-
    5 = .....   6 = -....   7 = --...   8 = ---..   9 = ----.
"""
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import PayloadCategory, Variant
from evadex.variants.base import BaseVariantGenerator


MORSE_DIGITS: dict[str, str] = {
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
}


def _encode(value: str, sep: str, word_sep: str) -> str:
    """Encode each character of *value* to Morse, joining symbols with *sep*.

    Digits are replaced by their Morse symbol.  Non-digit characters are
    passed through as-is and separated from adjacent tokens by *word_sep*.

    Args:
        value:     Input string.
        sep:       Separator placed between Morse symbols of consecutive digits.
        word_sep:  Separator placed around non-digit (pass-through) characters.
    """
    tokens: list[str] = []
    for ch in value:
        if ch in MORSE_DIGITS:
            tokens.append(MORSE_DIGITS[ch])
        else:
            # Non-digit: keep literal, surrounded by word_sep so adjacent
            # Morse groups stay visually distinct.
            tokens.append(word_sep + ch + word_sep)
    # Join all tokens with sep, then collapse runs of multiple word_sep
    # that arise from consecutive non-digit characters or boundary artefacts.
    result = sep.join(tokens)
    # Clean up doubled word_sep sequences that can appear at non-digit boundaries.
    # Skip when word_sep is empty to avoid an infinite loop (empty string is always
    # a substring of any string and replace("", "") returns the original unchanged).
    if word_sep:
        doubled = word_sep + word_sep
        while doubled in result:
            result = result.replace(doubled, word_sep)
    return result


@register_generator("morse_code")
class MorseCodeGenerator(BaseVariantGenerator):
    """Encodes digit characters as International Morse Code symbols.

    Only applied to categories that are primarily numeric so that the
    obfuscation is meaningful.
    """

    name = "morse_code"

    applicable_categories = {
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.IBAN,
        PayloadCategory.PHONE,
        PayloadCategory.ABA_ROUTING,
        PayloadCategory.AU_TFN,
        PayloadCategory.DE_TAX_ID,
        PayloadCategory.FR_INSEE,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        # Only produce variants when the value contains at least one digit.
        if not any(c in MORSE_DIGITS for c in value):
            return

        # Variant 1: space-separated symbols, slash between characters
        # e.g. "123" → ".---- ..--- ...--"
        standard = _encode(value, sep=" ", word_sep=" ")
        yield self._make_variant(
            standard,
            "morse_space_sep",
            "Digits encoded as Morse; symbols separated by spaces",
        )

        # Variant 2: slash separator between characters (common Morse notation)
        # e.g. "123" → ".----/..---/...--"
        slash = _encode(value, sep="/", word_sep="/")
        if slash != standard:
            yield self._make_variant(
                slash,
                "morse_slash_sep",
                "Digits encoded as Morse; symbols separated by forward slashes",
            )

        # Variant 3: no separator between symbols (concatenated dots and dashes)
        # e.g. "123" → ".----..---...--"
        no_sep = _encode(value, sep="", word_sep="")
        if no_sep != standard and no_sep != slash:
            yield self._make_variant(
                no_sep,
                "morse_no_sep",
                "Digits encoded as Morse; symbols concatenated with no separator",
            )

        # Variant 4: each character on its own line (newline-separated)
        # e.g. "123" → ".----\n..---\n...--"
        newline = _encode(value, sep="\n", word_sep="\n")
        if newline not in (standard, slash, no_sep):
            yield self._make_variant(
                newline,
                "morse_newline_sep",
                "Digits encoded as Morse; each symbol on its own line",
            )
