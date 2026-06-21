"""Capital-markets identifier evasion variants.

Targets CUSIP, ISIN, SEDOL, LEI, FIGI, and related securities identifiers.
These identifiers have rigid alphanumeric structure that DLP tools pattern-match
against; variants here exercise boundary conditions specific to that structure.
"""

from __future__ import annotations

from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import PayloadCategory, Variant
from evadex.variants.base import BaseVariantGenerator


@register_generator("capital_markets")
class CapitalMarketsGenerator(BaseVariantGenerator):
    name = "capital_markets"
    applicable_categories: set[PayloadCategory] = {
        PayloadCategory.ISIN,
        PayloadCategory.CUSIP_NUM,
        PayloadCategory.SEDOL_NUM,
        PayloadCategory.LEI_NUM,
        PayloadCategory.FIGI_NUM,
        PayloadCategory.REUTERS_RIC,
        PayloadCategory.TICKER_SYMBOL,
        PayloadCategory.MT103_REF,
        PayloadCategory.CHIPS_UID,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        n = len(value)

        # -- Delimiter injection between groups --

        # Insert forward-slash between third and last chars (CUSIP-style split)
        if n >= 4:
            yield self._make_variant(
                value[: n - 1] + "/" + value[-1],
                "slash_before_check",
                "Forward-slash inserted before check digit",
            )

        # Insert hyphen at the 1/3 point (mimics bond reference formatting)
        third = n // 3
        if third > 0:
            yield self._make_variant(
                value[:third] + "-" + value[third:],
                "hyphen_at_third",
                "Hyphen inserted at one-third position",
            )

        # Space after first 2 chars (mimics ISO country-code separation in ISIN)
        if n > 4:
            yield self._make_variant(
                value[:2] + " " + value[2:],
                "space_after_prefix",
                "Space inserted after 2-char prefix (country code / LOU prefix)",
            )

        # Space before last char (separates check digit)
        if n > 2:
            yield self._make_variant(
                value[:-1] + " " + value[-1],
                "space_before_check",
                "Space inserted before check digit",
            )

        # -- Case manipulation --

        lower = value.lower()
        if lower != value:
            yield self._make_variant(
                lower, "lowercase_all", "All characters lowercased"
            )

        # Mixed case: alternate upper/lower starting from second char
        mixed = value[0] + "".join(
            c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(value[1:])
        )
        if mixed != value and mixed != lower:
            yield self._make_variant(
                mixed, "mixed_case_alt", "Alternating case starting from second char"
            )

        # -- Zero-width character injection --
        zwsp = "​"  # zero-width space (U+200B)
        mid = n // 2
        yield self._make_variant(
            value[:mid] + zwsp + value[mid:],
            "zwsp_mid",
            "Zero-width space inserted at midpoint",
        )

        # Zero-width no-break space after every 4 chars (block formatting)
        if n >= 8:
            blocked = ""
            for i, c in enumerate(value):
                if i > 0 and i % 4 == 0:
                    blocked += "﻿"  # BOM / zero-width no-break space
                blocked += c
            yield self._make_variant(
                blocked,
                "zwsp_block4",
                "Zero-width no-break space every 4 chars",
            )

        # -- Whitespace padding variants --
        yield self._make_variant(
            " " + value + " ",
            "padded_spaces",
            "Single space on each side",
        )

        # -- Noise context to confuse keyword gating --
        yield self._make_variant(
            "REFERENCE: " + value,
            "noisy_prefix_reference",
            "Generic 'REFERENCE: ' prefix to trigger context match without real context",
        )
        yield self._make_variant(
            value + " (see prospectus)",
            "noisy_suffix_prospectus",
            "Trailing parenthetical to shift span offset",
        )

        # -- Partial truncation --
        if n > 4:
            yield self._make_variant(
                value[:-1], "truncate_check", "Check digit removed"
            )

        # -- Reversal --
        reversed_val = value[::-1]
        if reversed_val != value:
            yield self._make_variant(
                reversed_val, "reversed", "Value reversed character-by-character"
            )
