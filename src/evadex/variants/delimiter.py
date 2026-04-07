import re
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator


@register_generator("delimiter")
class DelimiterGenerator(BaseVariantGenerator):
    name = "delimiter"
    applicable_categories = {
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.IBAN,
        PayloadCategory.PHONE,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        # Strip existing delimiters to get raw alphanumeric string
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        yield self._make_variant(raw, "no_delimiter", "All delimiters removed")

        delimiters = [
            (' ',  "space_delimiter",   "Groups separated by spaces"),
            ('-',  "hyphen_delimiter",  "Groups separated by hyphens"),
            ('.',  "dot_delimiter",     "Groups separated by dots"),
            ('/',  "slash_delimiter",   "Groups separated by slashes"),
            ('\t', "tab_delimiter",     "Groups separated by tabs"),
            ('\n', "newline_delimiter", "Groups separated by newlines"),
        ]

        for sep, technique, desc in delimiters:
            result = sep.join(groups)
            if result != value:
                yield self._make_variant(result, technique, desc)

        # Mixed: alternate space and hyphen
        if len(groups) > 1:
            parts = []
            for i, g in enumerate(groups):
                parts.append(g)
                if i < len(groups) - 1:
                    parts.append(' ' if i % 2 == 0 else '-')
            mixed = ''.join(parts)
            if mixed != value:
                yield self._make_variant(
                    mixed,
                    "mixed_delimiter",
                    "Alternating space and hyphen delimiters",
                )

        # Excessive: double hyphens
        excessive = '--'.join(groups)
        if excessive != value:
            yield self._make_variant(excessive, "excessive_delimiter", "Doubled hyphen delimiters")
