import re
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator

# Unicode whitespace characters — all distinct from ASCII space/tab/newline
# used by the delimiter generator. These can bypass regex patterns that only
# check for ASCII \s or specific ASCII separators.
UNICODE_SPACES = [
    ('\u00A0', 'nbsp',              'non-breaking space (U+00A0)'),
    ('\u2002', 'en_space',          'en-space (U+2002)'),
    ('\u2003', 'em_space',          'em-space (U+2003)'),
    ('\u2009', 'thin_space',        'thin space (U+2009)'),
    ('\u2007', 'figure_space',      'figure space (U+2007) — same width as a digit'),
    ('\u202F', 'narrow_nbsp',       'narrow no-break space (U+202F)'),
    ('\u3000', 'ideographic_space', 'ideographic space (U+3000)'),
]


@register_generator("unicode_whitespace")
class UnicodeWhitespaceGenerator(BaseVariantGenerator):
    name = "unicode_whitespace"
    applicable_categories = {
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.IBAN,
        PayloadCategory.PHONE,
        PayloadCategory.ABA_ROUTING,
        PayloadCategory.US_PASSPORT,
        PayloadCategory.AU_TFN,
        PayloadCategory.DE_TAX_ID,
        PayloadCategory.FR_INSEE,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        for char, tech_suffix, description in UNICODE_SPACES:
            result = char.join(groups)
            if result != value:
                yield self._make_variant(
                    result,
                    f"unicode_{tech_suffix}",
                    f"Groups separated by {description}",
                )

        # Mixed: alternating NBSP and thin space between groups
        if len(groups) > 1:
            parts = []
            for i, g in enumerate(groups):
                parts.append(g)
                if i < len(groups) - 1:
                    parts.append('\u00A0' if i % 2 == 0 else '\u2009')
            result = ''.join(parts)
            if result != value:
                yield self._make_variant(
                    result,
                    "unicode_mixed_spaces",
                    "Alternating non-breaking space and thin space between groups",
                )
