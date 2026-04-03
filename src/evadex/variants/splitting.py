import html
import json
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator

NOISE = "Lorem ipsum dolor sit amet consectetur"


@register_generator("splitting")
class SplittingGenerator(BaseVariantGenerator):
    name = "splitting"

    def generate(self, value: str) -> Iterator[Variant]:
        mid = len(value) // 2

        yield self._make_variant(
            value[:mid] + '\n' + value[mid:],
            "mid_line_break",
            "Line break injected at midpoint",
        )
        yield self._make_variant(
            '<!---->'.join(value),
            "html_comment_injection",
            "HTML comment injected between every character",
        )
        yield self._make_variant(
            '/**/'.join(value),
            "css_comment_injection",
            "CSS comment injected between every character",
        )
        yield self._make_variant(
            NOISE[:20] + ' ' + value,
            "prefix_noise",
            "Noise text prepended",
        )
        yield self._make_variant(
            value + ' ' + NOISE[:20],
            "suffix_noise",
            "Noise text appended",
        )
        yield self._make_variant(
            json.dumps({"part1": value[:mid], "part2": value[mid:]}),
            "json_field_split",
            "Value split across two JSON fields",
        )
        yield self._make_variant(
            ' '.join(value),
            "whitespace_padding",
            "Space inserted between every character",
        )
        yield self._make_variant(
            f'<data>{html.escape(value)}</data>',
            "xml_tag_injection",
            "Value wrapped in XML data tag",
        )
