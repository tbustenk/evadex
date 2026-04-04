from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator

# Unicode bidirectional control characters.
# These affect how text is rendered (display order) without changing storage order.
# Scanners that normalise or render text before pattern-matching may see a reversed
# or reordered value; scanners that match raw bytes/codepoints are unaffected.
RLO = '\u202E'  # Right-to-left override  — following text rendered RTL
LRO = '\u202D'  # Left-to-right override  — following text rendered LTR
RLE = '\u202B'  # Right-to-left embedding
PDF = '\u202C'  # Pop directional formatting (terminates RLO/LRO/RLE/LRE)
RLI = '\u2067'  # Right-to-left isolate   (Unicode 6.3+ bidi algorithm)
PDI = '\u2069'  # Pop directional isolate
ALM = '\u061C'  # Arabic letter mark      — invisible, shifts bidi algorithm


@register_generator("bidirectional")
class BidirectionalGenerator(BaseVariantGenerator):
    name = "bidirectional"
    # Applies to all categories — bidi evasion is format-agnostic

    def generate(self, value: str) -> Iterator[Variant]:
        yield from self._override_wraps(value)
        yield from self._rle_embed(value)
        yield from self._mid_rlo_inject(value)
        yield from self._rli_isolate(value)
        yield from self._alm_injection(value)

    def _override_wraps(self, value: str) -> Iterator[Variant]:
        # Full RTL override — entire value's display order reversed
        yield self._make_variant(
            f"{RLO}{value}{PDF}",
            "rlo_wrap",
            f"Value wrapped in RTL override ({RLO!r}...{PDF!r}) — display order reversed",
        )
        # Full LTR override — explicitly forces LTR; can trip bidi-normalising scanners
        yield self._make_variant(
            f"{LRO}{value}{PDF}",
            "lro_wrap",
            f"Value wrapped in LTR override ({LRO!r}...{PDF!r})",
        )

    def _rle_embed(self, value: str) -> Iterator[Variant]:
        yield self._make_variant(
            f"{RLE}{value}{PDF}",
            "rle_embed",
            f"Value inside RTL embedding ({RLE!r}...{PDF!r})",
        )

    def _mid_rlo_inject(self, value: str) -> Iterator[Variant]:
        # RTL override injected at midpoint — first half LTR, second half display-reversed
        mid = len(value) // 2
        yield self._make_variant(
            value[:mid] + RLO + value[mid:] + PDF,
            "mid_rlo_inject",
            "RTL override injected at midpoint — second half rendered reversed",
        )

    def _rli_isolate(self, value: str) -> Iterator[Variant]:
        # RTL isolate uses the newer Unicode bidi isolate mechanism (Unicode 6.3+)
        yield self._make_variant(
            f"{RLI}{value}{PDI}",
            "rli_isolate",
            f"Value wrapped in RTL isolate ({RLI!r}...{PDI!r}) — Unicode 6.3+ bidi",
        )

    def _alm_injection(self, value: str) -> Iterator[Variant]:
        # Arabic letter mark inserted between every character.
        # Invisible in rendering but shifts the bidi algorithm's character classification.
        yield self._make_variant(
            ALM.join(value),
            "alm_between_chars",
            f"Arabic letter mark ({ALM!r}, U+061C) injected between every character",
        )
