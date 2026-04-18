"""Variant generator for barcode/QR image evasions.

These techniques are image-level — the text ``value`` returned here is a
marker the :mod:`evadex.generate.writers.barcode_writer` interprets at
render time. When used outside the image-generation path (for example, in
``evadex scan --strategy text``) the variants still work as text: the
value is a minor perturbation of the original, so the scanner sees a
slightly altered string and evadex still tracks the technique in its
results.

Techniques
----------
``barcode_split``
    Split the value across two separate barcodes on the same image.
    The text variant splits the value with a newline so the scanner sees
    two fragments.
``barcode_noise``
    Overlay visual noise (salt-and-pepper pixels) on the barcode. The
    image should still decode — Siphon's ``rxing`` is noise-tolerant.
``barcode_rotate``
    Rotate the barcode 15° off-axis. QR is rotation-invariant by design;
    this verifies the scanner handles real-world skew.
``barcode_embed``
    Paste the barcode inside a larger document-style image (stamp on a
    mock invoice). Tests whether Siphon detects small barcodes embedded
    in a wider visual context.
"""
from __future__ import annotations

from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


BARCODE_EVASION_TECHNIQUES = (
    "barcode_split",
    "barcode_noise",
    "barcode_rotate",
    "barcode_embed",
)

# ASCII Record Separator — invisible in text UIs, unlikely in real payloads,
# and (critically) not a newline, so it doesn't inflate line counts when a
# barcode_split variant leaks into CSV/JSON/log/text output.
SPLIT_MARKER = "\x1e"


@register_generator("barcode_evasion")
class BarcodeEvasionGenerator(BaseVariantGenerator):
    """Emit barcode-image evasion variants for any text value."""

    name = "barcode_evasion"
    applicable_categories = None  # Any category — barcodes can encode anything
    # Only run when explicitly requested via --technique-group barcode_evasion.
    # Otherwise these image-level evasions would enter the random text pool
    # and skew line counts in CSV/JSON/log output with their zero-width and
    # split-marker characters.
    auto_applicable = False

    def generate(self, value: str) -> Iterator[Variant]:
        if not value:
            return

        mid = max(1, len(value) // 2)

        # 1. barcode_split — value split with an invisible record-separator
        # marker. The barcode writer splits on this to render two separate
        # codes; text-mode pipelines see the marker as a non-line-breaking
        # control char, so CSV/JSON/log output stays on one line.
        yield self._make_variant(
            f"{value[:mid]}{SPLIT_MARKER}{value[mid:]}",
            "barcode_split",
            "Split value across two barcodes on the same image",
        )

        # 2. barcode_noise — value unchanged; the writer overlays image noise.
        # In the text path, a trailing unicode mark keeps the variant distinct
        # from the plain payload for dedupe.
        yield self._make_variant(
            value + "\u200b",  # zero-width space — invisible to humans, trackable by scanner
            "barcode_noise",
            "Overlay salt-and-pepper noise on the rendered barcode",
        )

        # 3. barcode_rotate — value unchanged; writer rotates the barcode 15°.
        yield self._make_variant(
            value + "\u200c",  # zero-width non-joiner
            "barcode_rotate",
            "Rotate the barcode ~15° off-axis",
        )

        # 4. barcode_embed — value unchanged; writer embeds the barcode inside
        # a larger document-style canvas (fake invoice header + footer).
        yield self._make_variant(
            value + "\u200d",  # zero-width joiner
            "barcode_embed",
            "Embed barcode inside a larger document image",
        )
