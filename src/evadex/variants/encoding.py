import base64
import codecs
import unicodedata
from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator


@register_generator("encoding")
class EncodingGenerator(BaseVariantGenerator):
    name = "encoding"

    def generate(self, value: str) -> Iterator[Variant]:
        yield from self._base64_variants(value)
        yield from self._rot13_variants(value)
        yield from self._reversed_variants(value)
        yield from self._double_url_encoding(value)
        yield from self._mixed_normalization(value)

    # ------------------------------------------------------------------
    # Base64
    # ------------------------------------------------------------------

    def _base64_variants(self, value: str) -> Iterator[Variant]:
        raw = value.encode("utf-8")

        # Standard base64
        b64 = base64.b64encode(raw).decode("ascii")
        yield self._make_variant(b64, "base64_standard", "Value base64-encoded (standard alphabet)")

        # URL-safe base64 (+ → -, / → _)
        b64url = base64.urlsafe_b64encode(raw).decode("ascii")
        if b64url != b64:
            yield self._make_variant(b64url, "base64_urlsafe", "Value base64-encoded (URL-safe alphabet)")

        # No padding — strip trailing =
        b64_nopad = b64.rstrip("=")
        if b64_nopad != b64:
            yield self._make_variant(b64_nopad, "base64_no_padding", "Value base64-encoded, padding stripped")

        # MIME-style: line break every 76 chars
        if len(b64) > 76:
            lines = [b64[i:i+76] for i in range(0, len(b64), 76)]
            mime = "\n".join(lines)
            yield self._make_variant(mime, "base64_mime_linebreaks", "Base64 with MIME-style line breaks every 76 characters")

        # Partial base64: encode only the second half, leave first half literal
        mid = len(value) // 2
        partial = value[:mid] + base64.b64encode(value[mid:].encode()).decode("ascii")
        yield self._make_variant(partial, "base64_partial", "First half literal, second half base64-encoded")

        # Base64 of base64 (double-encoded)
        b64b64 = base64.b64encode(b64.encode("ascii")).decode("ascii")
        yield self._make_variant(b64b64, "base64_double", "Value base64-encoded twice")

    # ------------------------------------------------------------------
    # ROT13  (only meaningful for values containing letters)
    # ------------------------------------------------------------------

    def _rot13_variants(self, value: str) -> Iterator[Variant]:
        if not any(c.isalpha() for c in value):
            return

        rot = codecs.encode(value, "rot_13")
        yield self._make_variant(rot, "rot13", "ROT13 applied to all alphabetic characters")

        # ROT13 letters only, leave digits and symbols intact
        rot_letters_only = "".join(
            codecs.encode(c, "rot_13") if c.isalpha() else c for c in value
        )
        if rot_letters_only != rot:
            yield self._make_variant(rot_letters_only, "rot13_letters_only", "ROT13 applied to letters only, digits and symbols unchanged")

    # ------------------------------------------------------------------
    # Reversed forms
    # ------------------------------------------------------------------

    def _reversed_variants(self, value: str) -> Iterator[Variant]:
        # Full reversal
        rev = value[::-1]
        if rev != value:
            yield self._make_variant(rev, "reversed_full", "Entire value reversed")

        # Strip non-alphanumeric, split into 4-char groups, reverse within each group
        import re
        raw = re.sub(r"[^A-Za-z0-9]", "", value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]
        within = "".join(g[::-1] for g in groups)
        if within != raw and within != rev:
            yield self._make_variant(within, "reversed_within_groups", "Digits reversed within each 4-character group")

        # Reverse group order (keep internal order)
        group_order = "".join(reversed(groups))
        if group_order != raw and group_order != within:
            yield self._make_variant(group_order, "reversed_group_order", "4-character groups reversed in order")

    # ------------------------------------------------------------------
    # Double URL encoding  (%XX → %25XX)
    # ------------------------------------------------------------------

    def _double_url_encoding(self, value: str) -> Iterator[Variant]:
        # Single-encode every character, then encode the % signs
        single = "".join(f"%{ord(c):02X}" for c in value)
        # Now percent-encode the % signs themselves: % → %25
        double = single.replace("%", "%25")
        yield self._make_variant(double, "double_url_encoding", "Double percent-encoding (%XX → %2XXX)")

        # Selective double-encoding: only digits double-encoded, rest single
        selective = "".join(
            f"%25{ord(c):02X}" if c.isdigit() else f"%{ord(c):02X}"
            for c in value
        )
        if selective != double:
            yield self._make_variant(selective, "double_url_encoding_digits", "Double percent-encoding on digits only")

    # ------------------------------------------------------------------
    # Mixed Unicode normalization
    # ------------------------------------------------------------------

    def _mixed_normalization(self, value: str) -> Iterator[Variant]:
        # Alternate NFD and NFC character by character
        alternating = "".join(
            unicodedata.normalize("NFD", c) if i % 2 == 0
            else unicodedata.normalize("NFC", c)
            for i, c in enumerate(value)
        )
        if alternating != value:
            yield self._make_variant(
                alternating, "mixed_normalization_alternating",
                "Alternating NFD/NFC normalization per character"
            )

        # First half NFD, second half NFKC (cross-form attack)
        mid = len(value) // 2
        cross = (
            unicodedata.normalize("NFD", value[:mid])
            + unicodedata.normalize("NFKC", value[mid:])
        )
        if cross != value and cross != alternating:
            yield self._make_variant(
                cross, "mixed_normalization_cross_form",
                "First half NFD, second half NFKC"
            )

        # NFKD throughout — decomposes compatibility characters aggressively
        nfkd = unicodedata.normalize("NFKD", value)
        if nfkd != value:
            yield self._make_variant(nfkd, "nfkd_normalization", "Unicode NFKD normalization (aggressive decomposition)")
