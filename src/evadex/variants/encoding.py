import base64
import binascii
import codecs
import re
import unicodedata
from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


@register_generator("encoding")
class EncodingGenerator(BaseVariantGenerator):
    name = "encoding"

    def generate(self, value: str) -> Iterator[Variant]:
        yield from self._base64_variants(value)
        yield from self._base32_variants(value)
        yield from self._hex_variants(value)
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
    # Base32
    # ------------------------------------------------------------------

    def _base32_variants(self, value: str) -> Iterator[Variant]:
        raw = value.encode("utf-8")

        # Standard base32 (RFC 4648 §6 — A–Z, 2–7)
        b32 = base64.b32encode(raw).decode("ascii")
        yield self._make_variant(b32, "base32_standard", "Value base32-encoded (standard alphabet A–Z, 2–7)")

        # No padding — strip trailing =
        b32_nopad = b32.rstrip("=")
        if b32_nopad != b32:
            yield self._make_variant(b32_nopad, "base32_no_padding", "Value base32-encoded, padding stripped")

        # Lowercase
        b32_lower = b32.lower()
        yield self._make_variant(b32_lower, "base32_lowercase", "Value base32-encoded, lowercase alphabet")

        # Extended hex alphabet (RFC 4648 §7 — 0–9, A–V); Python 3.10+
        b32hex = base64.b32hexencode(raw).decode("ascii")
        yield self._make_variant(b32hex, "base32_hex_alphabet", "Value base32-encoded with extended hex alphabet (0–9, A–V)")

    # ------------------------------------------------------------------
    # Hex encoding
    # ------------------------------------------------------------------

    def _hex_variants(self, value: str) -> Iterator[Variant]:
        raw = value.encode("utf-8")

        # Raw hex string — each byte as two lowercase hex digits
        hex_lower = binascii.hexlify(raw).decode("ascii")
        yield self._make_variant(hex_lower, "hex_lowercase", "Value hex-encoded, lowercase (e.g. 34313131…)")

        # Uppercase hex
        hex_upper = hex_lower.upper()
        yield self._make_variant(hex_upper, "hex_uppercase", "Value hex-encoded, uppercase")

        # \\xNN escape sequence per byte
        hex_escaped = "".join(f"\\x{b:02x}" for b in raw)
        yield self._make_variant(hex_escaped, "hex_escaped_bytes", r"Value as \xNN escape sequences per byte")

        # 0x-prefixed single integer (the whole value as one big hex number)
        as_int = int.from_bytes(raw, "big")
        hex_0x = f"0x{as_int:x}"
        yield self._make_variant(hex_0x, "hex_0x_integer", "Value encoded as a single 0x-prefixed hex integer")

        # Spaced hex — bytes separated by spaces (common in hex dump output)
        hex_spaced = " ".join(f"{b:02x}" for b in raw)
        yield self._make_variant(hex_spaced, "hex_spaced_bytes", "Value as space-separated hex bytes (hex dump style)")

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
        # Encode UTF-8 bytes so non-ASCII chars produce valid %XX sequences
        def pct(c: str) -> str:
            return "".join(f"%{b:02X}" for b in c.encode("utf-8"))

        # Single-encode every character, then encode the % signs
        single = "".join(pct(c) for c in value)
        # Now percent-encode the % signs themselves: % → %25
        double = single.replace("%", "%25")
        yield self._make_variant(double, "double_url_encoding", "Double percent-encoding (%XX → %25XX)")

        # Selective double-encoding: only digits double-encoded, rest single
        selective = "".join(
            "".join(f"%25{b:02X}" for b in c.encode("utf-8")) if c.isdigit() else pct(c)
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
