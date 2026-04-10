"""Encoding chain variants — multiple encoding steps applied sequentially.

These defeat scanners that only decode one layer. Each technique applies two or
three transformations in order, producing a value that requires multi-stage
decoding to recover the original.
"""
from __future__ import annotations

import base64
import binascii
import codecs
from urllib.parse import quote
from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


def _hex(value: str) -> str:
    return binascii.hexlify(value.encode("utf-8")).decode("ascii")


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _rot13(value: str) -> str:
    return codecs.encode(value, "rot_13")


def _url(value: str) -> str:
    return quote(value, safe="")


@register_generator("encoding_chains")
class EncodingChainsGenerator(BaseVariantGenerator):
    """Chained encoding transformations — two or three steps applied sequentially.

    Applicable to all payload categories (``applicable_categories = None``).
    """

    name = "encoding_chains"

    def generate(self, value: str) -> Iterator[Variant]:
        # ── Two-step chains ──────────────────────────────────────────────────

        # base64(rot13(value))
        yield self._make_variant(
            _b64(_rot13(value)),
            "base64_of_rot13",
            "base64 of ROT13 of value",
        )

        # base64(hex(value))
        yield self._make_variant(
            _b64(_hex(value)),
            "base64_of_hex",
            "base64 of hex encoding of value",
        )

        # hex(base64(value))
        b64v = _b64(value)
        yield self._make_variant(
            _hex(b64v),
            "hex_of_base64",
            "hex of base64 of value",
        )

        # rot13(base64(value))
        yield self._make_variant(
            _rot13(b64v),
            "rot13_of_base64",
            "ROT13 of base64 of value",
        )

        # url_encode(base64(value))
        yield self._make_variant(
            _url(b64v),
            "url_of_base64",
            "URL encoding of base64 of value",
        )

        # base64(base64(value)) — double base64
        yield self._make_variant(
            _b64(b64v),
            "base64_of_base64",
            "double base64 of value",
        )

        # ── Triple chain ─────────────────────────────────────────────────────

        # base64(rot13(hex(value)))
        yield self._make_variant(
            _b64(_rot13(_hex(value))),
            "base64_of_rot13_of_hex",
            "base64 of ROT13 of hex of value (triple chain)",
        )
