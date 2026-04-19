"""Variant generator for archive-level evasions.

Like ``barcode_evasion``, these are container-level techniques: the
``value`` produced here is a marker that the archive writers in
:mod:`evadex.generate.writers.archive_writer` interpret at render
time. In a plain text-pipeline run (``evadex scan --strategy text``)
the variants still work as text — the value carries a small
disambiguating perturbation so the technique name stays trackable.

Techniques
----------
``archive_password``
    Wrap the payload in a password-protected ZIP. Tests whether the
    scanner attempts to crack a known-weak password (it should not),
    skips the entry (preferred), or surfaces an error.
``archive_double_extension``
    Rename ``file.csv.zip`` to ``file.zip.csv`` (or similar). Tests
    whether the scanner trusts the *last* extension or sniffs the
    actual file magic bytes. Magic-byte detection is the safe
    behaviour.
``archive_deep_nest``
    Bury the payload five levels deep inside nested archives. Tests
    whether the scanner recursively extracts. Siphon's current
    extractor does not, so this should evade detection — flag the
    technique to confirm the gap.
``archive_mixed_formats``
    ZIP containing a DOCX containing a CSV containing the payload —
    different container formats stacked. Tests cross-format extractor
    chaining.
"""
from __future__ import annotations

from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator


ARCHIVE_EVASION_TECHNIQUES = (
    "archive_password",
    "archive_double_extension",
    "archive_deep_nest",
    "archive_mixed_formats",
)


# Each marker is a single Unicode tag character (U+E000–U+F8FF Private
# Use Area). Invisible in any reasonable rendering, distinct enough that
# a scanner won't accidentally match them, and *not* a newline / control
# character so they don't perturb line-based pipelines (CSV, JSON, log).
_PASSWORD_MARK = "\ue001"
_DOUBLE_EXT_MARK = "\ue002"
_DEEP_NEST_MARK = "\ue003"
_MIXED_FORMATS_MARK = "\ue004"


@register_generator("archive_evasion")
class ArchiveEvasionGenerator(BaseVariantGenerator):
    """Emit container-level archive evasion variants for any text value.

    Like ``BarcodeEvasionGenerator``, this is gated behind
    ``auto_applicable = False`` so its archive-only markers do not
    leak into random text-pipeline selection and skew CSV/JSON/log
    output.
    """

    name = "archive_evasion"
    applicable_categories = None
    auto_applicable = False

    def generate(self, value: str) -> Iterator[Variant]:
        if not value:
            return

        # 1. archive_password — value untouched; the writer wraps the
        # whole archive in a known-weak password so the scanner is
        # forced to either crack, skip, or error.
        yield self._make_variant(
            value + _PASSWORD_MARK,
            "archive_password",
            "Wrap archive in a password-protected ZIP (weak password)",
        )

        # 2. archive_double_extension — file.csv.zip stored as file.zip.csv.
        # Pure metadata trick; value carries the marker so the technique
        # is still distinguishable from the plain payload in dedupe.
        yield self._make_variant(
            value + _DOUBLE_EXT_MARK,
            "archive_double_extension",
            "Rename archive with a misleading double extension",
        )

        # 3. archive_deep_nest — payload buried 5 archive levels deep.
        yield self._make_variant(
            value + _DEEP_NEST_MARK,
            "archive_deep_nest",
            "Bury payload 5 levels deep in nested archives",
        )

        # 4. archive_mixed_formats — ZIP of DOCX of CSV of payload.
        yield self._make_variant(
            value + _MIXED_FORMATS_MARK,
            "archive_mixed_formats",
            "Stack different container formats (ZIP > DOCX > CSV)",
        )
