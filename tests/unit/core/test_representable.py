"""A variant whose value a fixture format cannot carry has no fixture there.

Before 3.41.1 the engine submitted it anyway; python-docx and openpyxl
refused ("All strings must be XML compatible"), and the submission was
recorded as an *error* — 185 per XML strategy on a northam run, all from
``barcode_split``'s U+001E marker — which ``evadex ci --max-error-rate``
counted against the scanner. The scanner was never asked.

Before 3.42.0 the PDF fixture had the quieter version of the same bug: a
character outside Latin-1 became ``?`` and the submission was recorded as a
*miss*. PDF now follows the same rule, with the fixture's fonts deciding what
it can carry.
"""

from __future__ import annotations

import json
from typing import Iterator

import pytest

from evadex.adapters.base import BaseAdapter
from evadex.core.engine import Engine
from evadex.core.representable import (
    XML_STRATEGIES,
    describe_unrepresentable,
    pdf_charset,
    register_pdf_charset,
    representable,
    unrepresentable_chars,
    why_unrepresentable,
)
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.reporters.json_reporter import JsonReporter
from evadex.variants.base import BaseVariantGenerator

SSN = "742-18-5503"
PAYLOAD = Payload(SSN, PayloadCategory.SSN, "US SSN")
ALL = ["text", "docx", "pdf", "xlsx"]


@pytest.fixture(autouse=True)
def _no_pdf_font_knowledge():
    """Loading the builtins registers the real fixture's font coverage, which
    depends on the machine. These tests say what they assume."""
    previous = register_pdf_charset(None)
    yield
    register_pdf_charset(previous)


@pytest.fixture
def ascii_only_fonts():
    register_pdf_charset(lambda: frozenset(map(ord, "SN 0123456789-")))


class _Gen(BaseVariantGenerator):
    name = "stub"

    def generate(self, value: str) -> Iterator[Variant]:
        yield self._make_variant(value, "plain", "unchanged")
        yield self._make_variant(
            value[:5] + "\x1e" + value[5:], "split", "record separator"
        )
        yield self._make_variant(value + "\t", "tab", "trailing tab")


class _Recorder(BaseAdapter):
    def __init__(self):
        super().__init__({})
        self.seen: list[tuple[str, str]] = []

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        self.seen.append((variant.technique, variant.strategy))
        return ScanResult(payload=payload, variant=variant, detected=True)


# ── the predicate: XML ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("strategy", sorted(XML_STRATEGIES))
def test_c0_controls_are_not_representable_in_xml_containers(strategy):
    assert not representable("a\x1eb", strategy)
    assert not representable("a\x00b", strategy)
    assert unrepresentable_chars("a\x1eb\x1cc\x1eb", strategy) == ["\x1c", "\x1e"]


@pytest.mark.parametrize("strategy", sorted(XML_STRATEGIES))
def test_tab_newline_and_cr_are_fine_in_xml(strategy):
    assert representable("a\tb\nc\rd", strategy)
    assert unrepresentable_chars("a\tb", strategy) == []


@pytest.mark.parametrize("strategy", sorted(XML_STRATEGIES))
def test_xml_does_not_care_about_fonts(strategy, ascii_only_fonts):
    assert representable("SSN ١٢٣-٤٥-٦٧٨٩", strategy)


def test_text_carries_anything():
    assert representable("a\x1eb\x00c\t١", "text")
    assert unrepresentable_chars("a\x1eb", "text") == []


def test_description_names_the_code_point_and_the_format():
    line = describe_unrepresentable("4\x1e5", "docx")
    assert "U+001E" in line and "docx" in line and "no docx fixture" in line


# ── the predicate: PDF ─────────────────────────────────────────────────────────


def test_pdf_has_no_glyph_for_controls_or_tab_whatever_the_fonts():
    assert pdf_charset() is None, "fixture: nothing registered"
    assert not representable("a\x1eb", "pdf")
    assert not representable("1234\t5678", "pdf")
    assert unrepresentable_chars("a\tb\x1ec\x7f", "pdf") == ["\t", "\x1e", "\x7f"]


def test_pdf_newlines_are_line_breaks_not_glyphs(ascii_only_fonts):
    assert representable("SSN 123\n45-6789", "pdf")
    assert representable("SSN 123\r\n45-6789", "pdf")


def test_pdf_with_unknown_fonts_refuses_only_controls():
    assert pdf_charset() is None
    assert representable("SSN ١٢٣-٤٥-٦٧٨٩ １２３", "pdf")


def test_pdf_with_known_fonts_refuses_what_they_cannot_draw(ascii_only_fonts):
    assert representable("SSN 742-18-5503", "pdf")
    assert not representable("SSN ١٢٣-٤٥-٦٧٨٩", "pdf")
    assert unrepresentable_chars("S١S٢", "pdf") == ["١", "٢"]
    # A space is in the charset here; if it were not, it would still be the
    # fixture's problem to raise, so it is reported like any other character.
    register_pdf_charset(lambda: frozenset(map(ord, "SN0123456789-")))
    assert unrepresentable_chars("SSN 1", "pdf") == [" "]


def test_pdf_description_blames_the_fonts_and_names_the_code_point(ascii_only_fonts):
    line = describe_unrepresentable("SSN ١", "pdf")
    assert (
        "U+0661" in line
        and "pdf" in line
        and "font" in line
        and "no pdf fixture" in line
    )


def test_why_covers_the_strategies_present():
    assert why_unrepresentable({"docx"}) == "XML forbids control characters"
    assert why_unrepresentable({"pdf"}) == "no PDF fixture font has a glyph for them"
    assert why_unrepresentable({"docx", "pdf", "xlsx"}) == (
        "XML forbids control characters; no PDF fixture font has a glyph for them"
    )
    assert why_unrepresentable({"text"}) == ""


def test_register_returns_the_previous_provider():
    first = lambda: frozenset({65})  # noqa: E731
    assert register_pdf_charset(first) is None
    assert register_pdf_charset(None) is first


# ── the engine ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("streaming", [True, False])
def test_engine_skips_only_the_pairs_the_format_cannot_carry(streaming):
    adapter = _Recorder()
    engine = Engine(
        adapter=adapter, generators=[_Gen()], strategies=ALL, streaming=streaming
    )
    results = engine.run([PAYLOAD])

    submitted = set(adapter.seen)
    # The control-character variant goes to text only: XML forbids it, and
    # no PDF font has a glyph for it.
    assert ("split", "text") in submitted
    assert ("split", "docx") not in submitted and ("split", "xlsx") not in submitted
    assert ("split", "pdf") not in submitted
    # A tab is fine in XML and in text, and has no glyph in PDF.
    assert {("tab", s) for s in ("text", "docx", "xlsx")} <= submitted
    assert ("tab", "pdf") not in submitted
    # Plain goes everywhere.
    assert {("plain", s) for s in ALL} <= submitted

    assert len(results) == 3 * 4 - 4
    assert not any(r.error for r in results)
    assert sorted(engine.skipped_unrepresentable) == [
        ("ssn", "split", "docx"),
        ("ssn", "split", "pdf"),
        ("ssn", "split", "xlsx"),
        ("ssn", "tab", "pdf"),
    ]


def test_engine_skips_pdf_for_a_script_the_fonts_lack(ascii_only_fonts):
    class _Arabic(BaseVariantGenerator):
        name = "arabic"

        def generate(self, value: str) -> Iterator[Variant]:
            yield self._make_variant(value, "plain", "unchanged")
            yield self._make_variant(
                "٧٤٢-١٨-٥٥٠٣", "regional_arabic_indic", "Arabic-Indic digits"
            )

    adapter = _Recorder()
    engine = Engine(adapter=adapter, generators=[_Arabic()], strategies=ALL)
    engine.run([PAYLOAD])
    submitted = set(adapter.seen)
    assert {("regional_arabic_indic", s) for s in ("text", "docx", "xlsx")} <= submitted
    assert ("regional_arabic_indic", "pdf") not in submitted
    assert engine.skipped_unrepresentable == [("ssn", "regional_arabic_indic", "pdf")]


def test_engine_with_no_unrepresentable_values_records_nothing():
    class _Plain(BaseVariantGenerator):
        name = "plain"

        def generate(self, value: str) -> Iterator[Variant]:
            yield self._make_variant(value, "plain", "unchanged")

    engine = Engine(adapter=_Recorder(), generators=[_Plain()], strategies=ALL)
    engine.run([PAYLOAD])
    assert engine.skipped_unrepresentable == []


# ── the report ─────────────────────────────────────────────────────────────────


def test_meta_records_what_was_left_out_and_keeps_it_out_of_total():
    adapter = _Recorder()
    engine = Engine(adapter=adapter, generators=[_Gen()], strategies=ALL)
    results = engine.run([PAYLOAD])
    meta = json.loads(
        JsonReporter(skipped_unrepresentable=engine.skipped_unrepresentable).render(
            results
        )
    )["meta"]
    assert meta["total"] == 8
    assert meta["error"] == 0
    assert meta["skipped_unrepresentable"] == {
        "count": 4,
        "techniques": ["split", "tab"],
        "strategies": ["docx", "pdf", "xlsx"],
    }


def test_meta_block_is_present_and_empty_by_default():
    meta = json.loads(JsonReporter().render([]))["meta"]
    assert meta["skipped_unrepresentable"] == {
        "count": 0,
        "techniques": [],
        "strategies": [],
    }
