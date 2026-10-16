"""A variant whose value XML cannot carry has no DOCX/XLSX fixture.

Before 3.41.1 the engine submitted it anyway; python-docx and openpyxl
refused ("All strings must be XML compatible"), and the submission was
recorded as an *error* — 185 per XML strategy on a northam run, all from
``barcode_split``'s U+001E marker — which ``evadex ci --max-error-rate``
counted against the scanner. The scanner was never asked.
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
    representable,
    unrepresentable_chars,
)
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.reporters.json_reporter import JsonReporter
from evadex.variants.base import BaseVariantGenerator

SSN = "742-18-5503"
PAYLOAD = Payload(SSN, PayloadCategory.SSN, "US SSN")
ALL = ["text", "docx", "pdf", "xlsx"]


class _Gen(BaseVariantGenerator):
    name = "stub"

    def generate(self, value: str) -> Iterator[Variant]:
        yield self._make_variant(value, "plain", "unchanged")
        yield self._make_variant(value[:5] + "\x1e" + value[5:], "split", "record separator")
        yield self._make_variant(value + "\t", "tab", "trailing tab")


class _Recorder(BaseAdapter):
    def __init__(self):
        super().__init__({})
        self.seen: list[tuple[str, str]] = []

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        self.seen.append((variant.technique, variant.strategy))
        return ScanResult(payload=payload, variant=variant, detected=True)


# ── the predicate ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("strategy", sorted(XML_STRATEGIES))
def test_c0_controls_are_not_representable_in_xml_containers(strategy):
    assert not representable("a\x1eb", strategy)
    assert not representable("a\x00b", strategy)
    assert unrepresentable_chars("a\x1eb\x1cc\x1eb", strategy) == ["\x1c", "\x1e"]


@pytest.mark.parametrize("strategy", sorted(XML_STRATEGIES))
def test_tab_newline_and_cr_are_fine_in_xml(strategy):
    assert representable("a\tb\nc\rd", strategy)
    assert unrepresentable_chars("a\tb", strategy) == []


@pytest.mark.parametrize("strategy", ["text", "pdf"])
def test_non_xml_strategies_carry_anything(strategy):
    assert representable("a\x1eb\x00c", strategy)
    assert unrepresentable_chars("a\x1eb", strategy) == []


def test_description_names_the_code_point_and_the_format():
    line = describe_unrepresentable("4\x1e5", "docx")
    assert "U+001E" in line and "docx" in line and "no docx fixture" in line


# ── the engine ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("streaming", [True, False])
def test_engine_skips_xml_strategies_for_unrepresentable_values_only(streaming):
    adapter = _Recorder()
    engine = Engine(adapter=adapter, generators=[_Gen()], strategies=ALL, streaming=streaming)
    results = engine.run([PAYLOAD])

    submitted = set(adapter.seen)
    # The control-character variant goes to text and pdf, not to the XML pair.
    assert ("split", "text") in submitted and ("split", "pdf") in submitted
    assert ("split", "docx") not in submitted and ("split", "xlsx") not in submitted
    # Everything else still goes everywhere, including a tab, which XML allows.
    for tech in ("plain", "tab"):
        assert {(tech, s) for s in ALL} <= submitted

    assert len(results) == 3 * 4 - 2
    assert not any(r.error for r in results)
    assert sorted(engine.skipped_unrepresentable) == [
        ("ssn", "split", "docx"),
        ("ssn", "split", "xlsx"),
    ]


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
        JsonReporter(skipped_unrepresentable=engine.skipped_unrepresentable).render(results)
    )["meta"]
    assert meta["total"] == 10
    assert meta["error"] == 0
    assert meta["skipped_unrepresentable"] == {
        "count": 2,
        "techniques": ["split"],
        "strategies": ["docx", "xlsx"],
    }


def test_meta_block_is_present_and_empty_by_default():
    meta = json.loads(JsonReporter().render([]))["meta"]
    assert meta["skipped_unrepresentable"] == {"count": 0, "techniques": [], "strategies": []}
