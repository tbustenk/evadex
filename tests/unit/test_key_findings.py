"""Unit tests for _key_findings() in cli/commands/scan.py."""

import io
import pytest
from rich.console import Console
from evadex.cli.commands.scan import _key_findings
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory, SeverityLevel


def _make_result(generator, technique, category, strategy, detected):
    p = Payload("4532015112830366", category, category.value)
    v = Variant("variant", generator, technique, "desc", strategy=strategy)
    return ScanResult(payload=p, variant=v, detected=detected)


def _capture(results):
    """Run _key_findings and return plain-text output."""
    buf = io.StringIO()
    console = Console(file=buf, highlight=False, markup=False, no_color=True)
    _key_findings(results, console)
    return buf.getvalue()


# ── edge cases ────────────────────────────────────────────────────────────────

def test_no_results_produces_no_output():
    assert _capture([]) == ""


def test_all_detected_reports_clean():
    results = [_make_result("encoding", "base64", PayloadCategory.CREDIT_CARD, "text", True)]
    out = _capture(results)
    assert "Key Findings" in out
    assert "no bypass" in out.lower() or "detected all" in out.lower()


# ── finding 1: top bypass generator ──────────────────────────────────────────

def test_highest_bypass_generator_named():
    results = [
        _make_result("encoding", "base64", PayloadCategory.CREDIT_CARD, "text", False),
        _make_result("encoding", "hex",    PayloadCategory.CREDIT_CARD, "text", False),
        _make_result("delimiter", "space", PayloadCategory.CREDIT_CARD, "text", True),
    ]
    out = _capture(results)
    assert "Key Findings" in out
    assert "Encoding obfuscation" in out  # label for "encoding"


def test_bypass_rate_shown_in_finding():
    results = [
        _make_result("encoding", "base64", PayloadCategory.CREDIT_CARD, "text", False),
        _make_result("encoding", "hex",    PayloadCategory.CREDIT_CARD, "text", True),
    ]
    out = _capture(results)
    assert "50.0%" in out or "50%" in out


# ── finding 4: strategy gap ───────────────────────────────────────────────────

def test_file_strategy_gap_reported_when_significant():
    results = (
        # text: 0% bypass (2 detected)
        [_make_result("encoding", "b64", PayloadCategory.CREDIT_CARD, "text", True)] * 2
        # docx: 100% bypass (2 evaded)
        + [_make_result("encoding", "b64", PayloadCategory.CREDIT_CARD, "docx", False)] * 2
    )
    out = _capture(results)
    # 100% - 0% = 100pp gap, should be mentioned
    assert "extraction" in out.lower() or "file" in out.lower() or "docx" in out.lower() or "pp" in out.lower()


def test_no_strategy_finding_when_text_only():
    results = [
        _make_result("encoding", "b64", PayloadCategory.CREDIT_CARD, "text", False),
        _make_result("encoding", "b64", PayloadCategory.SSN,         "text", True),
    ]
    out = _capture(results)
    # No strategy gap finding when only one strategy used
    assert "extraction" not in out.lower()


# ── finding 5: zero-bypass generator ─────────────────────────────────────────

def test_zero_bypass_generator_reported():
    results = [
        _make_result("encoding",  "b64",   PayloadCategory.CREDIT_CARD, "text", False),
        _make_result("delimiter", "space", PayloadCategory.CREDIT_CARD, "text", True),
        _make_result("delimiter", "tab",   PayloadCategory.CREDIT_CARD, "text", True),
    ]
    out = _capture(results)
    assert "Delimiter variation" in out
    assert "0%" in out


def test_zero_bypass_not_reported_when_too_many():
    """If many generators all show 0% bypass, don't clutter the output."""
    zero_gens = ["delimiter", "splitting", "leetspeak", "structural", "morse_code"]
    results = [
        _make_result("encoding", "b64", PayloadCategory.CREDIT_CARD, "text", False),
    ] + [
        _make_result(g, "t", PayloadCategory.CREDIT_CARD, "text", True)
        for g in zero_gens
    ]
    out = _capture(results)
    # When > 4 generators have 0% bypass, the finding is suppressed
    assert out.count("0% bypass") == 0


# ── generator label mapping ───────────────────────────────────────────────────

def test_unknown_generator_uses_raw_name():
    from evadex.cli.commands.scan import _gen_label
    assert _gen_label("some_future_generator") == "some_future_generator"


def test_all_known_generators_have_labels():
    from evadex.cli.commands.scan import _GENERATOR_LABELS
    known = {
        "unicode_encoding", "delimiter", "splitting", "leetspeak",
        "regional_digits", "structural", "encoding", "context_injection",
        "unicode_whitespace", "bidirectional", "soft_hyphen", "morse_code",
    }
    assert known == set(_GENERATOR_LABELS.keys())
