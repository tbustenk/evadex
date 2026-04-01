from evadex.reporters.html_reporter import HtmlReporter
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory


def _make_result(detected: bool) -> ScanResult:
    payload = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    variant = Variant("4532015112830366", "structural", "uppercase", "Uppercased")
    return ScanResult(payload=payload, variant=variant, detected=detected)


def test_html_contains_table():
    reporter = HtmlReporter()
    output = reporter.render([_make_result(True)])
    assert "<table>" in output
    assert "evadex DLP Evasion Report" in output


def test_detected_badge():
    reporter = HtmlReporter()
    output = reporter.render([_make_result(True)])
    assert "detected" in output


def test_evaded_badge():
    reporter = HtmlReporter()
    output = reporter.render([_make_result(False)])
    assert "evaded" in output
