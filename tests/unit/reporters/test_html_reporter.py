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


def test_html_confidence_chart_appears_when_confidence_present():
    """Detected results with a confidence score must render the histogram."""
    reporter = HtmlReporter()
    results = []
    for conf in (0.95, 0.88, 0.55):
        p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
        v = Variant("4532015112830366", "structural", "no_delim", "No delim")
        results.append(ScanResult(payload=p, variant=v, detected=True, confidence=conf))
    output = reporter.render(results)
    assert "Confidence distribution" in output
    assert "0.9-1.0" in output


def test_html_confidence_chart_hidden_when_no_confidence():
    """No confidence data → no histogram section."""
    reporter = HtmlReporter()
    output = reporter.render([_make_result(True)])
    assert "Confidence distribution" not in output


def test_html_worst_techniques_section_when_evasions_present():
    """Evasions should surface the 'Top evading techniques' section."""
    reporter = HtmlReporter()
    # 4 variants of the same technique: 3 evade → should appear as worst.
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    v_fail = Variant("zzz", "unicode_whitespace", "zero_width_space", "ZWSP")
    v_pass = Variant("4532015112830366", "unicode_whitespace", "zero_width_space", "ZWSP")
    results = [
        ScanResult(payload=p, variant=v_fail, detected=False),
        ScanResult(payload=p, variant=v_fail, detected=False),
        ScanResult(payload=p, variant=v_fail, detected=False),
        ScanResult(payload=p, variant=v_pass, detected=True),
    ]
    output = reporter.render(results)
    assert "Top evading techniques" in output
    assert "zero_width_space" in output
    # evasion rate 3/4 = 75%
    assert "75.0%" in output


def test_html_suggestions_section_when_evasions_present():
    """The 'what to fix' section should render when known-technique evasions exist."""
    reporter = HtmlReporter()
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    # Use a technique name that the suggestions module knows about.
    v = Variant("zzz", "unicode_whitespace", "zero_width_zwsp", "ZWSP")
    results = [ScanResult(payload=p, variant=v, detected=False)]
    output = reporter.render(results)
    assert "What to fix" in output


def test_html_exec_summary_specific_when_evasions_present():
    """Exec summary mentions the worst technique, not just the detection %."""
    reporter = HtmlReporter()
    p = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    v = Variant("zzz", "unicode_whitespace", "zero_width_space", "ZWSP")
    results = [
        ScanResult(payload=p, variant=v, detected=False),
        ScanResult(payload=p, variant=v, detected=False),
        ScanResult(payload=p, variant=v, detected=False),
        ScanResult(payload=p, variant=v, detected=True),
    ]
    output = reporter.render(results)
    # Exec summary calls out the specific technique that slipped past
    assert "zero_width_space" in output
    assert "Scanner missed" in output
