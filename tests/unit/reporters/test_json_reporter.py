import json
from evadex.reporters.json_reporter import JsonReporter
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory


def _make_result(detected: bool) -> ScanResult:
    payload = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    variant = Variant("4532015112830366", "structural", "uppercase", "Uppercased")
    return ScanResult(payload=payload, variant=variant, detected=detected)


def test_json_structure():
    reporter = JsonReporter()
    results = [_make_result(True), _make_result(False)]
    output = reporter.render(results)
    data = json.loads(output)
    assert "meta" in data
    assert "results" in data
    assert data["meta"]["total"] == 2
    assert data["meta"]["pass"] == 1
    assert data["meta"]["fail"] == 1


def test_empty_results():
    reporter = JsonReporter()
    output = reporter.render([])
    data = json.loads(output)
    assert data["meta"]["total"] == 0
