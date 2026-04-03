import json
from evadex.reporters.json_reporter import JsonReporter
from evadex.core.result import ScanResult, Payload, Variant, PayloadCategory


def _make_result(detected: bool, error: str = None) -> ScanResult:
    payload = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    variant = Variant("4532015112830366", "structural", "uppercase", "Uppercased")
    return ScanResult(payload=payload, variant=variant, detected=detected, error=error)


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


def test_pass_rate_calculation():
    reporter = JsonReporter()
    results = [_make_result(True), _make_result(True), _make_result(False)]
    data = json.loads(reporter.render(results))
    assert data["meta"]["pass_rate"] == round(2 / 3 * 100, 1)


def test_error_counted_separately():
    reporter = JsonReporter()
    results = [_make_result(False, error="timeout"), _make_result(True)]
    data = json.loads(reporter.render(results))
    assert data["meta"]["error"] == 1
    assert data["meta"]["pass"] == 1
    assert data["meta"]["fail"] == 0


def test_scanner_label_in_meta():
    reporter = JsonReporter(scanner_label="rust-2.0.0")
    data = json.loads(reporter.render([_make_result(True)]))
    assert data["meta"]["scanner"] == "rust-2.0.0"


def test_summary_by_category_is_sorted():
    """Category keys must be sorted for deterministic output."""
    ssn_payload = Payload("123-45-6789", PayloadCategory.SSN, "US SSN")
    cc_payload = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    variant = Variant("x", "structural", "uppercase", "Uppercased")
    results = [
        ScanResult(payload=ssn_payload, variant=variant, detected=False),
        ScanResult(payload=cc_payload, variant=variant, detected=True),
    ]
    data = json.loads(JsonReporter().render(results))
    keys = list(data["meta"]["summary_by_category"].keys())
    assert keys == sorted(keys)


def test_all_result_fields_present():
    """Every result dict must have all documented fields."""
    data = json.loads(JsonReporter().render([_make_result(True)]))
    r = data["results"][0]
    for field in ("payload", "variant", "detected", "severity", "duration_ms", "error", "raw_response"):
        assert field in r, f"Missing field: {field}"
    for field in ("value", "category", "category_type", "label"):
        assert field in r["payload"], f"Missing payload field: {field}"
    for field in ("value", "generator", "technique", "transform_name", "strategy"):
        assert field in r["variant"], f"Missing variant field: {field}"
