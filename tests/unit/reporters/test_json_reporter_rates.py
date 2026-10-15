"""`meta.detection_rate` excludes errored submissions; `meta.error_rate` and
`meta.seed` are recorded. `pass_rate` keeps its pre-3.41.0 meaning."""

import json

from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.reporters.json_reporter import JsonReporter


def _result(detected: bool, error: str = None) -> ScanResult:
    payload = Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa")
    variant = Variant("4532015112830366", "structural", "uppercase", "Uppercased")
    return ScanResult(payload=payload, variant=variant, detected=detected, error=error)


def test_detection_rate_excludes_errors_pass_rate_does_not():
    results = [
        _result(True),
        _result(True),
        _result(False),
        _result(False, error="timeout"),
    ]
    meta = json.loads(JsonReporter().render(results))["meta"]
    assert meta["pass_rate"] == 50.0
    assert meta["detection_rate"] == round(2 / 3 * 100, 1)
    assert meta["error_rate"] == 25.0
    assert meta["error"] == 1


def test_all_errors_gives_zero_detection_rate_not_a_crash():
    meta = json.loads(JsonReporter().render([_result(False, error="x")]))["meta"]
    assert meta["detection_rate"] == 0.0
    assert meta["error_rate"] == 100.0


def test_empty_results_rates_are_zero():
    meta = json.loads(JsonReporter().render([]))["meta"]
    assert meta["detection_rate"] == 0.0
    assert meta["error_rate"] == 0.0


def test_seed_recorded_in_meta():
    assert json.loads(JsonReporter(seed=1234).render([]))["meta"]["seed"] == 1234
    assert json.loads(JsonReporter().render([]))["meta"]["seed"] is None
