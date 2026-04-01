from evadex.core.result import Payload, Variant, ScanResult, PayloadCategory, SeverityLevel


def test_scan_result_severity_pass():
    p = Payload("val", PayloadCategory.CREDIT_CARD, "test")
    v = Variant("val", "gen", "tech", "desc")
    r = ScanResult(payload=p, variant=v, detected=True)
    assert r.severity == SeverityLevel.PASS


def test_scan_result_severity_fail():
    p = Payload("val", PayloadCategory.CREDIT_CARD, "test")
    v = Variant("val", "gen", "tech", "desc")
    r = ScanResult(payload=p, variant=v, detected=False)
    assert r.severity == SeverityLevel.FAIL


def test_scan_result_severity_error():
    p = Payload("val", PayloadCategory.CREDIT_CARD, "test")
    v = Variant("val", "gen", "tech", "desc")
    r = ScanResult(payload=p, variant=v, detected=False, error="timeout")
    assert r.severity == SeverityLevel.ERROR


def test_to_dict():
    p = Payload("val", PayloadCategory.CREDIT_CARD, "test")
    v = Variant("val", "gen", "tech", "desc")
    r = ScanResult(payload=p, variant=v, detected=True, duration_ms=12.5)
    d = r.to_dict()
    assert d["detected"] is True
    assert d["duration_ms"] == 12.5
    assert d["severity"] == "pass"
