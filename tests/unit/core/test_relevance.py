"""Detection counts only findings relevant to the payload's category."""

from evadex.core.relevance import classify_detection, is_match_relevant
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant

CARD = {"category": "Credit Card Numbers", "sub_category": "Visa"}
SEDOL = {"category": "Securities Identifiers", "sub_category": "SEDOL"}


def test_relevant_match_detected():
    assert classify_detection("credit_card", [CARD]) == (True, True)


def test_unrelated_match_is_not_a_detection():
    # A SEDOL firing on a fragment of an encoded card is not catching the card.
    assert classify_detection("credit_card", [SEDOL]) == (False, True)


def test_mixed_matches_detected():
    assert classify_detection("credit_card", [SEDOL, CARD]) == (True, True)


def test_no_matches():
    assert classify_detection("credit_card", []) == (False, False)
    assert classify_detection("credit_card", None) == (False, False)


def test_unmapped_category_keeps_any_finding_rule():
    assert classify_detection("us_passport", [SEDOL]) == (True, True)


def test_category_fallback_and_case_insensitive():
    assert is_match_relevant("credit_card", {"category": "CREDIT CARD NUMBERS"})
    assert is_match_relevant("ssn", {"sub_category": " USA SSN "})
    assert not is_match_relevant("credit_card", "not-a-dict")


def test_falsepos_reexport_is_the_same_map():
    from evadex.falsepos import generators

    assert generators.is_match_relevant is is_match_relevant


def test_detected_any_round_trips():
    r = ScanResult(
        payload=Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "cc"),
        variant=Variant("x", "g", "t", "n"),
        detected=False,
        detected_any=True,
    )
    d = r.to_dict()
    assert d["detected_any"] is True
    assert ScanResult.from_dict(d).detected_any is True
    # Absent when the adapter does not set it — old JSON stays byte-identical.
    r.detected_any = None
    assert "detected_any" not in r.to_dict()
