"""Detection counts only findings relevant to the payload's category."""

from evadex.core.relevance import (
    RELEVANT_SCANNER_LABELS,
    classify_detection,
    is_match_relevant,
)
from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant
from evadex.payloads.tiers import get_tier_categories

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
    assert classify_detection("wkn_num", [SEDOL]) == (True, True)


def test_map_keys_are_payload_categories():
    values = {c.value for c in PayloadCategory}
    # "entropy" is the falsepos harness's pseudo-category, not a payload one.
    assert set(RELEVANT_SCANNER_LABELS) - values == {"entropy"}


def test_northam_tier_is_mapped():
    # Siphon has no rule for these, so they stay unfiltered.
    no_siphon_rule = {"ca_bank_account", "mifid_tx_id", "reuters_ric", "wkn_num"}
    northam = {c.value for c in get_tier_categories("northam")}
    assert northam - set(RELEVANT_SCANNER_LABELS) == no_siphon_rule


def test_format_collisions_are_not_detections():
    # Observed against Siphon: a 17-digit SAR number trips the VIN rule, a
    # Quebec DL trips Florida DL, a BC CareCard trips US phone.
    vin = {"category": "Vehicle Identification", "sub_category": "VIN"}
    florida = {
        "category": "North America - United States",
        "sub_category": "Florida DL",
    }
    phone = {
        "category": "North America - United States",
        "sub_category": "US Phone Number",
    }
    assert classify_detection("reg_sar", [vin]) == (False, True)
    assert classify_detection("ca_qc_drivers", [florida]) == (False, True)
    assert classify_detection("ca_bc_carecard", [phone]) == (False, True)


def test_northam_relevant_matches():
    florida = {
        "category": "North America - United States",
        "sub_category": "Florida DL",
    }
    assert is_match_relevant("us_dl", florida)
    assert is_match_relevant("us_dl", {"sub_category": "New Hampshire DL"})
    assert is_match_relevant("card_track2", {"sub_category": "PAN"})
    assert is_match_relevant("card_track2", CARD)
    assert is_match_relevant("cins_num", {"sub_category": "CUSIP"})
    assert is_match_relevant("ca_gst_hst", {"sub_category": "Canada BN"})
    assert not is_match_relevant("cins_num", {"sub_category": "Investment Restricted"})


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
