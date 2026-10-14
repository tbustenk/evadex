"""evadex matches — scanner findings grouped by confidence band."""

import json

from click.testing import CliRunner

from evadex.cli.app import main
from evadex.cli.commands.matches import _clip, summarize_matches


def _result(category, technique, matches):
    return {
        "payload": {"value": "x", "category": category, "label": "x"},
        "variant": {"value": "x", "technique": technique},
        "detected": bool(matches),
        "raw_response": {"matches": matches},
    }


VISA = {
    "category": "Credit Card Numbers",
    "sub_category": "Visa",
    "text": "4111",
    "confidence": 0.95,
}
VISA_MED = {**VISA, "confidence": 0.81}
PHONE = {
    "category": "North America - United States",
    "sub_category": "US Phone Number",
    "text": "411-111",
    "confidence": 0.4,
}

RESULTS = [
    _result("credit_card", "zero_width_zwj", [VISA, PHONE]),
    _result("credit_card", "plain", [VISA_MED]),
    _result("credit_card", "base64", []),
    _result("ca_bank_account", "plain", [PHONE]),
    # Adapters without per-match detail store a non-list or nothing.
    {"payload": {"category": "credit_card"}, "variant": {}, "raw_response": {}},
]


def test_bands_and_counts():
    s = summarize_matches(RESULTS)
    assert s["variants_scanned"] == 5
    assert s["variants_with_matches"] == 3
    assert s["bands"]["high"] == {"matches": 1, "variants": 1, "rules": 1}
    assert s["bands"]["medium"] == {"matches": 1, "variants": 1, "rules": 1}
    # The phone rule fired on a credit card (collision) and on a WKN
    # (no relevance entry) — separate rows.
    assert s["bands"]["low"] == {"matches": 2, "variants": 2, "rules": 2}


def test_relevance_verdicts():
    s = summarize_matches(RESULTS)
    assert s["rules"]["high"][0]["relevance"] == "relevant"
    verdicts = {
        r["payload_categories"].popitem()[0]: r["relevance"] for r in s["rules"]["low"]
    }
    assert verdicts == {"credit_card": "collision", "ca_bank_account": "unmapped"}


def test_rule_row_detail():
    row = summarize_matches(RESULTS)["rules"]["high"][0]
    assert row["rule"] == "Visa"
    assert row["scanner_category"] == "Credit Card Numbers"
    assert row["example"] == "4111"
    assert row["example_technique"] == "zero_width_zwj"
    assert row["min_confidence"] == row["max_confidence"] == 0.95


def test_custom_bands_move_matches():
    s = summarize_matches(RESULTS, bands=(0.8, 0.3))
    assert s["bands"]["high"]["matches"] == 2
    assert s["bands"]["medium"]["matches"] == 2
    assert s["bands"]["low"]["matches"] == 0


def test_category_and_min_confidence_filters():
    s = summarize_matches(RESULTS, category="ca_bank_account")
    assert s["variants_scanned"] == 1
    s = summarize_matches(RESULTS, min_confidence=0.5)
    assert s["bands"]["low"]["matches"] == 0
    assert s["variants_with_matches"] == 2


def test_clip_shows_invisible_characters():
    assert _clip("4\u200b1\u200d1\t1\n") == "4·1·1·1⏎"
    assert _clip("9" * 50, width=10) == "9" * 9 + "…"


def _write_scan(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps({"meta": {}, "results": RESULTS}), encoding="utf-8")
    return str(path)


def test_cli_json(tmp_path):
    res = CliRunner().invoke(
        main, ["matches", _write_scan(tmp_path), "--format", "json"]
    )
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert data["thresholds"] == {"high": 0.9, "medium": 0.6}
    assert data["rules"]["high"][0]["rule"] == "Visa"


def test_cli_json_no_examples(tmp_path):
    res = CliRunner().invoke(
        main, ["matches", _write_scan(tmp_path), "--format", "json", "--no-examples"]
    )
    row = json.loads(res.stdout)["rules"]["high"][0]
    assert "example" not in row and "example_technique" not in row


def test_cli_table(tmp_path):
    res = CliRunner().invoke(main, ["matches", _write_scan(tmp_path)])
    assert res.exit_code == 0, res.output
    assert "High confidence" in res.output
    assert "collision" in res.output


def test_cli_rejects_bad_bands(tmp_path):
    res = CliRunner().invoke(
        main, ["matches", _write_scan(tmp_path), "--bands", "0.5,0.9"]
    )
    assert res.exit_code == 2
    assert "medium < high" in res.output


def test_cli_rejects_non_scan_file(tmp_path):
    path = tmp_path / "x.json"
    path.write_text("[]", encoding="utf-8")
    res = CliRunner().invoke(main, ["matches", str(path)])
    assert res.exit_code == 1
