"""Which scanner findings count for which evadex payload category.

A scanner that fires on *something* in a submitted variant has not
necessarily caught the value under test: a credit-card variant can trip a
SEDOL, an AWS-key or a loan-ID rule on a fragment of its encoding, and the
keyword sentence evadex wraps around a value can trip classification rules on
its own. Counting those as detections inflates detection rates and hides real
bypasses; counting them as false positives (the falsepos harness) inflates
false-positive rates the same way.

:data:`RELEVANT_SCANNER_LABELS` lists, per evadex category, the scanner-side
labels that count. Matches are checked against Siphon's ``sub_category``
first, then ``category``, case-insensitively. A category with no entry is
unfiltered — any finding counts — so scanners and categories the map does
not cover keep the previous behaviour.
"""

from __future__ import annotations

from collections.abc import Iterable

RELEVANT_SCANNER_LABELS: dict[str, set[str]] = {
    "credit_card": {
        "credit card numbers",
        "visa",
        "mastercard",
        "amex",
        "american express",
        "discover",
        "diners club",
        "jcb",
        "unionpay",
    },
    "ssn": {"usa ssn", "north america - united states"},
    "sin": {"canada sin"},
    "iban": {"iban generic", "iban"},
    "email": {"email address", "email"},
    "phone": {
        "us phone number",
        "canada phone number",
        "phone number",
        "international phone",
        "e.164 phone",
        # UK/regional phone patterns sometimes fire on NANP-shaped numbers
        # too — those still count (the scanner flagged a phone as a phone,
        # just wrong-region).
        "uk phone number",
        "eu phone number",
    },
    "ca_ramq": {"quebec hc"},
    "entropy": {
        # "Generic" high-entropy secrets we deliberately construct FPs for.
        "aws access key",
        "aws secret key",
        "gcp service account",
        "private key",
        "rsa private key",
        "ssh private key",
        "jwt",
        "generic api key",
        "generic secret",
        "slack token",
        "github token",
        "stripe key",
    },
}


def is_match_relevant(cat_name: str, match: dict) -> bool:
    """Return True if *match* (a Siphon-style match dict) counts for *cat_name*.

    When *cat_name* has no entry in :data:`RELEVANT_SCANNER_LABELS`, every
    match counts.
    """
    relevant = RELEVANT_SCANNER_LABELS.get(cat_name)
    if not relevant:
        return True
    if not isinstance(match, dict):
        return False
    sub = (match.get("sub_category") or "").strip().lower()
    if sub and sub in relevant:
        return True
    cat = (match.get("category") or "").strip().lower()
    return bool(cat) and cat in relevant


def classify_detection(cat_name: str, matches: Iterable) -> tuple[bool, bool]:
    """Return ``(detected, detected_any)`` for a scanner's *matches*.

    ``detected_any`` is the legacy rule — the scanner returned any finding.
    ``detected`` additionally requires a finding relevant to *cat_name*;
    for a category with no relevance entry the two are the same.
    """
    matches = list(matches or [])
    detected_any = len(matches) > 0
    detected = any(is_match_relevant(cat_name, m) for m in matches)
    return detected, detected_any
