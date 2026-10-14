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

_CARD_LABELS = {
    "credit card numbers",
    "visa",
    "mastercard",
    "amex",
    "american express",
    "discover",
    "diners club",
    "jcb",
    "unionpay",
}

_PHONE_LABELS = {
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
}

_IBAN_LABELS = {"iban generic", "iban"}
_DATE_LABELS = {"date of birth", "date us", "date eu", "date iso"}
_ROUTING_LABELS = {"aba routing number", "usa routing number"}
_LOAN_LABELS = {"loan number", "universal loan identifier"}
_TRAVELLER_LABELS = {"canada nexus", "us known traveler number"}
_US_PASSPORT_LABELS = {"usa passport", "usa passport card"}

_US_DL_STATES = (
    "alabama", "alaska", "arizona", "arkansas", "california", "colorado",
    "connecticut", "dc", "delaware", "florida", "georgia", "hawaii", "idaho",
    "illinois", "indiana", "iowa", "kansas", "kentucky", "louisiana", "maine",
    "maryland", "massachusetts", "michigan", "minnesota", "mississippi",
    "missouri", "montana", "nebraska", "nevada", "new hampshire",
    "new jersey", "new mexico", "new york", "north carolina", "north dakota",
    "ohio", "oklahoma", "oregon", "pennsylvania", "rhode island",
    "south carolina", "south dakota", "tennessee", "texas", "utah", "vermont",
    "virginia", "washington", "west virginia", "wisconsin", "wyoming",
)  # fmt: skip
# us_dl payloads span every state, so any state's DL rule counts.
_US_DL_LABELS = {f"{s} dl" for s in _US_DL_STATES} | {"generic us dl"}

RELEVANT_SCANNER_LABELS: dict[str, set[str]] = {
    "credit_card": _CARD_LABELS,
    # Sub-category only: the category label "North America - United States"
    # also covers US phone numbers and every state DL, which are not SSNs.
    "ssn": {"usa ssn"},
    "sin": {"canada sin"},
    "iban": _IBAN_LABELS,
    "email": {"email address", "email"},
    "phone": _PHONE_LABELS,
    "ca_ramq": {"quebec hc"},
    # ── northam tier ─────────────────────────────────────────────────────
    # Labels are Siphon sub_categories (crates/siphon-core/src/patterns).
    # Not mapped, because Siphon has no rule for them: ca_bank_account,
    # mifid_tx_id (heuristic: a MiFID TRN has no fixed format).
    #
    # Canadian provincial IDs: the province's own rule only. A Quebec DL
    # that trips Florida DL is a format collision, not a catch.
    "ca_ab_dl": {"alberta dl"},
    "ca_bc_drivers": {"british columbia dl"},
    "ca_mb_drivers": {"manitoba dl"},
    "ca_nb_drivers": {"new brunswick dl"},
    "ca_nl_drivers": {"newfoundland dl"},
    "ca_ns_drivers": {"nova scotia dl"},
    "ca_nu_dl": {"nunavut dl"},
    "ca_nwt_dl": {"nwt dl"},
    "ca_on_drivers": {"ontario dl"},
    "ca_pei_drivers": {"pei dl"},
    "ca_qc_drivers": {"quebec dl"},
    "ca_sk_drivers": {"saskatchewan dl"},
    "ca_yt_dl": {"yukon dl"},
    "ca_ab_health": {"alberta hc"},
    "ca_bc_carecard": {"bc hc"},
    "ca_mb_health": {"manitoba hc"},
    "ca_nb_health": {"new brunswick hc"},
    "ca_nl_health": {"newfoundland hc"},
    "ca_ns_health": {"nova scotia hc"},
    "ca_ontario_health": {"ontario hc"},
    "ca_pei_health": {"pei hc"},
    "ca_sk_health": {"saskatchewan hc"},
    # Canadian federal
    "ca_passport": {"canada passport"},
    "ca_pr_card": {"canada pr card"},
    "ca_nexus": _TRAVELLER_LABELS,
    # A GST/HST account is the 9-digit BN plus an RT program suffix.
    "ca_business_number": {"canada bn", "canada bn root"},
    "ca_gst_hst": {"canada bn"},
    "ca_postal_code": {"canada postal code"},
    "ca_transit_number": {"canada transit number", "canada bank code"},
    # US federal / state
    "us_dl": _US_DL_LABELS,
    "us_passport": _US_PASSPORT_LABELS,
    "us_passport_card": _US_PASSPORT_LABELS,
    "us_ktn": _TRAVELLER_LABELS,
    "us_ein": {"usa ein"},
    "us_itin": {"usa itin"},
    "us_mbi": {"us mbi"},
    "us_npi": {"us npi"},
    "us_dea": {"us dea number", "dea number"},
    "us_phone": _PHONE_LABELS,
    "us_zip4": {"us zip+4 code"},
    "us_routing": _ROUTING_LABELS,
    "aba_routing": _ROUTING_LABELS,
    # Cards. Track data embeds the PAN, so catching the PAN catches it.
    "masked_pan": {"masked pan"},
    "card_expiry": {"card expiry"},
    "card_track": {"track 1 data", "pan"} | _CARD_LABELS,
    "card_track2": {"track 2 data", "pan"} | _CARD_LABELS,
    "pin_block": {"pin block"},
    "hsm_key": {"hsm key"},
    "encryption_key": {"encryption key"},
    # Banking and payments
    "de_iban": {"germany iban"} | _IBAN_LABELS,
    "es_iban": _IBAN_LABELS,
    "fr_iban": _IBAN_LABELS,
    "nl_iban": _IBAN_LABELS,
    "swift_bic": {"swift/bic"},
    "micr": {"micr line"},
    "ach_batch": {"ach batch number"},
    "ach_trace": {"ach trace number"},
    "chips_uid": {"chips uid"},
    "fedwire_imad": {"fedwire imad"},
    "sepa_ref": {"sepa reference"},
    "wire_ref": {"wire reference number"},
    "mt103_ref": {"wire reference number"},
    "bank_ref": {"internal account ref"},
    "teller_id": {"teller id"},
    "account_balance": {"account balance", "balance with currency code"},
    "financial_amount": {
        "balance with currency code",
        "account balance",
        "income amount",
    },
    "income_amount": {"income amount"},
    "dti_ratio": {"dti ratio"},
    "ltv_ratio": {"ltv ratio"},
    "loan_number": _LOAN_LABELS,
    "loan_num_short": _LOAN_LABELS,
    "mers_min": {"mers min"},
    "insurance_policy": {"insurance policy number"},
    # Securities. CINS is the CUSIP International Numbering System — same
    # 9-character layout, so a CUSIP rule is the right catch.
    "cusip_num": {"cusip"},
    "cins_num": {"cusip"},
    "isin": {"isin"},
    "sedol_num": {"sedol"},
    "figi_num": {"figi"},
    "lei_num": {"lei"},
    "valor_num": {"valor"},
    "wkn_num": {"wkn"},  # siphon-core 2.10.0
    "reuters_ric": {"reuters ric"},  # siphon-core 2.10.0
    "ticker_symbol": {"ticker symbol"},
    # Regulatory
    "aml_case_id": {"aml case id"},
    "reg_sar": {"sar filing number"},
    "reg_ctr": {"ctr number"},
    "reg_fincen": {"fincen report number"},
    "reg_compliance_case": {"compliance case number"},
    # Personal / identity
    "dob": _DATE_LABELS,
    "date_iso": _DATE_LABELS,
    "employee_id": {"employee id"},
    "session_id": {"session id"},
    "biometric_id": {"biometric template id", "biometric hash"},
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
