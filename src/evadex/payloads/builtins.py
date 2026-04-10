import re
from evadex.core.result import Payload, PayloadCategory


BUILTIN_PAYLOADS = [
    # --- Credit cards ---
    Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit"),
    Payload("378282246310005",  PayloadCategory.CREDIT_CARD, "Amex 15-digit"),
    Payload("5105105105105100", PayloadCategory.CREDIT_CARD, "Mastercard 16-digit"),
    Payload("6011111111111117", PayloadCategory.CREDIT_CARD, "Discover 16-digit"),
    Payload("3530111333300000", PayloadCategory.CREDIT_CARD, "JCB 16-digit"),
    Payload("6250941006528599", PayloadCategory.CREDIT_CARD, "UnionPay 16-digit"),
    Payload("30569309025904",   PayloadCategory.CREDIT_CARD, "Diners Club 14-digit"),

    # --- National IDs / government ---
    Payload("123-45-6789",      PayloadCategory.SSN,         "US SSN"),
    Payload("046 454 286",      PayloadCategory.SIN,         "Canada SIN"),
    Payload("340000136",        PayloadCategory.US_PASSPORT, "US Passport number"),       # fires as CUSIP (9-digit collision); context_required for USA Passport pattern
    Payload("123 456 78",       PayloadCategory.AU_TFN,      "Australia TFN"),
    Payload("86095742719",      PayloadCategory.DE_TAX_ID,   "Germany Steuer-IdNr"),      # fires as Geohash (11-digit/charset collision); context_required for Germany Tax ID
    Payload("282097505604213",  PayloadCategory.FR_INSEE,    "France INSEE (NIR)"),       # fires as PAN (15-digit collision); context_required for France NIR

    # --- Banking ---
    Payload("GB82WEST12345698765432",    PayloadCategory.IBAN,        "UK IBAN"),
    Payload("DE89370400440532013000",    PayloadCategory.IBAN,        "Germany IBAN"),
    Payload("FR7630006000011234567890189", PayloadCategory.IBAN,      "France IBAN"),
    Payload("ES9121000418450200051332",  PayloadCategory.IBAN,        "Spain IBAN"),
    Payload("DEUTDEDB",                  PayloadCategory.SWIFT_BIC,   "SWIFT/BIC code"),
    Payload("021000021",                 PayloadCategory.ABA_ROUTING, "ABA routing number"),  # fires as CUSIP (9-digit collision); context_required for ABA Routing Number

    # --- Cryptocurrency ---
    Payload("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",       PayloadCategory.BITCOIN,   "Bitcoin legacy address"),
    Payload("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", PayloadCategory.ETHEREUM,  "Ethereum address"),

    # --- Secrets (heuristic) ---
    Payload("AKIAIOSFODNN7EXAMPLE",                         PayloadCategory.AWS_KEY,      "AWS Access Key ID"),
    Payload("ghp_16C7e42F292c6912E7710c838347Ae178B4a",    PayloadCategory.GITHUB_TOKEN, "GitHub classic token"),
    Payload("sk_test_4eC39HqLyjWDarjtT7en6bh8Xy9mPqZ",    PayloadCategory.STRIPE_KEY,   "Stripe test secret key"),
    Payload("xoxb-EXAMPLE-BOTTOKEN-abc123def",              PayloadCategory.SLACK_TOKEN, "Slack bot token"),
    Payload(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        PayloadCategory.JWT,
        "Sample JWT",
    ),

    # --- Classification labels (heuristic) ---
    Payload("TOP SECRET",  PayloadCategory.CLASSIFICATION, "Top Secret classification label"),
    Payload("HIPAA",       PayloadCategory.CLASSIFICATION, "HIPAA privacy label"),

    # --- Contact ---
    Payload("test.user@example.com", PayloadCategory.EMAIL, "Email address"),
    Payload("+1-555-867-5309",       PayloadCategory.PHONE, "US phone number"),

    # --- Canadian regional IDs ---
    Payload("BOUD 1234 5678",        PayloadCategory.CA_RAMQ,           "Quebec RAMQ health card"),
    Payload("1234-567-890-AB",       PayloadCategory.CA_ONTARIO_HEALTH, "Ontario health card"),
    Payload("9123456789",            PayloadCategory.CA_BC_CARECARD,    "BC CareCard"),
    Payload("123456789",             PayloadCategory.CA_AB_HEALTH,      "Alberta health card"),
    Payload("A12345678901234",       PayloadCategory.CA_QC_DRIVERS,     "Quebec driver's licence"),
    Payload("A1234-56789-01234",     PayloadCategory.CA_ON_DRIVERS,     "Ontario driver's licence"),
    Payload("1234567",               PayloadCategory.CA_BC_DRIVERS,     "British Columbia driver's licence"),
    Payload("AB123456",              PayloadCategory.CA_PASSPORT,       "Canadian passport"),

    # --- Remaining provincial health cards ---
    Payload("987654321",    PayloadCategory.CA_MB_HEALTH,  "Manitoba health card"),
    Payload("234567890",    PayloadCategory.CA_SK_HEALTH,  "Saskatchewan health card"),
    Payload("1234 567 890", PayloadCategory.CA_NS_HEALTH,  "Nova Scotia health card"),
    Payload("1234567890",   PayloadCategory.CA_NB_HEALTH,  "New Brunswick health card"),
    Payload("123456789012", PayloadCategory.CA_PEI_HEALTH, "PEI health card"),
    Payload("9876543210",   PayloadCategory.CA_NL_HEALTH,  "Newfoundland health card"),

    # --- Remaining provincial driver's licences ---
    Payload("AB-123-456-789", PayloadCategory.CA_MB_DRIVERS, "Manitoba driver's licence"),
    Payload("12345678",       PayloadCategory.CA_SK_DRIVERS, "Saskatchewan driver's licence"),
    Payload("AB1234567",      PayloadCategory.CA_NS_DRIVERS, "Nova Scotia driver's licence"),
    Payload("1234567",        PayloadCategory.CA_NB_DRIVERS, "New Brunswick driver's licence"),
    Payload("123456",         PayloadCategory.CA_PEI_DRIVERS, "PEI driver's licence"),
    Payload("A123456789",     PayloadCategory.CA_NL_DRIVERS, "Newfoundland driver's licence"),

    # --- Canadian corporate identifiers ---
    Payload("111222333",         PayloadCategory.CA_BUSINESS_NUMBER, "Canadian Business Number (BN)"),
    Payload("111222333RT0001",   PayloadCategory.CA_GST_HST,         "Canadian GST/HST registration"),
    Payload("12345-678",         PayloadCategory.CA_TRANSIT_NUMBER,  "Canadian transit/routing number"),
    Payload("12345678",          PayloadCategory.CA_BANK_ACCOUNT,    "Canadian bank account"),
]


def detect_category(value: str) -> PayloadCategory:
    """Auto-detect payload category from value format."""
    v = value.strip()

    # JWT: three base64url segments
    if re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', v):
        return PayloadCategory.JWT

    # AWS access key
    if re.match(r'^AKIA[0-9A-Z]{16}$', v):
        return PayloadCategory.AWS_KEY

    # Email
    if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
        return PayloadCategory.EMAIL

    # IBAN: 2 letter country code + 2 digits + up to 30 alphanumeric
    if re.match(r'^[A-Z]{2}\d{2}[A-Z0-9]{1,30}$', v):
        return PayloadCategory.IBAN

    # US SSN: NNN-NN-NNNN
    if re.match(r'^\d{3}-\d{2}-\d{4}$', v):
        return PayloadCategory.SSN

    # Canada SIN: NNN NNN NNN or NNN-NNN-NNN
    if re.match(r'^\d{3}[ -]\d{3}[ -]\d{3}$', v):
        return PayloadCategory.SIN

    # Phone: starts with + or has country code pattern
    digits_only = re.sub(r'[^\d]', '', v)
    if v.startswith('+') or (v.startswith('1') and len(digits_only) == 11):
        return PayloadCategory.PHONE

    # Credit card: Luhn check on 13-19 digit number
    if re.match(r'^[\d\s\-\.]{13,23}$', v):
        if _luhn_check(digits_only) and 13 <= len(digits_only) <= 19:
            return PayloadCategory.CREDIT_CARD

    return PayloadCategory.UNKNOWN


def _luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    if not number.isdigit():
        return False
    total = 0
    reverse = number[::-1]
    for i, digit in enumerate(reverse):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


HEURISTIC_CATEGORIES = {
    PayloadCategory.JWT,
    PayloadCategory.AWS_KEY,
    PayloadCategory.GITHUB_TOKEN,
    PayloadCategory.STRIPE_KEY,
    PayloadCategory.SLACK_TOKEN,
    PayloadCategory.CLASSIFICATION,
}


def get_payloads(categories=None, include_heuristic: bool = False) -> list[Payload]:
    payloads = BUILTIN_PAYLOADS
    if not include_heuristic:
        payloads = [p for p in payloads if p.category not in HEURISTIC_CATEGORIES]
    if categories:
        payloads = [p for p in payloads if p.category in categories]
    return payloads
