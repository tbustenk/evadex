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

    # --- Priority 1: US additional identifiers ---
    Payload("912-34-5678",      PayloadCategory.US_ITIN, "US ITIN (Individual Taxpayer ID)"),
    Payload("12-3456789",       PayloadCategory.US_EIN,  "US EIN (Employer Identification Number)"),
    Payload("1EG4-TE5-MK72",    PayloadCategory.US_MBI,  "US Medicare Beneficiary Identifier"),

    # US state driver's licences — one per state + DC
    Payload("1234567",          PayloadCategory.US_DL, "Alabama DL (7 digits)"),
    Payload("9876543",          PayloadCategory.US_DL, "Alaska DL (7 digits)"),
    Payload("B12345678",        PayloadCategory.US_DL, "Arizona DL (letter + 8 digits)"),
    Payload("12345678",         PayloadCategory.US_DL, "Arkansas DL (8 digits)"),
    Payload("D1234567",         PayloadCategory.US_DL, "California DL (letter + 7 digits)"),
    Payload("123456789",        PayloadCategory.US_DL, "Colorado DL (9 digits)"),
    Payload("234567890",        PayloadCategory.US_DL, "Connecticut DL (9 digits)"),
    Payload("7654321",          PayloadCategory.US_DL, "DC DL (7 digits)"),
    Payload("6543210",          PayloadCategory.US_DL, "Delaware DL (7 digits)"),
    Payload("A123456789012",    PayloadCategory.US_DL, "Florida DL (letter + 12 digits)"),
    Payload("87654321",         PayloadCategory.US_DL, "Georgia DL (8 digits)"),
    Payload("H12345678",        PayloadCategory.US_DL, "Hawaii DL (letter + 8 digits)"),
    Payload("AB123456C",        PayloadCategory.US_DL, "Idaho DL (2 letters + 6 digits + letter)"),
    Payload("A12345678901",     PayloadCategory.US_DL, "Illinois DL (letter + 11 digits)"),
    Payload("1234567890",       PayloadCategory.US_DL, "Indiana DL (10 digits)"),
    Payload("123AB1234",        PayloadCategory.US_DL, "Iowa DL (3 digits + 2 letters + 4 digits)"),
    Payload("K12345678",        PayloadCategory.US_DL, "Kansas DL (letter + 8 digits)"),
    Payload("Y12345678",        PayloadCategory.US_DL, "Kentucky DL (letter + 8 digits)"),
    Payload("345678901",        PayloadCategory.US_DL, "Louisiana DL (9 digits)"),
    Payload("5432167",          PayloadCategory.US_DL, "Maine DL (7 digits)"),
    Payload("M123456789012",    PayloadCategory.US_DL, "Maryland DL (letter + 12 digits)"),
    Payload("S12345678",        PayloadCategory.US_DL, "Massachusetts DL (letter + 8 digits)"),
    Payload("A123456789012",    PayloadCategory.US_DL, "Michigan DL (letter + 12 digits)"),
    Payload("M123456789012",    PayloadCategory.US_DL, "Minnesota DL (letter + 12 digits)"),
    Payload("456789012",        PayloadCategory.US_DL, "Mississippi DL (9 digits)"),
    Payload("A12345678",        PayloadCategory.US_DL, "Missouri DL (letter + 8 digits)"),
    Payload("1234567890123",    PayloadCategory.US_DL, "Montana DL (13 digits)"),
    Payload("N12345678",        PayloadCategory.US_DL, "Nebraska DL (letter + 8 digits)"),
    Payload("4567890123",       PayloadCategory.US_DL, "Nevada DL (10 digits)"),
    Payload("12ABC12345",       PayloadCategory.US_DL, "New Hampshire DL (2 digits + 3 letters + 5 digits)"),
    Payload("A12345678901234",  PayloadCategory.US_DL, "New Jersey DL (letter + 14 digits)"),
    Payload("567890123",        PayloadCategory.US_DL, "New Mexico DL (9 digits)"),
    Payload("678901234",        PayloadCategory.US_DL, "New York DL (9 digits)"),
    Payload("789012345",        PayloadCategory.US_DL, "North Carolina DL (9 digits)"),
    Payload("AAA123456",        PayloadCategory.US_DL, "North Dakota DL (3 letters + 6 digits)"),
    Payload("AB123456",         PayloadCategory.US_DL, "Ohio DL (2 letters + 6 digits)"),
    Payload("A123456789",       PayloadCategory.US_DL, "Oklahoma DL (letter + 9 digits)"),
    Payload("87654321",         PayloadCategory.US_DL, "Oregon DL (8 digits)"),
    Payload("76543210",         PayloadCategory.US_DL, "Pennsylvania DL (8 digits)"),
    Payload("V123456",          PayloadCategory.US_DL, "Rhode Island DL (letter + 6 digits)"),
    Payload("65432109",         PayloadCategory.US_DL, "South Carolina DL (8 digits)"),
    Payload("54321098",         PayloadCategory.US_DL, "South Dakota DL (8 digits)"),
    Payload("43210987",         PayloadCategory.US_DL, "Tennessee DL (8 digits)"),
    Payload("32109876",         PayloadCategory.US_DL, "Texas DL (8 digits)"),
    Payload("21098765",         PayloadCategory.US_DL, "Utah DL (8 digits)"),
    Payload("10987654",         PayloadCategory.US_DL, "Vermont DL (8 digits)"),
    Payload("V123456789",       PayloadCategory.US_DL, "Virginia DL (letter + 9 digits)"),
    Payload("ABCDE12345",       PayloadCategory.US_DL, "Washington DL (5 letters + 5 alphanumeric)"),
    Payload("W123456",          PayloadCategory.US_DL, "West Virginia DL (letter + 6 digits)"),
    Payload("A1234567890123",   PayloadCategory.US_DL, "Wisconsin DL (letter + 13 digits)"),
    Payload("987654321",        PayloadCategory.US_DL, "Wyoming DL (9 digits)"),

    # --- Priority 2: European national IDs ---
    Payload("AB123456C",        PayloadCategory.UK_NIN,   "UK National Insurance Number"),
    Payload("MORGA753116SM9IJ", PayloadCategory.UK_DL,    "UK driving licence"),
    Payload("L01X00T47",        PayloadCategory.DE_ID,    "German Personalausweis (9-char alphanumeric)"),
    Payload("880692310285",     PayloadCategory.FR_CNI,   "French Carte Nationale d'Identité (CNI)"),
    Payload("12345678Z",        PayloadCategory.ES_DNI,   "Spanish DNI"),
    Payload("RSSMRA85T10A562S", PayloadCategory.IT_CF,    "Italian Codice Fiscale"),
    Payload("111222333",        PayloadCategory.NL_BSN,   "Dutch BSN (Burgerservicenummer)"),
    Payload("811228-9874",      PayloadCategory.SE_PIN,   "Swedish Personnummer"),
    Payload("01010112345",      PayloadCategory.NO_FNR,   "Norwegian Fødselsnummer"),
    Payload("131052-308T",      PayloadCategory.FI_HETU,  "Finnish Henkilötunnus"),
    Payload("44051401458",      PayloadCategory.PL_PESEL, "Polish PESEL"),
    Payload("756.1234.5678.97", PayloadCategory.CH_AHV,   "Swiss AHV number"),

    # --- Priority 3: Asia-Pacific ---
    Payload("2123456701",       PayloadCategory.AU_MEDICARE,  "Australian Medicare card"),
    Payload("PA1234567",        PayloadCategory.AU_PASSPORT,  "Australian passport"),
    Payload("123456789",        PayloadCategory.NZ_IRD,       "New Zealand IRD number"),
    Payload("S1234567D",        PayloadCategory.SG_NRIC,      "Singapore NRIC"),
    Payload("A123456(3)",       PayloadCategory.HK_HKID,      "Hong Kong HKID"),
    Payload("123456789012",     PayloadCategory.JP_MY_NUMBER, "Japanese My Number"),
    Payload("2345 6789 0123",   PayloadCategory.IN_AADHAAR,   "Indian Aadhaar"),
    Payload("ABCDE1234F",       PayloadCategory.IN_PAN,       "Indian PAN"),

    # --- Priority 4: Latin America ---
    Payload("123.456.789-09",   PayloadCategory.BR_CPF,   "Brazilian CPF"),
    Payload("11.222.333/0001-81", PayloadCategory.BR_CNPJ, "Brazilian CNPJ"),
    Payload("BADD110313HCMLNS09", PayloadCategory.MX_CURP, "Mexican CURP"),
    Payload("12345678",         PayloadCategory.AR_DNI,   "Argentine DNI"),
    Payload("12.345.678-9",     PayloadCategory.CL_RUT,   "Chilean RUT"),

    # --- Priority 5: Middle East & Africa ---
    Payload("784-1234-1234567-1", PayloadCategory.UAE_EID, "UAE Emirates ID"),
    Payload("1234567890",         PayloadCategory.SA_NID,  "Saudi National ID"),
    Payload("9202204720082",       PayloadCategory.ZA_ID,   "South African ID"),
    Payload("123456782",           PayloadCategory.IL_ID,   "Israeli Teudat Zehut"),

    # --- Functional categories ---
    Payload("abc123def456abc123def456abc123de",                PayloadCategory.SESSION_ID,          "Session token (32-char hex)"),
    Payload("0123456789ABCDEF",                                 PayloadCategory.PIN_BLOCK,           "PIN block (ISO format 0, 16 hex chars)"),
    Payload("12345678-ABCD-1234-EFGH-123456789ABC",             PayloadCategory.BIOMETRIC_ID,        "Biometric identifier (UUID-style)"),
    Payload("12/26",                                            PayloadCategory.CARD_EXPIRY,         "Card expiration date MM/YY"),
    Payload("%B4532015112830366^SMITH/JOHN^2512101000000000?",  PayloadCategory.CARD_TRACK,          "Card track 1 data"),
    Payload("⑈021000021⑈ 123456789012 1234",                   PayloadCategory.MICR,                "MICR check line data"),
    Payload("Company Confidential",                             PayloadCategory.CORP_CLASSIFICATION, "Corporate confidential classification label"),
    Payload("USD 12,345.67",                                    PayloadCategory.FINANCIAL_AMOUNT,    "Financial amount with currency code"),
    Payload("2024-01-15",                                       PayloadCategory.DATE_ISO,            "ISO 8601 date"),
    Payload("89014103211118510720",                             PayloadCategory.ICCID,               "SIM card ICCID (20 digits)"),
    Payload("john.smith@mit.edu",                               PayloadCategory.EDU_EMAIL,           "Educational institution email address"),
    Payload("EMP1234567",                                       PayloadCategory.EMPLOYEE_ID,         "Employee identifier"),
    Payload("MNPI",                                             PayloadCategory.MNPI,                "Material Non-Public Information label"),
    Payload("40.7128,-74.0060",                                 PayloadCategory.GPS_COORDS,          "GPS coordinates (lat/lon)"),
    Payload("POL123456789",                                     PayloadCategory.INSURANCE_POLICY,    "Insurance policy number"),
    Payload("ACCT12345678",                                     PayloadCategory.BANK_REF,            "Internal bank account reference"),
    Payload("1:24-cv-12345",                                    PayloadCategory.LEGAL_CASE,          "Federal civil case number"),
    Payload("ABCD00123456789012345678",                         PayloadCategory.LOAN_NUMBER,         "Loan/mortgage identifier"),
    Payload("0069-3190-03",                                     PayloadCategory.NDC_CODE,            "National Drug Code (NDC)"),
    Payload("John Smith",                                       PayloadCategory.CARDHOLDER_NAME,     "Cardholder name (PCI sensitive)"),
    Payload("01/15/1985",                                       PayloadCategory.DOB,                 "Date of birth MM/DD/YYYY"),
    Payload("SW1A 1AA",                                         PayloadCategory.POSTAL_CODE,         "UK postal code"),
    Payload("4532 XXXX XXXX 0366",                              PayloadCategory.MASKED_PAN,          "Masked primary account number"),
    Payload("PCI-DSS",                                          PayloadCategory.PRIVACY_LABEL,       "Privacy/compliance classification label"),
    Payload("Attorney-Client Privileged",                       PayloadCategory.ATTORNEY_CLIENT,     "Attorney-client privilege marker"),
    Payload("123-456-789",                                      PayloadCategory.PARCEL_NUMBER,       "Property parcel number"),
    Payload("AML-123456789",                                    PayloadCategory.AML_CASE_ID,         "Anti-money laundering case identifier"),
    Payload("US0378331005",                                     PayloadCategory.ISIN,                "International Securities Identification Number"),
    Payload("@johnsmith",                                       PayloadCategory.TWITTER_HANDLE,      "Twitter/X social media handle"),
    Payload("Confidential Supervisory Information",             PayloadCategory.SUPERVISORY_INFO,    "Confidential supervisory information label"),
    Payload("https://admin:password123@example.com/api",        PayloadCategory.URL_WITH_CREDS,      "URL containing embedded credentials"),
    Payload("1HGBH41JXMN109186",                                PayloadCategory.VIN,                 "Vehicle Identification Number (VIN)"),
    Payload("20240101AAAA12345678001234",                       PayloadCategory.FEDWIRE_IMAD,        "Fedwire IMAD (Input Message Accountability Data)"),

    # --- Africa ---
    Payload("28503251234567",      PayloadCategory.EG_NID,     "Egypt National ID"),
    Payload("EP1234567",           PayloadCategory.ET_PASSPORT, "Ethiopia passport number"),
    Payload("GHA-123456789-1",     PayloadCategory.GH_CARD,    "Ghana card number"),
    Payload("A123456789B",         PayloadCategory.KE_KRA,     "Kenya KRA PIN"),
    Payload("AB12345",             PayloadCategory.MA_CIN,     "Morocco CIN"),
    Payload("12345678901",         PayloadCategory.NG_BVN,     "Nigeria Bank Verification Number (BVN)"),
    Payload("12345678901234567890", PayloadCategory.TZ_NIDA,   "Tanzania NIDA number"),
    Payload("12345678",            PayloadCategory.TN_CIN,     "Tunisia CIN"),
    Payload("CM12345678ABCD",      PayloadCategory.UG_NIN,     "Uganda National Identification Number"),

    # --- Asia-Pacific (additional) ---
    Payload("1234567890",          PayloadCategory.BD_NID,     "Bangladesh National ID"),
    Payload("3201234567890001",    PayloadCategory.ID_NIK,     "Indonesia NIK (16 digits)"),
    Payload("850101-01-1234",      PayloadCategory.MY_MYKAD,   "Malaysia MyKad number"),
    Payload("12345-1234567-1",     PayloadCategory.PK_CNIC,    "Pakistan CNIC"),
    Payload("1234-5678-9012",      PayloadCategory.PH_PHILSYS, "Philippines PhilSys number"),
    Payload("880101-1234567",      PayloadCategory.KR_RRN,     "South Korea Resident Registration Number"),
    Payload("123456789V",          PayloadCategory.LK_NIC,     "Sri Lanka NIC"),
    Payload("1-1001-00001-85-1",   PayloadCategory.TH_NID,     "Thailand National ID"),
    Payload("001012345678",        PayloadCategory.VN_CCCD,    "Vietnam CCCD (citizen ID)"),

    # --- Europe (additional) ---
    Payload("1234-010150",         PayloadCategory.AT_SVN,  "Austria social insurance number"),
    Payload("85.01.01-234.56",     PayloadCategory.BE_NRN,  "Belgium National Register Number"),
    Payload("8501010001",          PayloadCategory.BG_EGN,  "Bulgaria EGN"),
    Payload("12345678901",         PayloadCategory.HR_OIB,  "Croatia OIB"),
    Payload("12345678A",           PayloadCategory.CY_TIN,  "Cyprus tax identification number"),
    Payload("850101/1234",         PayloadCategory.CZ_RC,   "Czech Republic birth number (rodné číslo)"),
    Payload("010185-1234",         PayloadCategory.DK_CPR,  "Denmark CPR number"),
    Payload("38501010002",         PayloadCategory.EE_IK,   "Estonia personal identification code"),
    Payload("DE123456789",         PayloadCategory.EU_VAT,  "EU VAT number (Germany example)"),
    Payload("01018512345",         PayloadCategory.GR_AMKA, "Greece AMKA social security number"),
    Payload("123 456 789",         PayloadCategory.HU_TAJ,  "Hungary TAJ social security number"),
    Payload("010185-1234",         PayloadCategory.IS_KT,   "Iceland kennitala"),
    Payload("1234567A",            PayloadCategory.IE_PPS,  "Ireland PPS number"),
    Payload("010185-12345",        PayloadCategory.LV_PK,   "Latvia personal code"),
    Payload("A12345",              PayloadCategory.LI_PP,   "Liechtenstein passport number"),
    Payload("38501010002",         PayloadCategory.LT_AK,   "Lithuania personal code"),
    Payload("1985012312345",       PayloadCategory.LU_NIN,  "Luxembourg national identification number"),
    Payload("12345A",              PayloadCategory.MT_ID,   "Malta identity card number"),
    Payload("123456789",           PayloadCategory.PT_NIF,  "Portugal NIF tax number"),
    Payload("1850101123456",       PayloadCategory.RO_CNP,  "Romania CNP personal numeric code"),
    Payload("850101/1234",         PayloadCategory.SK_BN,   "Slovakia birth number"),
    Payload("0101850500003",       PayloadCategory.SI_EMSO, "Slovenia EMSO personal number"),
    Payload("12345678901",         PayloadCategory.TR_TC,   "Turkey TC identity number"),

    # --- Latin America (additional) ---
    Payload("123.456.789-0",  PayloadCategory.CO_CEDULA, "Colombia cedula de ciudadania"),
    Payload("1-0123-0456",    PayloadCategory.CR_CEDULA, "Costa Rica cedula de identidad"),
    Payload("1234567890",     PayloadCategory.EC_CEDULA, "Ecuador cedula de identidad"),
    Payload("12345678-9",     PayloadCategory.PY_RUC,    "Paraguay RUC tax number"),
    Payload("12345678",       PayloadCategory.PE_DNI,    "Peru DNI"),
    Payload("1.234.567-8",    PayloadCategory.UY_CI,     "Uruguay cedula de identidad"),
    Payload("V-12345678",     PayloadCategory.VE_CEDULA, "Venezuela cedula de identidad"),

    # --- Middle East (additional) ---
    Payload("850101234",     PayloadCategory.BH_CPR,   "Bahrain CPR number"),
    Payload("1234567890",    PayloadCategory.IR_MELLI, "Iran Melli code (national ID)"),
    Payload("123456789012",  PayloadCategory.IQ_NID,   "Iraq national ID number"),
    Payload("9001012345",    PayloadCategory.JO_NID,   "Jordan national ID number"),
    Payload("285010112345",  PayloadCategory.KW_CIVIL, "Kuwait civil ID"),
    Payload("RL123456",      PayloadCategory.LB_PP,    "Lebanon passport number"),
    Payload("28501011234",   PayloadCategory.QA_QID,   "Qatar QID number"),
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
    PayloadCategory.CORP_CLASSIFICATION,
    PayloadCategory.MNPI,
    PayloadCategory.CARDHOLDER_NAME,
    PayloadCategory.PRIVACY_LABEL,
    PayloadCategory.ATTORNEY_CLIENT,
    PayloadCategory.SUPERVISORY_INFO,
}


def get_payloads(categories=None, include_heuristic: bool = False) -> list[Payload]:
    payloads = BUILTIN_PAYLOADS
    if not include_heuristic:
        payloads = [p for p in payloads if p.category not in HEURISTIC_CATEGORIES]
    if categories:
        payloads = [p for p in payloads if p.category in categories]
    return payloads
