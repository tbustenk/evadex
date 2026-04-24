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

    # --- High-entropy secrets (heuristic; targets Siphon's EntropyMode) ------
    # Bare high-entropy tokens — caught only by EntropyMode::All.
    Payload("xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ",
            PayloadCategory.RANDOM_API_KEY,
            "Random 32-char alphanumeric API key"),
    Payload("eyJhbGciOiJIUzI1NiJ9.dGVzdHBheWxvYWRyYW5kb20xMjM0NTY3ODkw.abc123XYZdef456UVWghi789RSTjkl",
            PayloadCategory.RANDOM_TOKEN,
            "Random 48-char base64url token"),
    Payload("a3f8c2e1d4b7a9f0e2c5d8b1a4f7c0e3d6b9a2f5c8e1d4b7a0f3c6e9d2b5a8c1",
            PayloadCategory.RANDOM_SECRET,
            "Random 64-char hex secret"),
    Payload("dXNlcm5hbWU6c3VwZXJfc2VjcmV0X3Bhc3N3b3JkXzEyMzQ1Ng==",
            PayloadCategory.ENCODED_CREDENTIAL,
            "Base64-encoded user:password credential"),
    # Assignment form — caught by EntropyMode::Assignment and ::All.
    Payload("DATABASE_PASSWORD=xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ",
            PayloadCategory.ASSIGNMENT_SECRET,
            "High-entropy value in KEY=VALUE format"),
    # Context-gated — caught by EntropyMode::Gated, ::Assignment (if formatted), and ::All.
    Payload("api_key: xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ",
            PayloadCategory.GATED_SECRET,
            "High-entropy value adjacent to 'api_key' keyword"),

    # --- Contact ---
    Payload("test.user@example.com", PayloadCategory.EMAIL, "Email address"),
    Payload("+1-555-867-5309",       PayloadCategory.PHONE, "US phone number"),

    # --- Canadian regional IDs ---
    Payload("BOUD 1234 5678",        PayloadCategory.CA_RAMQ,           "Quebec RAMQ health card"),
    Payload("1234-567-890-AB",       PayloadCategory.CA_ONTARIO_HEALTH, "Ontario health card"),
    Payload("9123456789",            PayloadCategory.CA_BC_CARECARD,    "BC CareCard"),
    Payload("123456789",             PayloadCategory.CA_AB_HEALTH,      "Alberta health card"),
    Payload("B123456789012",         PayloadCategory.CA_QC_DRIVERS,     "Quebec driver's licence (letter + 12 digits)"),
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
    Payload("AB-123-456-789", PayloadCategory.CA_MB_DRIVERS, "Manitoba driver's licence (2 letters + dashes + 9 digits)"),
    Payload("12345678",       PayloadCategory.CA_SK_DRIVERS, "Saskatchewan driver's licence"),
    Payload("ABCDE123456789", PayloadCategory.CA_NS_DRIVERS, "Nova Scotia driver's licence (5 letters + 9 digits)"),
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

    # ── Wire Transfer Data ────────────────────────────────────────────────────
    Payload("123456ABCD",             PayloadCategory.CHIPS_UID,  "CHIPS UID (6 digits + 4 alphanumeric)"),
    Payload("WIREREF1234567890ABCD",  PayloadCategory.WIRE_REF,   "Wire Reference Number (16-35 uppercase alphanumeric)"),
    Payload("SEPAREF123456",          PayloadCategory.SEPA_REF,   "SEPA Reference (12-35 uppercase alphanumeric)"),
    Payload("011234567890123",        PayloadCategory.ACH_TRACE,  "ACH Trace Number (15 digits, valid routing prefix)"),
    Payload("1234567",               PayloadCategory.ACH_BATCH,  "ACH Batch Number (7 digits)"),

    # ── US additional identifiers ─────────────────────────────────────────────
    Payload("990000000",             PayloadCategory.US_ROUTING, "USA Routing Number (9-digit, non-ABA prefix)"),
    Payload("(555) 867-5309",        PayloadCategory.US_PHONE,   "US Phone Number (local format without country code)"),

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

    # ── Africa — sub-pattern expansion ──────────────────────────────────────
    Payload("A1234567",           PayloadCategory.EG_PASSPORT,  "Egypt passport number"),
    Payload("123-456-789",        PayloadCategory.EG_TAX_ID,    "Egypt tax ID (3-3-3 digits)"),
    Payload("123456789012",       PayloadCategory.ET_NID,       "Ethiopia national ID (12 digits)"),
    Payload("1234567890",         PayloadCategory.ET_TIN,       "Ethiopia TIN (10 digits)"),
    Payload("GHA-987654321-2",    PayloadCategory.GH_NHIS,      "Ghana NHIS number"),
    Payload("G1234567",           PayloadCategory.GH_PASSPORT,  "Ghana passport number"),
    Payload("C12345678901",       PayloadCategory.GH_TIN,       "Ghana TIN (C + 10 digits)"),
    Payload("23456789",           PayloadCategory.KE_NHIF,      "Kenya NHIF number (8 digits)"),
    Payload("34567890",           PayloadCategory.KE_NID,       "Kenya national ID (8 digits)"),
    Payload("A12345678",          PayloadCategory.KE_PASSPORT,  "Kenya passport number"),
    Payload("MO1234567",          PayloadCategory.MA_PASSPORT,  "Morocco passport (2 letters + 7 digits)"),
    Payload("12345679",           PayloadCategory.MA_TAX_ID,    "Morocco tax ID (8 digits)"),
    Payload("AAA123456789",       PayloadCategory.NG_DL,        "Nigeria driver licence (3+ letters + 5-9 digits)"),
    Payload("12345678902",        PayloadCategory.NG_NIN,       "Nigeria NIN (11 digits)"),
    Payload("A12345679",          PayloadCategory.NG_PASSPORT,  "Nigeria passport (letter + 8 digits)"),
    Payload("1234567890124",      PayloadCategory.NG_TIN,       "Nigeria TIN (13 digits)"),
    Payload("12345678901234ABCDE", PayloadCategory.NG_VOTER,   "Nigeria voter card (19 alphanumeric)"),
    Payload("1234567890AB",       PayloadCategory.ZA_DL,        "South Africa DL (10 digits + 2 letters)"),
    Payload("A12345679",          PayloadCategory.ZA_PASSPORT,  "South Africa passport"),
    Payload("TZ1234567",          PayloadCategory.TZ_PASSPORT,  "Tanzania passport (2 letters + 7 digits)"),
    Payload("123456790",          PayloadCategory.TZ_TIN,       "Tanzania TIN (9 digits)"),
    Payload("A123457",            PayloadCategory.TN_PASSPORT,  "Tunisia passport (letter + 6 digits)"),
    Payload("A1234568",           PayloadCategory.UG_PASSPORT,  "Uganda passport (letter + 7-8 digits)"),

    # ── Asia-Pacific — Australia DLs (8 state patterns) ─────────────────────
    Payload("12345679",           PayloadCategory.AU_DL,  "Australia DL ACT/NSW/QLD (8 digits)"),
    Payload("12346",              PayloadCategory.AU_DL,  "Australia DL NT (5 digits)"),
    Payload("A12346",             PayloadCategory.AU_DL,  "Australia DL SA (letter + 5 digits)"),
    Payload("B123457",            PayloadCategory.AU_DL,  "Australia DL TAS (letter + 6 digits)"),
    Payload("1234568",            PayloadCategory.AU_DL,  "Australia DL WA (7 digits)"),
    Payload("1234567891",         PayloadCategory.AU_DL,  "Australia DL VIC (10 digits)"),

    # ── Asia-Pacific — Bangladesh ────────────────────────────────────────────
    Payload("BD1234567",          PayloadCategory.BD_PASSPORT,  "Bangladesh passport (2 letters + 7 digits)"),
    Payload("123456789013",       PayloadCategory.BD_TIN,       "Bangladesh TIN (12 digits)"),

    # ── Asia-Pacific — China ────────────────────────────────────────────────
    Payload("E12345678",          PayloadCategory.CN_PASSPORT,  "China passport (E/G/D + optional letter + 7-8 digits)"),
    Payload("110105199001011234",  PayloadCategory.CN_RID,       "China resident ID (18-digit)"),
    Payload("12345674",           PayloadCategory.MO_ID,        "Macau ID (starts 1/5/7/8 + 6 digits + check)"),
    Payload("A123456789",         PayloadCategory.TW_NID,       "Taiwan national ID (letter + [12489] + 8 digits)"),

    # ── Asia-Pacific — India ────────────────────────────────────────────────
    Payload("MH0220191234567",    PayloadCategory.IN_DL,          "India driver's licence"),
    Payload("A1234561",           PayloadCategory.IN_PASSPORT,    "India passport"),
    Payload("1312345678",         PayloadCategory.IN_RATION_CARD, "India ration card (2 + 8 digits)"),
    Payload("ABC1234568",         PayloadCategory.IN_VOTER_ID,    "India voter ID (3 letters + 7 digits)"),

    # ── Asia-Pacific — Indonesia ────────────────────────────────────────────
    Payload("12.345.678.9-012.345", PayloadCategory.ID_NPWP,   "Indonesia NPWP tax number"),
    Payload("A1234568",           PayloadCategory.ID_PASSPORT,  "Indonesia passport"),

    # ── Asia-Pacific — Japan ────────────────────────────────────────────────
    Payload("123456789013",       PayloadCategory.JP_DL,            "Japan DL (12 digits)"),
    Payload("12345679",           PayloadCategory.JP_HEALTH_INS,    "Japan health insurance (8 digits)"),
    Payload("12345678902",        PayloadCategory.JP_JUMINHYO,      "Japan juminhyo code (11 digits)"),
    Payload("JP1234567",          PayloadCategory.JP_PASSPORT,      "Japan passport (2 letters + 7 digits)"),
    Payload("AB12345679CD",       PayloadCategory.JP_RESIDENCE_CARD, "Japan residence card (2+8+2)"),

    # ── Asia-Pacific — Malaysia ─────────────────────────────────────────────
    Payload("A12345679",          PayloadCategory.MY_PASSPORT,  "Malaysia passport (letter + 8 digits)"),

    # ── Asia-Pacific — New Zealand ──────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.NZ_DL,       "New Zealand DL (2 letters + 6 digits)"),
    Payload("ABC1235",            PayloadCategory.NZ_NHI,      "New Zealand NHI (3 letters + 4 digits)"),
    Payload("NZ123457",           PayloadCategory.NZ_PASSPORT, "New Zealand passport"),

    # ── Asia-Pacific — Pakistan ─────────────────────────────────────────────
    Payload("12346-1234568-1",    PayloadCategory.PK_NICOP,    "Pakistan NICOP (same format as CNIC)"),
    Payload("PK1234568",          PayloadCategory.PK_PASSPORT, "Pakistan passport (2 letters + 7 digits)"),

    # ── Asia-Pacific — Philippines ──────────────────────────────────────────
    Payload("AA1234568A",         PayloadCategory.PH_PASSPORT,  "Philippines passport"),
    Payload("12-123456790-1",     PayloadCategory.PH_PHILHEALTH, "Philippines PhilHealth"),
    Payload("12-1234568-8",       PayloadCategory.PH_SSS,        "Philippines SSS"),
    Payload("123-456-790-012",    PayloadCategory.PH_TIN,        "Philippines TIN"),
    Payload("1234-1234568-8",     PayloadCategory.PH_UMID,       "Philippines UMID"),

    # ── Asia-Pacific — Singapore ────────────────────────────────────────────
    Payload("S1234568A",          PayloadCategory.SG_DL,       "Singapore DL (NRIC-format starts with S/T)"),
    Payload("F1234568A",          PayloadCategory.SG_FIN,      "Singapore FIN (F/G/M prefix)"),
    Payload("E1234568A",          PayloadCategory.SG_PASSPORT, "Singapore passport (letter + 7 + letter)"),

    # ── Asia-Pacific — South Korea ──────────────────────────────────────────
    Payload("12-35-123457-78",    PayloadCategory.KR_DL,       "South Korea driver's licence"),
    Payload("M12345679",          PayloadCategory.KR_PASSPORT, "South Korea passport"),

    # ── Asia-Pacific — Sri Lanka ────────────────────────────────────────────
    Payload("200012345679",       PayloadCategory.LK_NIC_NEW,  "Sri Lanka NIC new format (12 digits)"),
    Payload("A1234568",           PayloadCategory.LK_PASSPORT, "Sri Lanka passport"),

    # ── Asia-Pacific — Thailand ─────────────────────────────────────────────
    Payload("1234567890124",      PayloadCategory.TH_DL,       "Thailand DL (13 digits)"),
    Payload("TH1234568",          PayloadCategory.TH_PASSPORT, "Thailand passport (2 letters + 7 digits)"),
    Payload("1234567890125",      PayloadCategory.TH_TAX_ID,   "Thailand tax ID (13 digits)"),

    # ── Asia-Pacific — Vietnam ──────────────────────────────────────────────
    Payload("A12345679",          PayloadCategory.VN_PASSPORT, "Vietnam passport (letter + 8 digits)"),
    Payload("1234567891",         PayloadCategory.VN_TAX_CODE, "Vietnam tax code (10 digits)"),

    # ── Banking Authentication ────────────────────────────────────────────────
    Payload("0123456789ABCDEF0123456789ABCDEF", PayloadCategory.ENCRYPTION_KEY, "Encryption key (32 hex chars)"),
    Payload("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
            PayloadCategory.HSM_KEY, "HSM key (56 hex chars)"),

    # ── Card Track Data ──────────────────────────────────────────────────────
    Payload(";4532015112830366=25121010000000000?", PayloadCategory.CARD_TRACK2, "Card track 2 data"),

    # ── Check and MICR (context required) ────────────────────────────────────
    Payload("123456789012345",    PayloadCategory.CASHIER_CHECK, "Cashier check number (15 digits)"),
    Payload("12345",              PayloadCategory.CHECK_NUMBER,  "Check number (5 digits)"),

    # ── Cloud Provider Secrets ──────────────────────────────────────────────
    Payload("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            PayloadCategory.AWS_SECRET_KEY, "AWS secret access key (40-char base64)"),
    Payload("AIzaSyDt0Y3QL5dFX6iFwIm6JFxE12345678901",
            PayloadCategory.GOOGLE_API_KEY, "Google API key (AIza + 35 chars)"),

    # ── Code Platform Secrets ───────────────────────────────────────────────
    Payload("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01",
            PayloadCategory.GITHUB_OAUTH, "GitHub OAuth token (gho_ + 36 chars)"),
    Payload("github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567",
            PayloadCategory.GITHUB_PAT, "GitHub fine-grained PAT"),
    Payload("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01",
            PayloadCategory.NPM_TOKEN, "NPM access token (npm_ + 36 chars)"),
    Payload("pypi-AgEIcHlwaS5vcmcCJABCDEFGHIJKLMNOPQRSTUVWXYZabcde",
            PayloadCategory.PYPI_TOKEN, "PyPI API token"),

    # ── Cryptocurrency ──────────────────────────────────────────────────────
    Payload("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            PayloadCategory.BITCOIN_BECH32, "Bitcoin Bech32 (native SegWit) address"),
    Payload("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
            PayloadCategory.BITCOIN_CASH, "Bitcoin Cash address (q-prefix + 41 chars)"),
    Payload("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL",
            PayloadCategory.LITECOIN, "Litecoin address (L/M prefix + 26-33 base58)"),
    Payload("44ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz1234567890ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrs",
            PayloadCategory.MONERO, "Monero address (95 chars starting with 4[0-9AB])"),
    Payload("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
            PayloadCategory.RIPPLE, "Ripple/XRP address (r + 34 base58 chars)"),

    # ── Payment Service Secrets ─────────────────────────────────────────────
    Payload("pk_test_4eC39HqLyjWDarjtT7en6bh8Xy9mPqZaB1C2D3",
            PayloadCategory.STRIPE_PK, "Stripe publishable key"),

    # ── Generic Secrets ─────────────────────────────────────────────────────
    Payload("Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.abc123",
            PayloadCategory.BEARER_TOKEN, "Bearer token in Authorization header"),
    Payload("postgresql://admin:s3cr3tP@ssw0rd@db.example.com:5432/prod",
            PayloadCategory.DB_CONNECTION_STRING, "Database connection string with credentials"),
    Payload("-----BEGIN RSA PRIVATE KEY-----",
            PayloadCategory.PRIVATE_KEY, "PEM private key header"),

    # ── Messaging Service Secrets ───────────────────────────────────────────
    Payload("key-3ax6xnjp29jd6fds4gc373sgvjxteol0",
            PayloadCategory.MAILGUN_KEY, "Mailgun API key (key- + 32 chars)"),
    Payload("SG.ABCDEFGHIJKLMNOPQRSTUVWX.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr",
            PayloadCategory.SENDGRID_KEY, "SendGrid API key"),
    Payload("xoxp-EXAMPLE-USERTOKEN-abc123def456",
            PayloadCategory.SLACK_USER_TOKEN, "Slack user token (xoxp- prefix)"),
    Payload("https://hooks.slack.com/services/TTEST/BTEST/TESTTOKEN",
            PayloadCategory.SLACK_WEBHOOK, "Slack webhook URL (test pattern only)"),
    Payload("SK" + "deadbeef" * 4,
            PayloadCategory.TWILIO_KEY, "Twilio API key (SK + 32 hex, test pattern)"),

    # ── Contact Information ──────────────────────────────────────────────────
    Payload("192.168.100.200",    PayloadCategory.IPV4_ADDRESS, "IPv4 address"),
    Payload("2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            PayloadCategory.IPV6_ADDRESS, "IPv6 address (full notation)"),
    Payload("00:1A:2B:3C:4D:5E", PayloadCategory.MAC_ADDRESS, "MAC address (colon notation)"),

    # ── Device Identifiers ──────────────────────────────────────────────────
    Payload("12345678-ABCD-EF01-2345-67890ABCDEF0",
            PayloadCategory.IDFA_IDFV, "Apple IDFA/IDFV (uppercase hex UUID)"),
    Payload("35-209900-176148-1", PayloadCategory.IMEI,   "IMEI (15 digits with separators)"),
    Payload("35-209900-176148-23", PayloadCategory.IMEISV, "IMEISV (16 digits with separators)"),
    Payload("A0000027124FF0",     PayloadCategory.MEID,   "MEID (14 hex chars)"),

    # ── Employment ──────────────────────────────────────────────────────────
    Payload("WP12345678901",      PayloadCategory.WORK_PERMIT, "Work permit number"),

    # ── Geolocation ─────────────────────────────────────────────────────────
    Payload("u4pruydqqvj",        PayloadCategory.GEOHASH, "Geohash (11-char base32)"),

    # ── Insurance ────────────────────────────────────────────────────────────
    Payload("CLM123456789",       PayloadCategory.INSURANCE_CLAIM, "Insurance claim number (3 letters + 9 digits)"),

    # ── Internal Banking ────────────────────────────────────────────────────
    Payload("TLR12345",           PayloadCategory.TELLER_ID, "Bank teller ID (context required)"),

    # ── Corporate Classification ─────────────────────────────────────────────
    Payload("Not for Distribution",    PayloadCategory.CORP_DND,           "Do not distribute label"),
    Payload("Embargoed Information",   PayloadCategory.CORP_EMBARGOED,     "Embargoed material label"),
    Payload("Eyes Only",               PayloadCategory.CORP_EYES_ONLY,     "Eyes Only label"),
    Payload("Highly Confidential",     PayloadCategory.CORP_HIGHLY_CONF,   "Highly Confidential label"),
    Payload("Internal Use Only",       PayloadCategory.CORP_INTERNAL_ONLY, "Internal Only label"),
    Payload("Need to Know",            PayloadCategory.CORP_NEED_TO_KNOW,  "Need to Know label"),
    Payload("Proprietary Information", PayloadCategory.CORP_PROPRIETARY,   "Proprietary information label"),
    Payload("RESTRICTED",              PayloadCategory.CORP_RESTRICTED,    "Restricted label"),

    # ── Customer Financial Data ──────────────────────────────────────────────
    Payload("$12,345.67",         PayloadCategory.ACCOUNT_BALANCE, "Account balance with dollar sign"),
    Payload("43.5%",              PayloadCategory.DTI_RATIO,       "Debt-to-income ratio (context req)"),
    Payload("$85,000.00",         PayloadCategory.INCOME_AMOUNT,   "Income amount (context req)"),

    # ── Data Classification Labels ───────────────────────────────────────────
    Payload("CUI",                        PayloadCategory.DC_CUI,            "Controlled Unclassified Information"),
    Payload("CLASSIFIED CONFIDENTIAL",    PayloadCategory.DC_CLASSIFIED_CONF, "Classified Confidential label"),
    Payload("For Official Use Only",      PayloadCategory.DC_FOUO,           "FOUO label"),
    Payload("Law Enforcement Sensitive",  PayloadCategory.DC_LES,            "LES label"),
    Payload("NOFORN",                     PayloadCategory.DC_NOFORN,         "NOFORN label"),
    Payload("Sensitive But Unclassified", PayloadCategory.DC_SBU,            "SBU label"),
    Payload("SECRET",                     PayloadCategory.DC_SECRET,         "Secret Classification label"),

    # ── Europe — Austria ─────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.AT_DL,       "Austria driver's licence (8 digits)"),
    Payload("87654322",           PayloadCategory.AT_ID_CARD,  "Austria ID card (8 digits)"),
    Payload("A1234568",           PayloadCategory.AT_PASSPORT, "Austria passport (letter + 7 digits)"),
    Payload("12-345-6790",        PayloadCategory.AT_TAX_NUM,  "Austria tax number (2-3-4 digits)"),

    # ── Europe — Belgium ─────────────────────────────────────────────────────
    Payload("1234567891",         PayloadCategory.BE_DL,       "Belgium driver's licence (10 digits)"),
    Payload("AB123457",           PayloadCategory.BE_PASSPORT, "Belgium passport (2 letters + 6 digits)"),
    Payload("BE0123.456.789",     PayloadCategory.BE_VAT,      "Belgium VAT number"),

    # ── Europe — Bulgaria ────────────────────────────────────────────────────
    Payload("123456790",          PayloadCategory.BG_ID_CARD,  "Bulgaria ID card (9 digits)"),
    Payload("1234567891",         PayloadCategory.BG_LNC,      "Bulgaria LNC (10 digits)"),
    Payload("234567892",          PayloadCategory.BG_PASSPORT, "Bulgaria passport (9 digits)"),

    # ── Europe — Croatia ─────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.HR_DL,       "Croatia DL (8 digits)"),
    Payload("123456790",          PayloadCategory.HR_ID_CARD,  "Croatia ID card (9 digits)"),
    Payload("234567891",          PayloadCategory.HR_PASSPORT, "Croatia passport (9 digits)"),

    # ── Europe — Cyprus ──────────────────────────────────────────────────────
    Payload("1234568",            PayloadCategory.CY_ID_CARD,  "Cyprus ID card (7 digits)"),
    Payload("A1234568",           PayloadCategory.CY_PASSPORT, "Cyprus passport (letter + 7-8 digits)"),

    # ── Europe — Czech Republic ──────────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.CZ_DL,       "Czech DL (2 letters + 6 digits)"),
    Payload("12345679",           PayloadCategory.CZ_ICO,      "Czech ICO company number (8 digits)"),
    Payload("23456790",           PayloadCategory.CZ_PASSPORT, "Czech passport (8 digits)"),

    # ── Europe — Denmark ────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.DK_DL,       "Denmark DL (8 digits)"),
    Payload("123456790",          PayloadCategory.DK_PASSPORT, "Denmark passport (9 digits)"),

    # ── Europe — EU ─────────────────────────────────────────────────────────
    Payload("ABC123457",          PayloadCategory.EU_ETD,      "EU Emergency Travel Document"),

    # ── Europe — Estonia ────────────────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.EE_DL,       "Estonia DL (2 letters + 6 digits)"),
    Payload("AB1234568",          PayloadCategory.EE_PASSPORT, "Estonia passport (2 letters + 7 digits)"),

    # ── Europe — Finland ────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.FI_DL,       "Finland DL (8 digits)"),
    Payload("AB1234568",          PayloadCategory.FI_PASSPORT, "Finland passport (2 letters + 7 digits)"),

    # ── Europe — France ──────────────────────────────────────────────────────
    Payload("12AB34568",          PayloadCategory.FR_DL,       "France DL (2 digits + 2 letters + 5 digits)"),
    Payload("12AB34569",          PayloadCategory.FR_PASSPORT, "France passport (same pattern as DL)"),
    Payload("FR7630006000011234567890189",
            PayloadCategory.FR_IBAN, "France IBAN"),

    # ── Europe — Germany ─────────────────────────────────────────────────────
    Payload("B073RD3J1",          PayloadCategory.DE_DL,         "Germany DL (11 alphanumeric)"),
    Payload("C1234567R",          PayloadCategory.DE_PASSPORT,   "Germany passport (C + 8 alphanumeric)"),
    Payload("12010185A001",       PayloadCategory.DE_SOCIAL_INS, "Germany social insurance number"),
    Payload("DE89370400440532013001",
            PayloadCategory.DE_IBAN, "Germany IBAN"),

    # ── Europe — Greece ──────────────────────────────────────────────────────
    Payload("123456790",          PayloadCategory.GR_AFM,      "Greece AFM tax number (9 digits)"),
    Payload("AB123457",           PayloadCategory.GR_DL,       "Greece DL (2 letters + 6 digits)"),
    Payload("AC123457",           PayloadCategory.GR_ID_CARD,  "Greece ID card (2 letters + 6 digits)"),
    Payload("AB1234568",          PayloadCategory.GR_PASSPORT, "Greece passport (2 letters + 7 digits)"),

    # ── Europe — Hungary ─────────────────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.HU_DL,          "Hungary DL (2 letters + 6 digits)"),
    Payload("AB1234568",          PayloadCategory.HU_PASSPORT,    "Hungary passport (2 letters + 6-7 digits)"),
    Payload("1-850102-1234",      PayloadCategory.HU_PERSONAL_ID, "Hungary personal ID"),
    Payload("1234567891",         PayloadCategory.HU_TAX_NUM,     "Hungary tax number (10 digits)"),

    # ── Europe — Iceland ─────────────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.IS_PASSPORT,  "Iceland passport (letter + 7 digits)"),

    # ── Europe — Ireland ─────────────────────────────────────────────────────
    Payload("123-456-790",        PayloadCategory.IE_DL,       "Ireland DL (3-3-3 digits)"),
    Payload("D12 YH79",           PayloadCategory.IE_EIRCODE,  "Ireland Eircode"),
    Payload("AB1234568",          PayloadCategory.IE_PASSPORT, "Ireland passport (2 letters + 7 digits)"),

    # ── Europe — Italy ──────────────────────────────────────────────────────
    Payload("AB1234568C",         PayloadCategory.IT_DL,       "Italy DL (2+7+1 alphanumeric)"),
    Payload("12345678902",        PayloadCategory.IT_PIVA,     "Italy Partita IVA (11 digits)"),
    Payload("AB1234568",          PayloadCategory.IT_PASSPORT, "Italy passport (2 letters + 7 digits)"),
    Payload("RSSMRA86T10A562S",   PayloadCategory.IT_SSN,      "Italy SSN (codice fiscale)"),

    # ── Europe — Latvia ──────────────────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.LV_DL,       "Latvia DL (2 letters + 6 digits)"),
    Payload("AB1234568",          PayloadCategory.LV_PASSPORT, "Latvia passport (2 letters + 7 digits)"),

    # ── Europe — Liechtenstein ───────────────────────────────────────────────
    Payload("123456789013",       PayloadCategory.LI_PIN,      "Liechtenstein PIN (12 digits)"),

    # ── Europe — Lithuania ───────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.LT_DL,       "Lithuania DL (8 digits)"),
    Payload("23456790",           PayloadCategory.LT_PASSPORT, "Lithuania passport (8 digits)"),

    # ── Europe — Luxembourg ──────────────────────────────────────────────────
    Payload("123457",             PayloadCategory.LU_DL,       "Luxembourg DL (6 digits)"),
    Payload("AB123457",           PayloadCategory.LU_PASSPORT, "Luxembourg passport (2 letters + 6 digits)"),

    # ── Europe — Malta ───────────────────────────────────────────────────────
    Payload("1234568",            PayloadCategory.MT_PASSPORT, "Malta passport (7 digits)"),
    Payload("12346A",             PayloadCategory.MT_TIN,      "Malta TIN (digits + letter)"),

    # ── Europe — Netherlands ─────────────────────────────────────────────────
    Payload("1234567891",         PayloadCategory.NL_DL,       "Netherlands DL (10 digits)"),
    Payload("NL91ABNA0417164300", PayloadCategory.NL_IBAN,     "Netherlands IBAN"),
    Payload("AB123457C",          PayloadCategory.NL_PASSPORT, "Netherlands passport (2+6+1)"),

    # ── Europe — Norway ──────────────────────────────────────────────────────
    Payload("41018512346",        PayloadCategory.NO_D_NUMBER, "Norway D-number (4-7 in first position)"),
    Payload("12345678902",        PayloadCategory.NO_DL,       "Norway DL (11 digits)"),
    Payload("12345679",           PayloadCategory.NO_PASSPORT, "Norway passport (8 digits)"),

    # ── Europe — Poland ──────────────────────────────────────────────────────
    Payload("12345-13-1234",      PayloadCategory.PL_DL,       "Poland DL"),
    Payload("ABC123457",          PayloadCategory.PL_ID_CARD,  "Poland ID card (3 letters + 6 digits)"),
    Payload("123-456-13-12",      PayloadCategory.PL_NIP,      "Poland NIP tax number"),
    Payload("AB1234568",          PayloadCategory.PL_PASSPORT, "Poland passport (2 letters + 7 digits)"),
    Payload("123456790",          PayloadCategory.PL_REGON,    "Poland REGON (9 digits)"),

    # ── Europe — Portugal ────────────────────────────────────────────────────
    Payload("12345679 9 ZZ4",     PayloadCategory.PT_CC,       "Portugal citizen card (CC)"),
    Payload("12345678902",        PayloadCategory.PT_NISS,     "Portugal NISS (11 digits)"),
    Payload("AB123457",           PayloadCategory.PT_PASSPORT, "Portugal passport (1-2 letters + 6 digits)"),

    # ── Europe — Romania ─────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.RO_CIF,      "Romania CIF (2-10 digits)"),
    Payload("123456790",          PayloadCategory.RO_DL,       "Romania DL (9 digits)"),
    Payload("12345679",           PayloadCategory.RO_PASSPORT, "Romania passport (8-9 digits)"),

    # ── Europe — Slovakia ────────────────────────────────────────────────────
    Payload("AB123457",           PayloadCategory.SK_DL,       "Slovakia DL (2 letters + 6 digits)"),
    Payload("AB123458",           PayloadCategory.SK_PASSPORT, "Slovakia passport (2 letters + 6 digits)"),

    # ── Europe — Slovenia ────────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.SI_DL,       "Slovenia DL (8 digits)"),
    Payload("AB1234568",          PayloadCategory.SI_PASSPORT, "Slovenia passport (2 letters + 7 digits)"),
    Payload("12345680",           PayloadCategory.SI_TAX_NUM,  "Slovenia tax number (8 digits)"),

    # ── Europe — Spain ───────────────────────────────────────────────────────
    Payload("12345679Z",          PayloadCategory.ES_DL,       "Spain DL (8 digits + letter)"),
    Payload("X1234568L",          PayloadCategory.ES_NIE,      "Spain NIE (X/Y/Z + 7 digits + letter)"),
    Payload("12-12345679-12",     PayloadCategory.ES_NSS,      "Spain NSS social security"),
    Payload("ABC123457",          PayloadCategory.ES_PASSPORT, "Spain passport (3 letters + 6 digits)"),
    Payload("ES9121000418450200051332",
            PayloadCategory.ES_IBAN, "Spain IBAN"),

    # ── Europe — Sweden ──────────────────────────────────────────────────────
    Payload("811229-1234",        PayloadCategory.SE_DL,       "Sweden DL (PN format)"),
    Payload("556001-1234",        PayloadCategory.SE_ORG_NUM,  "Sweden organisation number"),
    Payload("12345679",           PayloadCategory.SE_PASSPORT, "Sweden passport (8 digits)"),

    # ── Europe — Switzerland ─────────────────────────────────────────────────
    Payload("123457",             PayloadCategory.CH_DL,       "Switzerland DL (6-7 digits)"),
    Payload("A1234568",           PayloadCategory.CH_PASSPORT, "Switzerland passport (letter + 7 digits)"),
    Payload("CHE-123.456.789",    PayloadCategory.CH_UID,      "Switzerland UID (CHE-NNN.NNN.NNN)"),

    # ── Europe — Turkey ──────────────────────────────────────────────────────
    Payload("123457",             PayloadCategory.TR_DL,       "Turkey DL (6 digits)"),
    Payload("A1234568",           PayloadCategory.TR_PASSPORT, "Turkey passport (letter + 7 digits)"),
    Payload("1234567891",         PayloadCategory.TR_TAX_ID,   "Turkey tax ID (10 digits)"),

    # ── Europe — United Kingdom ───────────────────────────────────────────────
    Payload("485 777 3457",       PayloadCategory.UK_NHS,       "UK NHS number (10 digits)"),
    Payload("123456790",          PayloadCategory.UK_PASSPORT,  "UK passport (9 digits)"),
    Payload("+44 7911 123457",    PayloadCategory.UK_PHONE,     "UK phone number"),
    Payload("20-00-01",           PayloadCategory.UK_SORT_CODE, "UK bank sort code"),
    Payload("12346 67890",        PayloadCategory.UK_UTR,       "UK Unique Taxpayer Reference"),

    # ── Financial Regulatory Labels ──────────────────────────────────────────
    Payload("Draft - Not for Circulation", PayloadCategory.FRL_DRAFT_NOT_CIRC,    "Draft not for circulation"),
    Payload("Information Barrier",         PayloadCategory.FRL_INFO_BARRIER,      "Information barrier"),
    Payload("Inside Information",          PayloadCategory.FRL_INSIDE_INFO,       "Inside information"),
    Payload("Restricted List",             PayloadCategory.FRL_INVEST_RESTRICTED, "Investment restricted list"),
    Payload("Market Sensitive",            PayloadCategory.FRL_MARKET_SENSITIVE,  "Market sensitive"),
    Payload("Pre-Decisional",              PayloadCategory.FRL_PRE_DECISIONAL,    "Pre-decisional document"),

    # ── Latin America — Argentina ────────────────────────────────────────────
    Payload("20-12345678-9",      PayloadCategory.AR_CUIL_CUIT, "Argentina CUIL/CUIT"),
    Payload("AAA123457",          PayloadCategory.AR_PASSPORT,  "Argentina passport (3 letters + 6 digits)"),

    # ── Latin America — Brazil ────────────────────────────────────────────────
    Payload("12345678902",        PayloadCategory.BR_CNH,      "Brazil CNH driver's licence (11 digits)"),
    Payload("AB123457",           PayloadCategory.BR_PASSPORT, "Brazil passport (2 letters + 6 digits)"),
    Payload("12.345.679-9",       PayloadCategory.BR_RG,       "Brazil RG identity document"),
    Payload("100123456789001",    PayloadCategory.BR_SUS,      "Brazil SUS health card (15 digits)"),

    # ── Latin America — Chile ────────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.CL_PASSPORT, "Chile passport"),

    # ── Latin America — Colombia ─────────────────────────────────────────────
    Payload("123-456-790-1",      PayloadCategory.CO_NIT,      "Colombia NIT tax number"),
    Payload("1234567891",         PayloadCategory.CO_NUIP,     "Colombia NUIP (6-10 digits)"),
    Payload("AB1234568",          PayloadCategory.CO_PASSPORT, "Colombia passport"),

    # ── Latin America — Costa Rica ───────────────────────────────────────────
    Payload("12345678902",        PayloadCategory.CR_DIMEX,   "Costa Rica DIMEX (11-12 digits)"),
    Payload("A12345679",          PayloadCategory.CR_PASSPORT, "Costa Rica passport"),

    # ── Latin America — Ecuador ──────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.EC_PASSPORT, "Ecuador passport"),
    Payload("1234567890002",      PayloadCategory.EC_RUC,      "Ecuador RUC (13 digits)"),

    # ── Latin America — Paraguay ─────────────────────────────────────────────
    Payload("1234568",            PayloadCategory.PY_CEDULA,  "Paraguay cedula (5-7 digits)"),
    Payload("A1234568",           PayloadCategory.PY_PASSPORT, "Paraguay passport"),

    # ── Latin America — Peru ─────────────────────────────────────────────────
    Payload("123456790",          PayloadCategory.PE_CARNET_EXT, "Peru carnet extranjeria (9-12 digits)"),
    Payload("AB123457",           PayloadCategory.PE_PASSPORT,   "Peru passport (2 letters + 6-7 digits)"),
    Payload("10123456790",        PayloadCategory.PE_RUC,        "Peru RUC (starts 10/15/17/20 + 9 digits)"),

    # ── Latin America — Uruguay ──────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.UY_PASSPORT, "Uruguay passport"),
    Payload("123456789013",       PayloadCategory.UY_RUT,      "Uruguay RUT (12 digits)"),

    # ── Latin America — Venezuela ────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.VE_PASSPORT, "Venezuela passport"),
    Payload("V-12345679-9",       PayloadCategory.VE_RIF,      "Venezuela RIF tax number"),

    # ── Legal ────────────────────────────────────────────────────────────────
    Payload("24-CV-12345",        PayloadCategory.COURT_DOCKET, "Court docket number"),

    # ── Loan and Mortgage ────────────────────────────────────────────────────
    Payload("LOAN12345",          PayloadCategory.LOAN_NUM_SHORT, "Loan number (8-15 alphanumeric)"),
    Payload("35.5%",              PayloadCategory.LTV_RATIO,      "LTV ratio (context req)"),
    Payload("100012345678901234", PayloadCategory.MERS_MIN,       "MERS MIN (18 digits)"),

    # ── Medical ──────────────────────────────────────────────────────────────
    Payload("AB1234568",          PayloadCategory.DEA_NUMBER,    "US DEA registration (2 letters + 7 digits)"),
    Payload("ABC123456789",       PayloadCategory.HEALTH_PLAN_ID, "Health plan ID (3 letters + 9 digits)"),
    Payload("J45.0",              PayloadCategory.ICD10_CODE,    "ICD-10 diagnosis code"),

    # ── Middle East — Bahrain ─────────────────────────────────────────────────
    Payload("123456790",          PayloadCategory.BH_PASSPORT,  "Bahrain passport (7-9 digits)"),

    # ── Middle East — Iran ────────────────────────────────────────────────────
    Payload("A12345679",          PayloadCategory.IR_PASSPORT,  "Iran passport (letter + 8 digits)"),

    # ── Middle East — Iraq ────────────────────────────────────────────────────
    Payload("ABCDEFGH2",          PayloadCategory.IQ_PASSPORT,  "Iraq passport (9 alphanumeric)"),

    # ── Middle East — Israel ──────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.IL_PASSPORT,  "Israel passport (7-8 digits)"),

    # ── Middle East — Jordan ──────────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.JO_PASSPORT,  "Jordan passport (letter + 7 digits)"),

    # ── Middle East — Kuwait ──────────────────────────────────────────────────
    Payload("123456790",          PayloadCategory.KW_PASSPORT,  "Kuwait passport (7-9 digits)"),

    # ── Middle East — Lebanon ──────────────────────────────────────────────────
    Payload("12345679",           PayloadCategory.LB_ID,        "Lebanon ID (7-12 digits)"),

    # ── Middle East — Qatar ───────────────────────────────────────────────────
    Payload("A1234568",           PayloadCategory.QA_PASSPORT,  "Qatar passport (letter + 7 digits)"),

    # ── Middle East — Saudi Arabia ────────────────────────────────────────────
    Payload("A12345679",          PayloadCategory.SA_PASSPORT,  "Saudi Arabia passport"),

    # ── Middle East — UAE ─────────────────────────────────────────────────────
    Payload("A12345679",          PayloadCategory.UAE_PASSPORT, "UAE passport (letter + 7-9 digits)"),
    Payload("101/2023/1234567",   PayloadCategory.UAE_VISA,     "UAE visa number"),

    # ── North America — Canada (new sub-patterns) ─────────────────────────────
    Payload("123457",             PayloadCategory.CA_AB_DL,    "Alberta DL (6-9 digits)"),
    Payload("123458",             PayloadCategory.CA_NWT_DL,   "NWT DL (6 digits)"),
    Payload("654322",             PayloadCategory.CA_NU_DL,    "Nunavut DL (6 digits)"),
    Payload("567891",             PayloadCategory.CA_YT_DL,    "Yukon DL (6 digits)"),
    Payload("987654322",          PayloadCategory.CA_NEXUS,    "Canada NEXUS traveller number (9 digits)"),
    Payload("AB12345679",         PayloadCategory.CA_PR_CARD,  "Canada PR card (2 letters + 7-10 digits)"),

    # ── North America — Mexico (new sub-patterns) ──────────────────────────────
    Payload("GOMJUA78092H010",    PayloadCategory.MX_CLAVE_ELECTOR, "Mexico clave de elector"),
    Payload("123456790",          PayloadCategory.MX_INE_CIC,       "Mexico INE CIC (9 digits)"),
    Payload("1234567890124",      PayloadCategory.MX_INE_OCR,       "Mexico INE OCR (13 digits)"),
    Payload("12345678902",        PayloadCategory.MX_NSS,           "Mexico NSS (11 digits)"),
    Payload("M12345679",          PayloadCategory.MX_PASSPORT,      "Mexico passport (letter + 8 digits)"),
    Payload("GOMC780916A12",      PayloadCategory.MX_RFC,           "Mexico RFC tax ID"),

    # ── North America — United States (new sub-patterns) ──────────────────────
    Payload("AB1234568",          PayloadCategory.US_DEA,          "US DEA registration (2 letters + 7 digits)"),
    Payload("1234567891",         PayloadCategory.US_DOD_ID,       "US DoD ID (10 digits)"),
    Payload("123456790",          PayloadCategory.US_KTN,          "US Known Traveler Number (9 digits)"),
    Payload("1234567891",         PayloadCategory.US_NPI,          "US NPI (1/2 + 9 digits)"),
    Payload("C12345679",          PayloadCategory.US_PASSPORT_CARD, "US passport card (C + 8 digits)"),

    # ── Personal / Postal ────────────────────────────────────────────────────
    Payload("female",             PayloadCategory.GENDER_MARKER, "Gender marker"),
    Payload("01310-100",          PayloadCategory.BR_CEP,         "Brazil postal code CEP"),
    Payload("M5V 3A8",            PayloadCategory.CA_POSTAL_CODE, "Canada postal code"),
    Payload("100-0001",           PayloadCategory.JP_POSTAL_CODE, "Japan postal code"),
    Payload("90210-1234",         PayloadCategory.US_ZIP4,        "US ZIP+4 code"),

    # ── Privacy Classification Labels ────────────────────────────────────────
    Payload("CCPA",                              PayloadCategory.PC_CCPA,      "California Consumer Privacy Act label"),
    Payload("FERPA",                             PayloadCategory.PC_FERPA,     "FERPA educational privacy label"),
    Payload("GDPR",                              PayloadCategory.PC_GDPR,      "GDPR personal data label"),
    Payload("GLBA",                              PayloadCategory.PC_GLBA,      "Gramm-Leach-Bliley Act label"),
    Payload("Non-Public Personal Information",   PayloadCategory.PC_NPI_LABEL, "NPI non-public personal information"),
    Payload("PHI",                               PayloadCategory.PC_PHI,       "Protected Health Information label"),
    Payload("PII",                               PayloadCategory.PC_PII,       "Personally Identifiable Information label"),
    Payload("SOX",                               PayloadCategory.PC_SOX,       "Sarbanes-Oxley Act label"),

    # ── Privileged Information ───────────────────────────────────────────────
    Payload("Legally Privileged",          PayloadCategory.PRIV_LEGAL,           "Legal privilege marker"),
    Payload("Litigation Hold",             PayloadCategory.PRIV_LITIGATION_HOLD, "Litigation hold notice"),
    Payload("Privileged Information",      PayloadCategory.PRIV_PRIVILEGED_INFO, "Privileged information marker"),
    Payload("Privileged and Confidential", PayloadCategory.PRIV_PRIV_CONF,       "Privileged and confidential"),
    Payload("Protected by Privilege",      PayloadCategory.PRIV_PROTECTED,       "Protected by privilege"),
    Payload("Work Product Doctrine",       PayloadCategory.PRIV_WORK_PRODUCT,    "Work product doctrine"),

    # ── Property Identifiers ─────────────────────────────────────────────────
    Payload("12345-67890",        PayloadCategory.TITLE_DEED, "Title deed number"),

    # ── Regulatory Identifiers ───────────────────────────────────────────────
    Payload("12345678901235",     PayloadCategory.REG_CTR,            "CTR number (14 digits)"),
    Payload("AML-2024-12345679",  PayloadCategory.REG_COMPLIANCE_CASE, "Compliance case number"),
    Payload("12345678901236",     PayloadCategory.REG_FINCEN,         "FinCEN report number (14 digits)"),
    Payload("12346",              PayloadCategory.REG_OFAC,           "OFAC SDN number (4-6 digits, context req)"),
    Payload("12345678901234568",  PayloadCategory.REG_SAR,            "SAR filing number (14-20 digits)"),

    # ── Securities Identifiers ───────────────────────────────────────────────
    Payload("037833100",          PayloadCategory.CUSIP_NUM, "CUSIP (Apple Inc, context req)"),
    Payload("BBG000B9XRY4",       PayloadCategory.FIGI_NUM,  "FIGI identifier"),
    Payload("HWUPKR0MPOU8FGXBT394",
            PayloadCategory.LEI_NUM,   "Legal Entity Identifier (20 alphanumeric)"),
    Payload("2005973",            PayloadCategory.SEDOL_NUM,  "SEDOL (7 chars, context req)"),
    Payload("$AAPL",              PayloadCategory.TICKER_SYMBOL, "Stock ticker (context req)"),

    # ── Social Media ─────────────────────────────────────────────────────────
    Payload("#FinancialData",     PayloadCategory.HASHTAG, "Hashtag (context req)"),

    # ── Supervisory Information (sub-patterns) ───────────────────────────────
    Payload("Matter Requiring Attention",         PayloadCategory.SUP_EXAM_FINDINGS,    "MRA examination findings"),
    Payload("Non-Public Supervisory Information", PayloadCategory.SUP_NON_PUBLIC,       "Non-public supervisory info"),
    Payload("Restricted Supervisory Information", PayloadCategory.SUP_RESTRICTED_SUP,   "Restricted supervisory info"),
    Payload("Supervisory Confidential",           PayloadCategory.SUP_SUPERVISORY_CONF, "Supervisory confidential"),
    Payload("Supervisory Controlled Information", PayloadCategory.SUP_SUPERVISORY_CTRL, "Supervisory controlled info"),

    # ── URLs with Credentials ────────────────────────────────────────────────
    Payload("https://api.example.com/data?token=abc123secret456def789",
            PayloadCategory.URL_WITH_TOKEN, "URL with embedded token parameter"),
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
    # Entropy-based secret categories — detection is a heuristic over
    # Shannon entropy, so they're gated out of the default tier like other
    # heuristic categories and only run with --include-heuristic or the
    # entropy command.
    PayloadCategory.RANDOM_API_KEY,
    PayloadCategory.RANDOM_TOKEN,
    PayloadCategory.RANDOM_SECRET,
    PayloadCategory.ENCODED_CREDENTIAL,
    PayloadCategory.ASSIGNMENT_SECRET,
    PayloadCategory.GATED_SECRET,
}

# Subset of HEURISTIC_CATEGORIES that represent high-entropy secret payloads.
# Exposed so the `evadex entropy` command can select them without leaking
# knowledge of its own internals into the entropy CLI module.
ENTROPY_CATEGORIES = {
    PayloadCategory.RANDOM_API_KEY,
    PayloadCategory.RANDOM_TOKEN,
    PayloadCategory.RANDOM_SECRET,
    PayloadCategory.ENCODED_CREDENTIAL,
    PayloadCategory.ASSIGNMENT_SECRET,
    PayloadCategory.GATED_SECRET,
}


def get_payloads(categories=None, include_heuristic: bool = False) -> list[Payload]:
    payloads = BUILTIN_PAYLOADS
    if not include_heuristic:
        payloads = [p for p in payloads if p.category not in HEURISTIC_CATEGORIES]
    if categories:
        payloads = [p for p in payloads if p.category in categories]
    return payloads
