from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PayloadCategory(Enum):
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    SIN = "sin"
    IBAN = "iban"
    SWIFT_BIC = "swift_bic"
    ABA_ROUTING = "aba_routing"
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    US_PASSPORT = "us_passport"
    AU_TFN = "au_tfn"
    DE_TAX_ID = "de_tax_id"
    FR_INSEE = "fr_insee"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    SLACK_TOKEN = "slack_token"
    CLASSIFICATION = "classification"
    AWS_KEY = "aws_key"
    JWT = "jwt"
    EMAIL = "email"
    PHONE = "phone"
    # Canadian regional IDs
    CA_RAMQ = "ca_ramq"
    CA_ONTARIO_HEALTH = "ca_ontario_health"
    CA_BC_CARECARD = "ca_bc_carecard"
    CA_AB_HEALTH = "ca_ab_health"
    CA_QC_DRIVERS = "ca_qc_drivers"
    CA_ON_DRIVERS = "ca_on_drivers"
    CA_BC_DRIVERS = "ca_bc_drivers"
    CA_PASSPORT = "ca_passport"
    # Remaining provincial health cards
    CA_MB_HEALTH = "ca_mb_health"
    CA_SK_HEALTH = "ca_sk_health"
    CA_NS_HEALTH = "ca_ns_health"
    CA_NB_HEALTH = "ca_nb_health"
    CA_PEI_HEALTH = "ca_pei_health"
    CA_NL_HEALTH = "ca_nl_health"
    # Remaining provincial driver's licences
    CA_MB_DRIVERS = "ca_mb_drivers"
    CA_SK_DRIVERS = "ca_sk_drivers"
    CA_NS_DRIVERS = "ca_ns_drivers"
    CA_NB_DRIVERS = "ca_nb_drivers"
    CA_PEI_DRIVERS = "ca_pei_drivers"
    CA_NL_DRIVERS = "ca_nl_drivers"
    # Canadian corporate identifiers
    CA_BUSINESS_NUMBER = "ca_business_number"
    CA_GST_HST = "ca_gst_hst"
    CA_TRANSIT_NUMBER = "ca_transit_number"
    CA_BANK_ACCOUNT = "ca_bank_account"
    # United States — additional identifiers
    US_DL = "us_dl"
    US_ITIN = "us_itin"
    US_EIN = "us_ein"
    US_MBI = "us_mbi"
    # Europe — national IDs
    UK_NIN = "uk_nin"
    UK_DL = "uk_dl"
    DE_ID = "de_id"
    FR_CNI = "fr_cni"
    ES_DNI = "es_dni"
    IT_CF = "it_cf"
    NL_BSN = "nl_bsn"
    SE_PIN = "se_pin"
    NO_FNR = "no_fnr"
    FI_HETU = "fi_hetu"
    PL_PESEL = "pl_pesel"
    CH_AHV = "ch_ahv"
    # Asia-Pacific
    AU_MEDICARE = "au_medicare"
    AU_PASSPORT = "au_passport"
    NZ_IRD = "nz_ird"
    SG_NRIC = "sg_nric"
    HK_HKID = "hk_hkid"
    JP_MY_NUMBER = "jp_my_number"
    IN_AADHAAR = "in_aadhaar"
    IN_PAN = "in_pan"
    # Latin America
    BR_CPF = "br_cpf"
    BR_CNPJ = "br_cnpj"
    MX_CURP = "mx_curp"
    AR_DNI = "ar_dni"
    CL_RUT = "cl_rut"
    # Middle East & Africa
    UAE_EID = "uae_eid"
    SA_NID = "sa_nid"
    ZA_ID = "za_id"
    IL_ID = "il_id"
    # Functional categories
    SESSION_ID = "session_id"
    PIN_BLOCK = "pin_block"
    BIOMETRIC_ID = "biometric_id"
    CARD_EXPIRY = "card_expiry"
    CARD_TRACK = "card_track"
    MICR = "micr"
    CORP_CLASSIFICATION = "corp_classification"
    FINANCIAL_AMOUNT = "financial_amount"
    DATE_ISO = "date_iso"
    ICCID = "iccid"
    EDU_EMAIL = "edu_email"
    EMPLOYEE_ID = "employee_id"
    MNPI = "mnpi"
    GPS_COORDS = "gps_coords"
    INSURANCE_POLICY = "insurance_policy"
    BANK_REF = "bank_ref"
    LEGAL_CASE = "legal_case"
    LOAN_NUMBER = "loan_number"
    NDC_CODE = "ndc_code"
    CARDHOLDER_NAME = "cardholder_name"
    DOB = "dob"
    POSTAL_CODE = "postal_code"
    MASKED_PAN = "masked_pan"
    PRIVACY_LABEL = "privacy_label"
    ATTORNEY_CLIENT = "attorney_client"
    PARCEL_NUMBER = "parcel_number"
    AML_CASE_ID = "aml_case_id"
    ISIN = "isin"
    TWITTER_HANDLE = "twitter_handle"
    SUPERVISORY_INFO = "supervisory_info"
    URL_WITH_CREDS = "url_with_creds"
    VIN = "vin"
    FEDWIRE_IMAD = "fedwire_imad"
    # Africa
    EG_NID = "eg_nid"
    ET_PASSPORT = "et_passport"
    GH_CARD = "gh_card"
    KE_KRA = "ke_kra"
    MA_CIN = "ma_cin"
    NG_BVN = "ng_bvn"
    TZ_NIDA = "tz_nida"
    TN_CIN = "tn_cin"
    UG_NIN = "ug_nin"
    # Asia-Pacific (additional)
    BD_NID = "bd_nid"
    ID_NIK = "id_nik"
    MY_MYKAD = "my_mykad"
    PK_CNIC = "pk_cnic"
    PH_PHILSYS = "ph_philsys"
    KR_RRN = "kr_rrn"
    LK_NIC = "lk_nic"
    TH_NID = "th_nid"
    VN_CCCD = "vn_cccd"
    # Europe (additional)
    AT_SVN = "at_svn"
    BE_NRN = "be_nrn"
    BG_EGN = "bg_egn"
    HR_OIB = "hr_oib"
    CY_TIN = "cy_tin"
    CZ_RC = "cz_rc"
    DK_CPR = "dk_cpr"
    EE_IK = "ee_ik"
    EU_VAT = "eu_vat"
    GR_AMKA = "gr_amka"
    HU_TAJ = "hu_taj"
    IS_KT = "is_kt"
    IE_PPS = "ie_pps"
    LV_PK = "lv_pk"
    LI_PP = "li_pp"
    LT_AK = "lt_ak"
    LU_NIN = "lu_nin"
    MT_ID = "mt_id"
    PT_NIF = "pt_nif"
    RO_CNP = "ro_cnp"
    SK_BN = "sk_bn"
    SI_EMSO = "si_emso"
    TR_TC = "tr_tc"
    # Latin America (additional)
    CO_CEDULA = "co_cedula"
    CR_CEDULA = "cr_cedula"
    EC_CEDULA = "ec_cedula"
    PY_RUC = "py_ruc"
    PE_DNI = "pe_dni"
    UY_CI = "uy_ci"
    VE_CEDULA = "ve_cedula"
    # Middle East (additional)
    BH_CPR = "bh_cpr"
    IR_MELLI = "ir_melli"
    IQ_NID = "iq_nid"
    JO_NID = "jo_nid"
    KW_CIVIL = "kw_civil"
    LB_PP = "lb_pp"
    QA_QID = "qa_qid"
    UNKNOWN = "unknown"


class CategoryType(Enum):
    STRUCTURED = "structured"
    HEURISTIC = "heuristic"


CATEGORY_TYPES: dict[PayloadCategory, CategoryType] = {
    PayloadCategory.CREDIT_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.SSN:            CategoryType.STRUCTURED,
    PayloadCategory.SIN:            CategoryType.STRUCTURED,
    PayloadCategory.IBAN:           CategoryType.STRUCTURED,
    PayloadCategory.SWIFT_BIC:      CategoryType.STRUCTURED,
    PayloadCategory.ABA_ROUTING:    CategoryType.STRUCTURED,
    PayloadCategory.BITCOIN:        CategoryType.STRUCTURED,
    PayloadCategory.ETHEREUM:       CategoryType.STRUCTURED,
    PayloadCategory.US_PASSPORT:    CategoryType.STRUCTURED,
    PayloadCategory.AU_TFN:         CategoryType.STRUCTURED,
    PayloadCategory.DE_TAX_ID:      CategoryType.STRUCTURED,
    PayloadCategory.FR_INSEE:       CategoryType.STRUCTURED,
    PayloadCategory.GITHUB_TOKEN:   CategoryType.HEURISTIC,
    PayloadCategory.STRIPE_KEY:     CategoryType.HEURISTIC,
    PayloadCategory.SLACK_TOKEN:    CategoryType.HEURISTIC,
    PayloadCategory.CLASSIFICATION: CategoryType.HEURISTIC,
    PayloadCategory.EMAIL:          CategoryType.STRUCTURED,
    PayloadCategory.PHONE:          CategoryType.STRUCTURED,
    PayloadCategory.AWS_KEY:        CategoryType.HEURISTIC,
    PayloadCategory.JWT:            CategoryType.HEURISTIC,
    PayloadCategory.CA_RAMQ:           CategoryType.STRUCTURED,
    PayloadCategory.CA_ONTARIO_HEALTH: CategoryType.STRUCTURED,
    PayloadCategory.CA_BC_CARECARD:    CategoryType.STRUCTURED,
    PayloadCategory.CA_AB_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_QC_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_ON_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_BC_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.CA_MB_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_SK_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_NS_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_NB_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_PEI_HEALTH:     CategoryType.STRUCTURED,
    PayloadCategory.CA_NL_HEALTH:      CategoryType.STRUCTURED,
    PayloadCategory.CA_MB_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_SK_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_NS_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_NB_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_PEI_DRIVERS:    CategoryType.STRUCTURED,
    PayloadCategory.CA_NL_DRIVERS:     CategoryType.STRUCTURED,
    PayloadCategory.CA_BUSINESS_NUMBER: CategoryType.STRUCTURED,
    PayloadCategory.CA_GST_HST:        CategoryType.STRUCTURED,
    PayloadCategory.CA_TRANSIT_NUMBER: CategoryType.STRUCTURED,
    PayloadCategory.CA_BANK_ACCOUNT:   CategoryType.STRUCTURED,
    # United States — additional identifiers
    PayloadCategory.US_DL:    CategoryType.STRUCTURED,
    PayloadCategory.US_ITIN:  CategoryType.STRUCTURED,
    PayloadCategory.US_EIN:   CategoryType.STRUCTURED,
    PayloadCategory.US_MBI:   CategoryType.STRUCTURED,
    # Europe — national IDs
    PayloadCategory.UK_NIN:   CategoryType.STRUCTURED,
    PayloadCategory.UK_DL:    CategoryType.STRUCTURED,
    PayloadCategory.DE_ID:    CategoryType.STRUCTURED,
    PayloadCategory.FR_CNI:   CategoryType.STRUCTURED,
    PayloadCategory.ES_DNI:   CategoryType.STRUCTURED,
    PayloadCategory.IT_CF:    CategoryType.STRUCTURED,
    PayloadCategory.NL_BSN:   CategoryType.STRUCTURED,
    PayloadCategory.SE_PIN:   CategoryType.STRUCTURED,
    PayloadCategory.NO_FNR:   CategoryType.STRUCTURED,
    PayloadCategory.FI_HETU:  CategoryType.STRUCTURED,
    PayloadCategory.PL_PESEL: CategoryType.STRUCTURED,
    PayloadCategory.CH_AHV:   CategoryType.STRUCTURED,
    # Asia-Pacific
    PayloadCategory.AU_MEDICARE:    CategoryType.STRUCTURED,
    PayloadCategory.AU_PASSPORT:    CategoryType.STRUCTURED,
    PayloadCategory.NZ_IRD:         CategoryType.STRUCTURED,
    PayloadCategory.SG_NRIC:        CategoryType.STRUCTURED,
    PayloadCategory.HK_HKID:        CategoryType.STRUCTURED,
    PayloadCategory.JP_MY_NUMBER:   CategoryType.STRUCTURED,
    PayloadCategory.IN_AADHAAR:     CategoryType.STRUCTURED,
    PayloadCategory.IN_PAN:         CategoryType.STRUCTURED,
    # Latin America
    PayloadCategory.BR_CPF:   CategoryType.STRUCTURED,
    PayloadCategory.BR_CNPJ:  CategoryType.STRUCTURED,
    PayloadCategory.MX_CURP:  CategoryType.STRUCTURED,
    PayloadCategory.AR_DNI:   CategoryType.STRUCTURED,
    PayloadCategory.CL_RUT:   CategoryType.STRUCTURED,
    # Middle East & Africa
    PayloadCategory.UAE_EID:  CategoryType.STRUCTURED,
    PayloadCategory.SA_NID:   CategoryType.STRUCTURED,
    PayloadCategory.ZA_ID:    CategoryType.STRUCTURED,
    PayloadCategory.IL_ID:    CategoryType.STRUCTURED,
    # Functional categories
    PayloadCategory.SESSION_ID:          CategoryType.STRUCTURED,
    PayloadCategory.PIN_BLOCK:           CategoryType.STRUCTURED,
    PayloadCategory.BIOMETRIC_ID:        CategoryType.STRUCTURED,
    PayloadCategory.CARD_EXPIRY:         CategoryType.STRUCTURED,
    PayloadCategory.CARD_TRACK:          CategoryType.STRUCTURED,
    PayloadCategory.MICR:                CategoryType.STRUCTURED,
    PayloadCategory.CORP_CLASSIFICATION: CategoryType.HEURISTIC,
    PayloadCategory.FINANCIAL_AMOUNT:    CategoryType.STRUCTURED,
    PayloadCategory.DATE_ISO:            CategoryType.STRUCTURED,
    PayloadCategory.ICCID:               CategoryType.STRUCTURED,
    PayloadCategory.EDU_EMAIL:           CategoryType.STRUCTURED,
    PayloadCategory.EMPLOYEE_ID:         CategoryType.STRUCTURED,
    PayloadCategory.MNPI:                CategoryType.HEURISTIC,
    PayloadCategory.GPS_COORDS:          CategoryType.STRUCTURED,
    PayloadCategory.INSURANCE_POLICY:    CategoryType.STRUCTURED,
    PayloadCategory.BANK_REF:            CategoryType.STRUCTURED,
    PayloadCategory.LEGAL_CASE:          CategoryType.STRUCTURED,
    PayloadCategory.LOAN_NUMBER:         CategoryType.STRUCTURED,
    PayloadCategory.NDC_CODE:            CategoryType.STRUCTURED,
    PayloadCategory.CARDHOLDER_NAME:     CategoryType.HEURISTIC,
    PayloadCategory.DOB:                 CategoryType.STRUCTURED,
    PayloadCategory.POSTAL_CODE:         CategoryType.STRUCTURED,
    PayloadCategory.MASKED_PAN:          CategoryType.STRUCTURED,
    PayloadCategory.PRIVACY_LABEL:       CategoryType.HEURISTIC,
    PayloadCategory.ATTORNEY_CLIENT:     CategoryType.HEURISTIC,
    PayloadCategory.PARCEL_NUMBER:       CategoryType.STRUCTURED,
    PayloadCategory.AML_CASE_ID:         CategoryType.STRUCTURED,
    PayloadCategory.ISIN:                CategoryType.STRUCTURED,
    PayloadCategory.TWITTER_HANDLE:      CategoryType.STRUCTURED,
    PayloadCategory.SUPERVISORY_INFO:    CategoryType.HEURISTIC,
    PayloadCategory.URL_WITH_CREDS:      CategoryType.STRUCTURED,
    PayloadCategory.VIN:                 CategoryType.STRUCTURED,
    PayloadCategory.FEDWIRE_IMAD:        CategoryType.STRUCTURED,
    # Africa
    PayloadCategory.EG_NID:     CategoryType.STRUCTURED,
    PayloadCategory.ET_PASSPORT: CategoryType.STRUCTURED,
    PayloadCategory.GH_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.KE_KRA:     CategoryType.STRUCTURED,
    PayloadCategory.MA_CIN:     CategoryType.STRUCTURED,
    PayloadCategory.NG_BVN:     CategoryType.STRUCTURED,
    PayloadCategory.TZ_NIDA:    CategoryType.STRUCTURED,
    PayloadCategory.TN_CIN:     CategoryType.STRUCTURED,
    PayloadCategory.UG_NIN:     CategoryType.STRUCTURED,
    # Asia-Pacific (additional)
    PayloadCategory.BD_NID:     CategoryType.STRUCTURED,
    PayloadCategory.ID_NIK:     CategoryType.STRUCTURED,
    PayloadCategory.MY_MYKAD:   CategoryType.STRUCTURED,
    PayloadCategory.PK_CNIC:    CategoryType.STRUCTURED,
    PayloadCategory.PH_PHILSYS: CategoryType.STRUCTURED,
    PayloadCategory.KR_RRN:     CategoryType.STRUCTURED,
    PayloadCategory.LK_NIC:     CategoryType.STRUCTURED,
    PayloadCategory.TH_NID:     CategoryType.STRUCTURED,
    PayloadCategory.VN_CCCD:    CategoryType.STRUCTURED,
    # Europe (additional)
    PayloadCategory.AT_SVN:  CategoryType.STRUCTURED,
    PayloadCategory.BE_NRN:  CategoryType.STRUCTURED,
    PayloadCategory.BG_EGN:  CategoryType.STRUCTURED,
    PayloadCategory.HR_OIB:  CategoryType.STRUCTURED,
    PayloadCategory.CY_TIN:  CategoryType.STRUCTURED,
    PayloadCategory.CZ_RC:   CategoryType.STRUCTURED,
    PayloadCategory.DK_CPR:  CategoryType.STRUCTURED,
    PayloadCategory.EE_IK:   CategoryType.STRUCTURED,
    PayloadCategory.EU_VAT:  CategoryType.STRUCTURED,
    PayloadCategory.GR_AMKA: CategoryType.STRUCTURED,
    PayloadCategory.HU_TAJ:  CategoryType.STRUCTURED,
    PayloadCategory.IS_KT:   CategoryType.STRUCTURED,
    PayloadCategory.IE_PPS:  CategoryType.STRUCTURED,
    PayloadCategory.LV_PK:   CategoryType.STRUCTURED,
    PayloadCategory.LI_PP:   CategoryType.STRUCTURED,
    PayloadCategory.LT_AK:   CategoryType.STRUCTURED,
    PayloadCategory.LU_NIN:  CategoryType.STRUCTURED,
    PayloadCategory.MT_ID:   CategoryType.STRUCTURED,
    PayloadCategory.PT_NIF:  CategoryType.STRUCTURED,
    PayloadCategory.RO_CNP:  CategoryType.STRUCTURED,
    PayloadCategory.SK_BN:   CategoryType.STRUCTURED,
    PayloadCategory.SI_EMSO: CategoryType.STRUCTURED,
    PayloadCategory.TR_TC:   CategoryType.STRUCTURED,
    # Latin America (additional)
    PayloadCategory.CO_CEDULA: CategoryType.STRUCTURED,
    PayloadCategory.CR_CEDULA: CategoryType.STRUCTURED,
    PayloadCategory.EC_CEDULA: CategoryType.STRUCTURED,
    PayloadCategory.PY_RUC:    CategoryType.STRUCTURED,
    PayloadCategory.PE_DNI:    CategoryType.STRUCTURED,
    PayloadCategory.UY_CI:     CategoryType.STRUCTURED,
    PayloadCategory.VE_CEDULA: CategoryType.STRUCTURED,
    # Middle East (additional)
    PayloadCategory.BH_CPR:   CategoryType.STRUCTURED,
    PayloadCategory.IR_MELLI: CategoryType.STRUCTURED,
    PayloadCategory.IQ_NID:   CategoryType.STRUCTURED,
    PayloadCategory.JO_NID:   CategoryType.STRUCTURED,
    PayloadCategory.KW_CIVIL: CategoryType.STRUCTURED,
    PayloadCategory.LB_PP:    CategoryType.STRUCTURED,
    PayloadCategory.QA_QID:   CategoryType.STRUCTURED,
    PayloadCategory.UNKNOWN:  CategoryType.STRUCTURED,
}


class SeverityLevel(Enum):
    PASS = "pass"      # scanner DETECTED the evasion attempt (good — scanner caught it)
    FAIL = "fail"      # scanner did NOT detect (bad — evasion succeeded)
    ERROR = "error"    # adapter error


@dataclass
class Payload:
    value: str
    category: PayloadCategory
    label: str

    def to_dict(self):
        return {
            "value": self.value,
            "category": self.category.value,
            "category_type": CATEGORY_TYPES.get(self.category, CategoryType.STRUCTURED).value,
            "label": self.label,
        }


@dataclass(frozen=True)
class Variant:
    value: str
    generator: str          # e.g. "unicode_encoding"
    technique: str          # e.g. "zero_width_injection"
    transform_name: str     # human-readable e.g. "Zero-width space between digits"
    strategy: str = "text"  # "text", "docx", "pdf", "xlsx"

    def to_dict(self):
        return {
            "value": self.value,
            "generator": self.generator,
            "technique": self.technique,
            "transform_name": self.transform_name,
            "strategy": self.strategy,
        }


@dataclass
class ScanResult:
    payload: Payload
    variant: Variant
    detected: bool
    raw_response: dict = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: float = 0.0

    @property
    def severity(self) -> SeverityLevel:
        if self.error:
            return SeverityLevel.ERROR
        return SeverityLevel.PASS if self.detected else SeverityLevel.FAIL

    def to_dict(self):
        return {
            "payload": self.payload.to_dict(),
            "variant": self.variant.to_dict(),
            "detected": self.detected,
            "severity": self.severity.value,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "raw_response": self.raw_response,
        }
