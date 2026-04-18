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

    # ── Africa (sub-pattern expansion) ──────────────────────────────────────
    EG_PASSPORT = "eg_passport"
    EG_TAX_ID = "eg_tax_id"
    ET_NID = "et_nid"
    ET_TIN = "et_tin"
    GH_NHIS = "gh_nhis"
    GH_PASSPORT = "gh_passport"
    GH_TIN = "gh_tin"
    KE_NHIF = "ke_nhif"
    KE_NID = "ke_nid"
    KE_PASSPORT = "ke_passport"
    MA_PASSPORT = "ma_passport"
    MA_TAX_ID = "ma_tax_id"
    NG_DL = "ng_dl"
    NG_NIN = "ng_nin"
    NG_PASSPORT = "ng_passport"
    NG_TIN = "ng_tin"
    NG_VOTER = "ng_voter"
    ZA_DL = "za_dl"
    ZA_PASSPORT = "za_passport"
    TZ_PASSPORT = "tz_passport"
    TZ_TIN = "tz_tin"
    TN_PASSPORT = "tn_passport"
    UG_PASSPORT = "ug_passport"

    # ── Asia-Pacific (sub-pattern expansion) ────────────────────────────────
    AU_DL = "au_dl"                    # 8 state-level payloads share this category
    BD_PASSPORT = "bd_passport"
    BD_TIN = "bd_tin"
    CN_PASSPORT = "cn_passport"
    CN_RID = "cn_rid"
    MO_ID = "mo_id"
    TW_NID = "tw_nid"
    IN_DL = "in_dl"
    IN_PASSPORT = "in_passport"
    IN_RATION_CARD = "in_ration_card"
    IN_VOTER_ID = "in_voter_id"
    ID_NPWP = "id_npwp"
    ID_PASSPORT = "id_passport"
    JP_DL = "jp_dl"
    JP_HEALTH_INS = "jp_health_ins"
    JP_JUMINHYO = "jp_juminhyo"
    JP_PASSPORT = "jp_passport"
    JP_RESIDENCE_CARD = "jp_residence_card"
    MY_PASSPORT = "my_passport"
    NZ_DL = "nz_dl"
    NZ_NHI = "nz_nhi"
    NZ_PASSPORT = "nz_passport"
    PK_NICOP = "pk_nicop"
    PK_PASSPORT = "pk_passport"
    PH_PASSPORT = "ph_passport"
    PH_PHILHEALTH = "ph_philhealth"
    PH_SSS = "ph_sss"
    PH_TIN = "ph_tin"
    PH_UMID = "ph_umid"
    SG_DL = "sg_dl"
    SG_FIN = "sg_fin"
    SG_PASSPORT = "sg_passport"
    KR_DL = "kr_dl"
    KR_PASSPORT = "kr_passport"
    LK_NIC_NEW = "lk_nic_new"
    LK_PASSPORT = "lk_passport"
    TH_DL = "th_dl"
    TH_PASSPORT = "th_passport"
    TH_TAX_ID = "th_tax_id"
    VN_PASSPORT = "vn_passport"
    VN_TAX_CODE = "vn_tax_code"

    # ── Banking / crypto / financial (sub-pattern expansion) ────────────────
    ENCRYPTION_KEY = "encryption_key"
    HSM_KEY = "hsm_key"
    CARD_TRACK2 = "card_track2"
    CASHIER_CHECK = "cashier_check"
    CHECK_NUMBER = "check_number"
    AWS_SECRET_KEY = "aws_secret_key"
    GOOGLE_API_KEY = "google_api_key"
    GITHUB_OAUTH = "github_oauth"
    GITHUB_PAT = "github_pat"
    NPM_TOKEN = "npm_token"
    PYPI_TOKEN = "pypi_token"
    BITCOIN_BECH32 = "bitcoin_bech32"
    BITCOIN_CASH = "bitcoin_cash"
    LITECOIN = "litecoin"
    MONERO = "monero"
    RIPPLE = "ripple"
    STRIPE_PK = "stripe_pk"
    BEARER_TOKEN = "bearer_token"
    DB_CONNECTION_STRING = "db_connection_string"
    PRIVATE_KEY = "private_key"
    MAILGUN_KEY = "mailgun_key"
    SENDGRID_KEY = "sendgrid_key"
    SLACK_USER_TOKEN = "slack_user_token"
    SLACK_WEBHOOK = "slack_webhook"
    TWILIO_KEY = "twilio_key"

    # ── Contact / device (sub-pattern expansion) ────────────────────────────
    IPV4_ADDRESS = "ipv4_address"
    IPV6_ADDRESS = "ipv6_address"
    MAC_ADDRESS = "mac_address"
    IDFA_IDFV = "idfa_idfv"
    IMEI = "imei"
    IMEISV = "imeisv"
    MEID = "meid"
    WORK_PERMIT = "work_permit"
    GEOHASH = "geohash"
    INSURANCE_CLAIM = "insurance_claim"
    TELLER_ID = "teller_id"

    # ── Corporate classification (sub-patterns) ──────────────────────────────
    CORP_DND = "corp_dnd"
    CORP_EMBARGOED = "corp_embargoed"
    CORP_EYES_ONLY = "corp_eyes_only"
    CORP_HIGHLY_CONF = "corp_highly_conf"
    CORP_INTERNAL_ONLY = "corp_internal_only"
    CORP_NEED_TO_KNOW = "corp_need_to_know"
    CORP_PROPRIETARY = "corp_proprietary"
    CORP_RESTRICTED = "corp_restricted"

    # ── Customer financial data ──────────────────────────────────────────────
    ACCOUNT_BALANCE = "account_balance"
    DTI_RATIO = "dti_ratio"
    INCOME_AMOUNT = "income_amount"

    # ── Data classification labels (sub-patterns) ───────────────────────────
    DC_CUI = "dc_cui"
    DC_CLASSIFIED_CONF = "dc_classified_conf"
    DC_FOUO = "dc_fouo"
    DC_LES = "dc_les"
    DC_NOFORN = "dc_noforn"
    DC_SBU = "dc_sbu"
    DC_SECRET = "dc_secret"

    # ── Europe — Austria (sub-patterns) ─────────────────────────────────────
    AT_DL = "at_dl"
    AT_ID_CARD = "at_id_card"
    AT_PASSPORT = "at_passport"
    AT_TAX_NUM = "at_tax_num"

    # ── Europe — Belgium (sub-patterns) ─────────────────────────────────────
    BE_DL = "be_dl"
    BE_PASSPORT = "be_passport"
    BE_VAT = "be_vat"

    # ── Europe — Bulgaria (sub-patterns) ────────────────────────────────────
    BG_ID_CARD = "bg_id_card"
    BG_LNC = "bg_lnc"
    BG_PASSPORT = "bg_passport"

    # ── Europe — Croatia (sub-patterns) ─────────────────────────────────────
    HR_DL = "hr_dl"
    HR_ID_CARD = "hr_id_card"
    HR_PASSPORT = "hr_passport"

    # ── Europe — Cyprus (sub-patterns) ──────────────────────────────────────
    CY_ID_CARD = "cy_id_card"
    CY_PASSPORT = "cy_passport"

    # ── Europe — Czech Republic (sub-patterns) ───────────────────────────────
    CZ_DL = "cz_dl"
    CZ_ICO = "cz_ico"
    CZ_PASSPORT = "cz_passport"

    # ── Europe — Denmark (sub-patterns) ─────────────────────────────────────
    DK_DL = "dk_dl"
    DK_PASSPORT = "dk_passport"

    # ── Europe — EU ─────────────────────────────────────────────────────────
    EU_ETD = "eu_etd"

    # ── Europe — Estonia (sub-patterns) ─────────────────────────────────────
    EE_DL = "ee_dl"
    EE_PASSPORT = "ee_passport"

    # ── Europe — Finland (sub-patterns) ─────────────────────────────────────
    FI_DL = "fi_dl"
    FI_PASSPORT = "fi_passport"

    # ── Europe — France (sub-patterns) ──────────────────────────────────────
    FR_DL = "fr_dl"
    FR_PASSPORT = "fr_passport"
    FR_IBAN = "fr_iban"

    # ── Europe — Germany (sub-patterns) ─────────────────────────────────────
    DE_DL = "de_dl"
    DE_PASSPORT = "de_passport"
    DE_SOCIAL_INS = "de_social_ins"
    DE_IBAN = "de_iban"

    # ── Europe — Greece (sub-patterns) ──────────────────────────────────────
    GR_AFM = "gr_afm"
    GR_DL = "gr_dl"
    GR_ID_CARD = "gr_id_card"
    GR_PASSPORT = "gr_passport"

    # ── Europe — Hungary (sub-patterns) ─────────────────────────────────────
    HU_DL = "hu_dl"
    HU_PASSPORT = "hu_passport"
    HU_PERSONAL_ID = "hu_personal_id"
    HU_TAX_NUM = "hu_tax_num"

    # ── Europe — Iceland (sub-patterns) ─────────────────────────────────────
    IS_PASSPORT = "is_passport"

    # ── Europe — Ireland (sub-patterns) ─────────────────────────────────────
    IE_DL = "ie_dl"
    IE_EIRCODE = "ie_eircode"
    IE_PASSPORT = "ie_passport"

    # ── Europe — Italy (sub-patterns) ───────────────────────────────────────
    IT_DL = "it_dl"
    IT_PIVA = "it_piva"
    IT_PASSPORT = "it_passport"
    IT_SSN = "it_ssn"

    # ── Europe — Latvia (sub-patterns) ──────────────────────────────────────
    LV_DL = "lv_dl"
    LV_PASSPORT = "lv_passport"

    # ── Europe — Liechtenstein (sub-patterns) ────────────────────────────────
    LI_PIN = "li_pin"

    # ── Europe — Lithuania (sub-patterns) ───────────────────────────────────
    LT_DL = "lt_dl"
    LT_PASSPORT = "lt_passport"

    # ── Europe — Luxembourg (sub-patterns) ──────────────────────────────────
    LU_DL = "lu_dl"
    LU_PASSPORT = "lu_passport"

    # ── Europe — Malta (sub-patterns) ───────────────────────────────────────
    MT_PASSPORT = "mt_passport"
    MT_TIN = "mt_tin"

    # ── Europe — Netherlands (sub-patterns) ──────────────────────────────────
    NL_DL = "nl_dl"
    NL_IBAN = "nl_iban"
    NL_PASSPORT = "nl_passport"

    # ── Europe — Norway (sub-patterns) ──────────────────────────────────────
    NO_D_NUMBER = "no_d_number"
    NO_DL = "no_dl"
    NO_PASSPORT = "no_passport"

    # ── Europe — Poland (sub-patterns) ──────────────────────────────────────
    PL_DL = "pl_dl"
    PL_ID_CARD = "pl_id_card"
    PL_NIP = "pl_nip"
    PL_PASSPORT = "pl_passport"
    PL_REGON = "pl_regon"

    # ── Europe — Portugal (sub-patterns) ────────────────────────────────────
    PT_CC = "pt_cc"
    PT_NISS = "pt_niss"
    PT_PASSPORT = "pt_passport"

    # ── Europe — Romania (sub-patterns) ─────────────────────────────────────
    RO_CIF = "ro_cif"
    RO_DL = "ro_dl"
    RO_PASSPORT = "ro_passport"

    # ── Europe — Slovakia (sub-patterns) ────────────────────────────────────
    SK_DL = "sk_dl"
    SK_PASSPORT = "sk_passport"

    # ── Europe — Slovenia (sub-patterns) ────────────────────────────────────
    SI_DL = "si_dl"
    SI_PASSPORT = "si_passport"
    SI_TAX_NUM = "si_tax_num"

    # ── Europe — Spain (sub-patterns) ───────────────────────────────────────
    ES_DL = "es_dl"
    ES_NIE = "es_nie"
    ES_NSS = "es_nss"
    ES_PASSPORT = "es_passport"
    ES_IBAN = "es_iban"

    # ── Europe — Sweden (sub-patterns) ──────────────────────────────────────
    SE_DL = "se_dl"
    SE_ORG_NUM = "se_org_num"
    SE_PASSPORT = "se_passport"

    # ── Europe — Switzerland (sub-patterns) ──────────────────────────────────
    CH_DL = "ch_dl"
    CH_PASSPORT = "ch_passport"
    CH_UID = "ch_uid"

    # ── Europe — Turkey (sub-patterns) ──────────────────────────────────────
    TR_DL = "tr_dl"
    TR_PASSPORT = "tr_passport"
    TR_TAX_ID = "tr_tax_id"

    # ── Europe — United Kingdom (sub-patterns) ───────────────────────────────
    UK_NHS = "uk_nhs"
    UK_PASSPORT = "uk_passport"
    UK_PHONE = "uk_phone"
    UK_SORT_CODE = "uk_sort_code"
    UK_UTR = "uk_utr"

    # ── Financial regulatory labels (sub-patterns) ───────────────────────────
    FRL_DRAFT_NOT_CIRC = "frl_draft_not_circ"
    FRL_INFO_BARRIER = "frl_info_barrier"
    FRL_INSIDE_INFO = "frl_inside_info"
    FRL_INVEST_RESTRICTED = "frl_invest_restricted"
    FRL_MARKET_SENSITIVE = "frl_market_sensitive"
    FRL_PRE_DECISIONAL = "frl_pre_decisional"

    # ── Latin America (sub-pattern expansion) ───────────────────────────────
    AR_CUIL_CUIT = "ar_cuil_cuit"
    AR_PASSPORT = "ar_passport"
    BR_CNH = "br_cnh"
    BR_PASSPORT = "br_passport"
    BR_RG = "br_rg"
    BR_SUS = "br_sus"
    CL_PASSPORT = "cl_passport"
    CO_NIT = "co_nit"
    CO_NUIP = "co_nuip"
    CO_PASSPORT = "co_passport"
    CR_DIMEX = "cr_dimex"
    CR_PASSPORT = "cr_passport"
    EC_PASSPORT = "ec_passport"
    EC_RUC = "ec_ruc"
    PY_CEDULA = "py_cedula"
    PY_PASSPORT = "py_passport"
    PE_CARNET_EXT = "pe_carnet_ext"
    PE_PASSPORT = "pe_passport"
    PE_RUC = "pe_ruc"
    UY_PASSPORT = "uy_passport"
    UY_RUT = "uy_rut"
    VE_PASSPORT = "ve_passport"
    VE_RIF = "ve_rif"

    # ── Legal / loan / medical ──────────────────────────────────────────────
    COURT_DOCKET = "court_docket"
    LOAN_NUM_SHORT = "loan_num_short"
    LTV_RATIO = "ltv_ratio"
    MERS_MIN = "mers_min"
    DEA_NUMBER = "dea_number"
    HEALTH_PLAN_ID = "health_plan_id"
    ICD10_CODE = "icd10_code"

    # ── Middle East (sub-pattern expansion) ─────────────────────────────────
    BH_PASSPORT = "bh_passport"
    IR_PASSPORT = "ir_passport"
    IQ_PASSPORT = "iq_passport"
    IL_PASSPORT = "il_passport"
    JO_PASSPORT = "jo_passport"
    KW_PASSPORT = "kw_passport"
    LB_ID = "lb_id"
    QA_PASSPORT = "qa_passport"
    SA_PASSPORT = "sa_passport"
    UAE_PASSPORT = "uae_passport"
    UAE_VISA = "uae_visa"

    # ── North America — Canada (sub-pattern expansion) ───────────────────────
    CA_AB_DL = "ca_ab_dl"
    CA_NWT_DL = "ca_nwt_dl"
    CA_NU_DL = "ca_nu_dl"
    CA_YT_DL = "ca_yt_dl"
    CA_NEXUS = "ca_nexus"
    CA_PR_CARD = "ca_pr_card"

    # ── North America — Mexico (sub-pattern expansion) ───────────────────────
    MX_CLAVE_ELECTOR = "mx_clave_elector"
    MX_INE_CIC = "mx_ine_cic"
    MX_INE_OCR = "mx_ine_ocr"
    MX_NSS = "mx_nss"
    MX_PASSPORT = "mx_passport"
    MX_RFC = "mx_rfc"

    # ── North America — United States (sub-pattern expansion) ────────────────
    US_DEA = "us_dea"
    US_DOD_ID = "us_dod_id"
    US_KTN = "us_ktn"
    US_NPI = "us_npi"
    US_PASSPORT_CARD = "us_passport_card"

    # ── Personal / postal ───────────────────────────────────────────────────
    GENDER_MARKER = "gender_marker"
    BR_CEP = "br_cep"
    CA_POSTAL_CODE = "ca_postal_code"
    JP_POSTAL_CODE = "jp_postal_code"
    US_ZIP4 = "us_zip4"

    # ── Privacy classification labels (sub-patterns) ─────────────────────────
    PC_CCPA = "pc_ccpa"
    PC_FERPA = "pc_ferpa"
    PC_GDPR = "pc_gdpr"
    PC_GLBA = "pc_glba"
    PC_NPI_LABEL = "pc_npi_label"
    PC_PHI = "pc_phi"
    PC_PII = "pc_pii"
    PC_SOX = "pc_sox"

    # ── Privileged information (sub-patterns) ────────────────────────────────
    PRIV_LEGAL = "priv_legal"
    PRIV_LITIGATION_HOLD = "priv_litigation_hold"
    PRIV_PRIVILEGED_INFO = "priv_privileged_info"
    PRIV_PRIV_CONF = "priv_priv_conf"
    PRIV_PROTECTED = "priv_protected"
    PRIV_WORK_PRODUCT = "priv_work_product"

    # ── Property / regulatory / securities ──────────────────────────────────
    TITLE_DEED = "title_deed"
    REG_CTR = "reg_ctr"
    REG_COMPLIANCE_CASE = "reg_compliance_case"
    REG_FINCEN = "reg_fincen"
    REG_OFAC = "reg_ofac"
    REG_SAR = "reg_sar"
    CUSIP_NUM = "cusip_num"
    FIGI_NUM = "figi_num"
    LEI_NUM = "lei_num"
    SEDOL_NUM = "sedol_num"
    TICKER_SYMBOL = "ticker_symbol"

    # ── Social media / supervisory / URL ────────────────────────────────────
    HASHTAG = "hashtag"
    SUP_EXAM_FINDINGS = "sup_exam_findings"
    SUP_NON_PUBLIC = "sup_non_public"
    SUP_RESTRICTED_SUP = "sup_restricted_sup"
    SUP_SUPERVISORY_CONF = "sup_supervisory_conf"
    SUP_SUPERVISORY_CTRL = "sup_supervisory_ctrl"
    URL_WITH_TOKEN = "url_with_token"

    # ── Wire Transfer Data ────────────────────────────────────────────────────
    ACH_BATCH = "ach_batch"
    ACH_TRACE = "ach_trace"
    CHIPS_UID = "chips_uid"
    SEPA_REF = "sepa_ref"
    WIRE_REF = "wire_ref"
    # ── US additional identifiers (expansion) ────────────────────────────────
    US_PHONE = "us_phone"
    US_ROUTING = "us_routing"

    # ── High-entropy secrets (heuristic, for Siphon's entropy modes) ────────
    RANDOM_API_KEY = "random_api_key"
    RANDOM_TOKEN = "random_token"
    RANDOM_SECRET = "random_secret"
    ENCODED_CREDENTIAL = "encoded_credential"
    ASSIGNMENT_SECRET = "assignment_secret"
    GATED_SECRET = "gated_secret"

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
    # Africa sub-patterns
    PayloadCategory.EG_PASSPORT: CategoryType.STRUCTURED,
    PayloadCategory.EG_TAX_ID:   CategoryType.STRUCTURED,
    PayloadCategory.ET_NID:       CategoryType.STRUCTURED,
    PayloadCategory.ET_TIN:       CategoryType.STRUCTURED,
    PayloadCategory.GH_NHIS:      CategoryType.STRUCTURED,
    PayloadCategory.GH_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.GH_TIN:       CategoryType.STRUCTURED,
    PayloadCategory.KE_NHIF:      CategoryType.STRUCTURED,
    PayloadCategory.KE_NID:       CategoryType.STRUCTURED,
    PayloadCategory.KE_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.MA_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.MA_TAX_ID:    CategoryType.STRUCTURED,
    PayloadCategory.NG_DL:        CategoryType.STRUCTURED,
    PayloadCategory.NG_NIN:       CategoryType.STRUCTURED,
    PayloadCategory.NG_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.NG_TIN:       CategoryType.STRUCTURED,
    PayloadCategory.NG_VOTER:     CategoryType.STRUCTURED,
    PayloadCategory.ZA_DL:        CategoryType.STRUCTURED,
    PayloadCategory.ZA_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.TZ_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.TZ_TIN:       CategoryType.STRUCTURED,
    PayloadCategory.TN_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.UG_PASSPORT:  CategoryType.STRUCTURED,
    # Asia-Pacific sub-patterns
    PayloadCategory.AU_DL:             CategoryType.STRUCTURED,
    PayloadCategory.BD_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.BD_TIN:            CategoryType.STRUCTURED,
    PayloadCategory.CN_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.CN_RID:            CategoryType.STRUCTURED,
    PayloadCategory.MO_ID:             CategoryType.STRUCTURED,
    PayloadCategory.TW_NID:            CategoryType.STRUCTURED,
    PayloadCategory.IN_DL:             CategoryType.STRUCTURED,
    PayloadCategory.IN_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.IN_RATION_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.IN_VOTER_ID:       CategoryType.STRUCTURED,
    PayloadCategory.ID_NPWP:           CategoryType.STRUCTURED,
    PayloadCategory.ID_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.JP_DL:             CategoryType.STRUCTURED,
    PayloadCategory.JP_HEALTH_INS:     CategoryType.STRUCTURED,
    PayloadCategory.JP_JUMINHYO:       CategoryType.STRUCTURED,
    PayloadCategory.JP_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.JP_RESIDENCE_CARD: CategoryType.STRUCTURED,
    PayloadCategory.MY_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.NZ_DL:             CategoryType.STRUCTURED,
    PayloadCategory.NZ_NHI:            CategoryType.STRUCTURED,
    PayloadCategory.NZ_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.PK_NICOP:          CategoryType.STRUCTURED,
    PayloadCategory.PK_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.PH_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.PH_PHILHEALTH:     CategoryType.STRUCTURED,
    PayloadCategory.PH_SSS:            CategoryType.STRUCTURED,
    PayloadCategory.PH_TIN:            CategoryType.STRUCTURED,
    PayloadCategory.PH_UMID:           CategoryType.STRUCTURED,
    PayloadCategory.SG_DL:             CategoryType.STRUCTURED,
    PayloadCategory.SG_FIN:            CategoryType.STRUCTURED,
    PayloadCategory.SG_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.KR_DL:             CategoryType.STRUCTURED,
    PayloadCategory.KR_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.LK_NIC_NEW:        CategoryType.STRUCTURED,
    PayloadCategory.LK_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.TH_DL:             CategoryType.STRUCTURED,
    PayloadCategory.TH_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.TH_TAX_ID:         CategoryType.STRUCTURED,
    PayloadCategory.VN_PASSPORT:       CategoryType.STRUCTURED,
    PayloadCategory.VN_TAX_CODE:       CategoryType.STRUCTURED,
    # Banking / crypto / financial sub-patterns
    PayloadCategory.ENCRYPTION_KEY:      CategoryType.STRUCTURED,
    PayloadCategory.HSM_KEY:             CategoryType.STRUCTURED,
    PayloadCategory.CARD_TRACK2:         CategoryType.STRUCTURED,
    PayloadCategory.CASHIER_CHECK:       CategoryType.STRUCTURED,
    PayloadCategory.CHECK_NUMBER:        CategoryType.STRUCTURED,
    PayloadCategory.AWS_SECRET_KEY:      CategoryType.HEURISTIC,
    PayloadCategory.GOOGLE_API_KEY:      CategoryType.HEURISTIC,
    PayloadCategory.GITHUB_OAUTH:        CategoryType.HEURISTIC,
    PayloadCategory.GITHUB_PAT:          CategoryType.HEURISTIC,
    PayloadCategory.NPM_TOKEN:           CategoryType.HEURISTIC,
    PayloadCategory.PYPI_TOKEN:          CategoryType.HEURISTIC,
    PayloadCategory.BITCOIN_BECH32:      CategoryType.STRUCTURED,
    PayloadCategory.BITCOIN_CASH:        CategoryType.STRUCTURED,
    PayloadCategory.LITECOIN:            CategoryType.STRUCTURED,
    PayloadCategory.MONERO:              CategoryType.STRUCTURED,
    PayloadCategory.RIPPLE:              CategoryType.STRUCTURED,
    PayloadCategory.STRIPE_PK:           CategoryType.HEURISTIC,
    PayloadCategory.BEARER_TOKEN:        CategoryType.HEURISTIC,
    PayloadCategory.DB_CONNECTION_STRING: CategoryType.HEURISTIC,
    PayloadCategory.PRIVATE_KEY:         CategoryType.HEURISTIC,
    PayloadCategory.MAILGUN_KEY:         CategoryType.HEURISTIC,
    PayloadCategory.SENDGRID_KEY:        CategoryType.HEURISTIC,
    PayloadCategory.SLACK_USER_TOKEN:    CategoryType.HEURISTIC,
    PayloadCategory.SLACK_WEBHOOK:       CategoryType.HEURISTIC,
    PayloadCategory.TWILIO_KEY:          CategoryType.HEURISTIC,
    # Contact / device sub-patterns
    PayloadCategory.IPV4_ADDRESS:  CategoryType.STRUCTURED,
    PayloadCategory.IPV6_ADDRESS:  CategoryType.STRUCTURED,
    PayloadCategory.MAC_ADDRESS:   CategoryType.STRUCTURED,
    PayloadCategory.IDFA_IDFV:     CategoryType.STRUCTURED,
    PayloadCategory.IMEI:          CategoryType.STRUCTURED,
    PayloadCategory.IMEISV:        CategoryType.STRUCTURED,
    PayloadCategory.MEID:          CategoryType.STRUCTURED,
    PayloadCategory.WORK_PERMIT:   CategoryType.STRUCTURED,
    PayloadCategory.GEOHASH:       CategoryType.STRUCTURED,
    PayloadCategory.INSURANCE_CLAIM: CategoryType.STRUCTURED,
    PayloadCategory.TELLER_ID:     CategoryType.STRUCTURED,
    # Corporate classification sub-patterns
    PayloadCategory.CORP_DND:          CategoryType.HEURISTIC,
    PayloadCategory.CORP_EMBARGOED:    CategoryType.HEURISTIC,
    PayloadCategory.CORP_EYES_ONLY:    CategoryType.HEURISTIC,
    PayloadCategory.CORP_HIGHLY_CONF:  CategoryType.HEURISTIC,
    PayloadCategory.CORP_INTERNAL_ONLY: CategoryType.HEURISTIC,
    PayloadCategory.CORP_NEED_TO_KNOW: CategoryType.HEURISTIC,
    PayloadCategory.CORP_PROPRIETARY:  CategoryType.HEURISTIC,
    PayloadCategory.CORP_RESTRICTED:   CategoryType.HEURISTIC,
    # Customer financial data
    PayloadCategory.ACCOUNT_BALANCE: CategoryType.STRUCTURED,
    PayloadCategory.DTI_RATIO:       CategoryType.STRUCTURED,
    PayloadCategory.INCOME_AMOUNT:   CategoryType.STRUCTURED,
    # Data classification labels sub-patterns
    PayloadCategory.DC_CUI:            CategoryType.HEURISTIC,
    PayloadCategory.DC_CLASSIFIED_CONF: CategoryType.HEURISTIC,
    PayloadCategory.DC_FOUO:           CategoryType.HEURISTIC,
    PayloadCategory.DC_LES:            CategoryType.HEURISTIC,
    PayloadCategory.DC_NOFORN:         CategoryType.HEURISTIC,
    PayloadCategory.DC_SBU:            CategoryType.HEURISTIC,
    PayloadCategory.DC_SECRET:         CategoryType.HEURISTIC,
    # Europe sub-patterns
    PayloadCategory.AT_DL:         CategoryType.STRUCTURED,
    PayloadCategory.AT_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.AT_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.AT_TAX_NUM:    CategoryType.STRUCTURED,
    PayloadCategory.BE_DL:         CategoryType.STRUCTURED,
    PayloadCategory.BE_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.BE_VAT:        CategoryType.STRUCTURED,
    PayloadCategory.BG_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.BG_LNC:        CategoryType.STRUCTURED,
    PayloadCategory.BG_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.HR_DL:         CategoryType.STRUCTURED,
    PayloadCategory.HR_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.HR_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.CY_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.CY_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.CZ_DL:         CategoryType.STRUCTURED,
    PayloadCategory.CZ_ICO:        CategoryType.STRUCTURED,
    PayloadCategory.CZ_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.DK_DL:         CategoryType.STRUCTURED,
    PayloadCategory.DK_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.EU_ETD:        CategoryType.STRUCTURED,
    PayloadCategory.EE_DL:         CategoryType.STRUCTURED,
    PayloadCategory.EE_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.FI_DL:         CategoryType.STRUCTURED,
    PayloadCategory.FI_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.FR_DL:         CategoryType.STRUCTURED,
    PayloadCategory.FR_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.FR_IBAN:       CategoryType.STRUCTURED,
    PayloadCategory.DE_DL:         CategoryType.STRUCTURED,
    PayloadCategory.DE_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.DE_SOCIAL_INS: CategoryType.STRUCTURED,
    PayloadCategory.DE_IBAN:       CategoryType.STRUCTURED,
    PayloadCategory.GR_AFM:        CategoryType.STRUCTURED,
    PayloadCategory.GR_DL:         CategoryType.STRUCTURED,
    PayloadCategory.GR_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.GR_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.HU_DL:         CategoryType.STRUCTURED,
    PayloadCategory.HU_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.HU_PERSONAL_ID: CategoryType.STRUCTURED,
    PayloadCategory.HU_TAX_NUM:    CategoryType.STRUCTURED,
    PayloadCategory.IS_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.IE_DL:         CategoryType.STRUCTURED,
    PayloadCategory.IE_EIRCODE:    CategoryType.STRUCTURED,
    PayloadCategory.IE_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.IT_DL:         CategoryType.STRUCTURED,
    PayloadCategory.IT_PIVA:       CategoryType.STRUCTURED,
    PayloadCategory.IT_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.IT_SSN:        CategoryType.STRUCTURED,
    PayloadCategory.LV_DL:         CategoryType.STRUCTURED,
    PayloadCategory.LV_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.LI_PIN:        CategoryType.STRUCTURED,
    PayloadCategory.LT_DL:         CategoryType.STRUCTURED,
    PayloadCategory.LT_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.LU_DL:         CategoryType.STRUCTURED,
    PayloadCategory.LU_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.MT_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.MT_TIN:        CategoryType.STRUCTURED,
    PayloadCategory.NL_DL:         CategoryType.STRUCTURED,
    PayloadCategory.NL_IBAN:       CategoryType.STRUCTURED,
    PayloadCategory.NL_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.NO_D_NUMBER:   CategoryType.STRUCTURED,
    PayloadCategory.NO_DL:         CategoryType.STRUCTURED,
    PayloadCategory.NO_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.PL_DL:         CategoryType.STRUCTURED,
    PayloadCategory.PL_ID_CARD:    CategoryType.STRUCTURED,
    PayloadCategory.PL_NIP:        CategoryType.STRUCTURED,
    PayloadCategory.PL_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.PL_REGON:      CategoryType.STRUCTURED,
    PayloadCategory.PT_CC:         CategoryType.STRUCTURED,
    PayloadCategory.PT_NISS:       CategoryType.STRUCTURED,
    PayloadCategory.PT_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.RO_CIF:        CategoryType.STRUCTURED,
    PayloadCategory.RO_DL:         CategoryType.STRUCTURED,
    PayloadCategory.RO_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.SK_DL:         CategoryType.STRUCTURED,
    PayloadCategory.SK_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.SI_DL:         CategoryType.STRUCTURED,
    PayloadCategory.SI_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.SI_TAX_NUM:    CategoryType.STRUCTURED,
    PayloadCategory.ES_DL:         CategoryType.STRUCTURED,
    PayloadCategory.ES_NIE:        CategoryType.STRUCTURED,
    PayloadCategory.ES_NSS:        CategoryType.STRUCTURED,
    PayloadCategory.ES_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.ES_IBAN:       CategoryType.STRUCTURED,
    PayloadCategory.SE_DL:         CategoryType.STRUCTURED,
    PayloadCategory.SE_ORG_NUM:    CategoryType.STRUCTURED,
    PayloadCategory.SE_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.CH_DL:         CategoryType.STRUCTURED,
    PayloadCategory.CH_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.CH_UID:        CategoryType.STRUCTURED,
    PayloadCategory.TR_DL:         CategoryType.STRUCTURED,
    PayloadCategory.TR_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.TR_TAX_ID:     CategoryType.STRUCTURED,
    PayloadCategory.UK_NHS:        CategoryType.STRUCTURED,
    PayloadCategory.UK_PASSPORT:   CategoryType.STRUCTURED,
    PayloadCategory.UK_PHONE:      CategoryType.STRUCTURED,
    PayloadCategory.UK_SORT_CODE:  CategoryType.STRUCTURED,
    PayloadCategory.UK_UTR:        CategoryType.STRUCTURED,
    # Financial regulatory label sub-patterns
    PayloadCategory.FRL_DRAFT_NOT_CIRC:   CategoryType.HEURISTIC,
    PayloadCategory.FRL_INFO_BARRIER:     CategoryType.HEURISTIC,
    PayloadCategory.FRL_INSIDE_INFO:      CategoryType.HEURISTIC,
    PayloadCategory.FRL_INVEST_RESTRICTED: CategoryType.HEURISTIC,
    PayloadCategory.FRL_MARKET_SENSITIVE:  CategoryType.HEURISTIC,
    PayloadCategory.FRL_PRE_DECISIONAL:   CategoryType.HEURISTIC,
    # Latin America sub-patterns
    PayloadCategory.AR_CUIL_CUIT: CategoryType.STRUCTURED,
    PayloadCategory.AR_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.BR_CNH:       CategoryType.STRUCTURED,
    PayloadCategory.BR_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.BR_RG:        CategoryType.STRUCTURED,
    PayloadCategory.BR_SUS:       CategoryType.STRUCTURED,
    PayloadCategory.CL_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.CO_NIT:       CategoryType.STRUCTURED,
    PayloadCategory.CO_NUIP:      CategoryType.STRUCTURED,
    PayloadCategory.CO_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.CR_DIMEX:     CategoryType.STRUCTURED,
    PayloadCategory.CR_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.EC_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.EC_RUC:       CategoryType.STRUCTURED,
    PayloadCategory.PY_CEDULA:    CategoryType.STRUCTURED,
    PayloadCategory.PY_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.PE_CARNET_EXT: CategoryType.STRUCTURED,
    PayloadCategory.PE_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.PE_RUC:       CategoryType.STRUCTURED,
    PayloadCategory.UY_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.UY_RUT:       CategoryType.STRUCTURED,
    PayloadCategory.VE_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.VE_RIF:       CategoryType.STRUCTURED,
    # Legal / loan / medical
    PayloadCategory.COURT_DOCKET:   CategoryType.STRUCTURED,
    PayloadCategory.LOAN_NUM_SHORT: CategoryType.STRUCTURED,
    PayloadCategory.LTV_RATIO:      CategoryType.STRUCTURED,
    PayloadCategory.MERS_MIN:       CategoryType.STRUCTURED,
    PayloadCategory.DEA_NUMBER:     CategoryType.STRUCTURED,
    PayloadCategory.HEALTH_PLAN_ID: CategoryType.STRUCTURED,
    PayloadCategory.ICD10_CODE:     CategoryType.STRUCTURED,
    # Middle East sub-patterns
    PayloadCategory.BH_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.IR_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.IQ_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.IL_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.JO_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.KW_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.LB_ID:        CategoryType.STRUCTURED,
    PayloadCategory.QA_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.SA_PASSPORT:  CategoryType.STRUCTURED,
    PayloadCategory.UAE_PASSPORT: CategoryType.STRUCTURED,
    PayloadCategory.UAE_VISA:     CategoryType.STRUCTURED,
    # North America — Canada sub-patterns
    PayloadCategory.CA_AB_DL:  CategoryType.STRUCTURED,
    PayloadCategory.CA_NWT_DL: CategoryType.STRUCTURED,
    PayloadCategory.CA_NU_DL:  CategoryType.STRUCTURED,
    PayloadCategory.CA_YT_DL:  CategoryType.STRUCTURED,
    PayloadCategory.CA_NEXUS:  CategoryType.STRUCTURED,
    PayloadCategory.CA_PR_CARD: CategoryType.STRUCTURED,
    # North America — Mexico sub-patterns
    PayloadCategory.MX_CLAVE_ELECTOR: CategoryType.STRUCTURED,
    PayloadCategory.MX_INE_CIC:  CategoryType.STRUCTURED,
    PayloadCategory.MX_INE_OCR:  CategoryType.STRUCTURED,
    PayloadCategory.MX_NSS:      CategoryType.STRUCTURED,
    PayloadCategory.MX_PASSPORT: CategoryType.STRUCTURED,
    PayloadCategory.MX_RFC:      CategoryType.STRUCTURED,
    # North America — US sub-patterns
    PayloadCategory.US_DEA:          CategoryType.STRUCTURED,
    PayloadCategory.US_DOD_ID:       CategoryType.STRUCTURED,
    PayloadCategory.US_KTN:          CategoryType.STRUCTURED,
    PayloadCategory.US_NPI:          CategoryType.STRUCTURED,
    PayloadCategory.US_PASSPORT_CARD: CategoryType.STRUCTURED,
    # Personal / postal
    PayloadCategory.GENDER_MARKER:  CategoryType.HEURISTIC,
    PayloadCategory.BR_CEP:         CategoryType.STRUCTURED,
    PayloadCategory.CA_POSTAL_CODE: CategoryType.STRUCTURED,
    PayloadCategory.JP_POSTAL_CODE: CategoryType.STRUCTURED,
    PayloadCategory.US_ZIP4:        CategoryType.STRUCTURED,
    # Privacy classification label sub-patterns
    PayloadCategory.PC_CCPA:     CategoryType.HEURISTIC,
    PayloadCategory.PC_FERPA:    CategoryType.HEURISTIC,
    PayloadCategory.PC_GDPR:     CategoryType.HEURISTIC,
    PayloadCategory.PC_GLBA:     CategoryType.HEURISTIC,
    PayloadCategory.PC_NPI_LABEL: CategoryType.HEURISTIC,
    PayloadCategory.PC_PHI:      CategoryType.HEURISTIC,
    PayloadCategory.PC_PII:      CategoryType.HEURISTIC,
    PayloadCategory.PC_SOX:      CategoryType.HEURISTIC,
    # Privileged information sub-patterns
    PayloadCategory.PRIV_LEGAL:           CategoryType.HEURISTIC,
    PayloadCategory.PRIV_LITIGATION_HOLD: CategoryType.HEURISTIC,
    PayloadCategory.PRIV_PRIVILEGED_INFO: CategoryType.HEURISTIC,
    PayloadCategory.PRIV_PRIV_CONF:       CategoryType.HEURISTIC,
    PayloadCategory.PRIV_PROTECTED:       CategoryType.HEURISTIC,
    PayloadCategory.PRIV_WORK_PRODUCT:    CategoryType.HEURISTIC,
    # Property / regulatory / securities
    PayloadCategory.TITLE_DEED:         CategoryType.STRUCTURED,
    PayloadCategory.REG_CTR:            CategoryType.STRUCTURED,
    PayloadCategory.REG_COMPLIANCE_CASE: CategoryType.STRUCTURED,
    PayloadCategory.REG_FINCEN:         CategoryType.STRUCTURED,
    PayloadCategory.REG_OFAC:           CategoryType.STRUCTURED,
    PayloadCategory.REG_SAR:            CategoryType.STRUCTURED,
    PayloadCategory.CUSIP_NUM:          CategoryType.STRUCTURED,
    PayloadCategory.FIGI_NUM:           CategoryType.STRUCTURED,
    PayloadCategory.LEI_NUM:            CategoryType.STRUCTURED,
    PayloadCategory.SEDOL_NUM:          CategoryType.STRUCTURED,
    PayloadCategory.TICKER_SYMBOL:      CategoryType.STRUCTURED,
    # Social media / supervisory / URL
    PayloadCategory.HASHTAG:             CategoryType.STRUCTURED,
    PayloadCategory.SUP_EXAM_FINDINGS:   CategoryType.HEURISTIC,
    PayloadCategory.SUP_NON_PUBLIC:      CategoryType.HEURISTIC,
    PayloadCategory.SUP_RESTRICTED_SUP:  CategoryType.HEURISTIC,
    PayloadCategory.SUP_SUPERVISORY_CONF: CategoryType.HEURISTIC,
    PayloadCategory.SUP_SUPERVISORY_CTRL: CategoryType.HEURISTIC,
    PayloadCategory.URL_WITH_TOKEN:      CategoryType.STRUCTURED,
    # Wire Transfer Data
    PayloadCategory.ACH_BATCH:           CategoryType.STRUCTURED,
    PayloadCategory.ACH_TRACE:           CategoryType.STRUCTURED,
    PayloadCategory.CHIPS_UID:           CategoryType.STRUCTURED,
    PayloadCategory.SEPA_REF:            CategoryType.STRUCTURED,
    PayloadCategory.WIRE_REF:            CategoryType.STRUCTURED,
    # US additional identifiers
    PayloadCategory.US_PHONE:            CategoryType.STRUCTURED,
    PayloadCategory.US_ROUTING:          CategoryType.STRUCTURED,
    # High-entropy secrets — detection is a heuristic over Shannon entropy, not a pattern
    PayloadCategory.RANDOM_API_KEY:      CategoryType.HEURISTIC,
    PayloadCategory.RANDOM_TOKEN:        CategoryType.HEURISTIC,
    PayloadCategory.RANDOM_SECRET:       CategoryType.HEURISTIC,
    PayloadCategory.ENCODED_CREDENTIAL:  CategoryType.HEURISTIC,
    PayloadCategory.ASSIGNMENT_SECRET:   CategoryType.HEURISTIC,
    PayloadCategory.GATED_SECRET:        CategoryType.HEURISTIC,
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
    confidence: Optional[float] = None
    bin_brand: Optional[str] = None
    bin_country: Optional[str] = None
    entropy_classification: Optional[str] = None
    validator: Optional[str] = None

    @property
    def severity(self) -> SeverityLevel:
        if self.error:
            return SeverityLevel.ERROR
        return SeverityLevel.PASS if self.detected else SeverityLevel.FAIL

    def to_dict(self):
        out = {
            "payload": self.payload.to_dict(),
            "variant": self.variant.to_dict(),
            "detected": self.detected,
            "severity": self.severity.value,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "raw_response": self.raw_response,
        }
        for key in ("confidence", "bin_brand", "bin_country",
                    "entropy_classification", "validator"):
            val = getattr(self, key)
            if val is not None:
                out[key] = val
        return out
