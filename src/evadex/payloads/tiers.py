"""Tier definitions for evadex scan and generate commands.

Five tiers are available:

  northam  — default; North America (Canada + US) with full capital markets coverage
  banking  — Canadian banking focus; subset of northam without US IDs
  core     — ~150 payloads covering broader PII and financial identifiers
  regional — ~350 payloads with international coverage
  full     — all 554 payloads

When no --tier or --category flag is given, evadex uses the northam tier.
"""
from __future__ import annotations

from evadex.core.result import PayloadCategory

# ── Banking tier (default) ─────────────────────────────────────────────────────
# Optimised for Canadian banking and RBC's compliance surface.
BANKING_TIER: frozenset[PayloadCategory] = frozenset({
    # ── Core financial ─────────────────────────────────────────────────
    PayloadCategory.CREDIT_CARD,
    PayloadCategory.IBAN,
    PayloadCategory.FR_IBAN,
    PayloadCategory.DE_IBAN,
    PayloadCategory.ES_IBAN,
    PayloadCategory.NL_IBAN,
    PayloadCategory.SWIFT_BIC,
    PayloadCategory.ABA_ROUTING,
    PayloadCategory.CA_TRANSIT_NUMBER,
    PayloadCategory.CA_BANK_ACCOUNT,
    PayloadCategory.CA_BUSINESS_NUMBER,
    PayloadCategory.CA_GST_HST,
    # ── Canadian identity ──────────────────────────────────────────────
    PayloadCategory.SIN,
    PayloadCategory.CA_RAMQ,
    PayloadCategory.CA_PASSPORT,
    # Provincial health cards (10 provinces; RAMQ covers QC)
    PayloadCategory.CA_ONTARIO_HEALTH,
    PayloadCategory.CA_BC_CARECARD,
    PayloadCategory.CA_AB_HEALTH,
    PayloadCategory.CA_MB_HEALTH,
    PayloadCategory.CA_SK_HEALTH,
    PayloadCategory.CA_NS_HEALTH,
    PayloadCategory.CA_NB_HEALTH,
    PayloadCategory.CA_PEI_HEALTH,
    PayloadCategory.CA_NL_HEALTH,
    # Provincial + territorial driver's licences (10 provinces + 3 territories)
    PayloadCategory.CA_QC_DRIVERS,
    PayloadCategory.CA_ON_DRIVERS,
    PayloadCategory.CA_BC_DRIVERS,
    PayloadCategory.CA_MB_DRIVERS,
    PayloadCategory.CA_SK_DRIVERS,
    PayloadCategory.CA_NS_DRIVERS,
    PayloadCategory.CA_NB_DRIVERS,
    PayloadCategory.CA_PEI_DRIVERS,
    PayloadCategory.CA_NL_DRIVERS,
    PayloadCategory.CA_AB_DL,
    PayloadCategory.CA_NWT_DL,
    PayloadCategory.CA_NU_DL,
    PayloadCategory.CA_YT_DL,
    # Canadian supplementary
    PayloadCategory.CA_POSTAL_CODE,
    PayloadCategory.CA_NEXUS,
    PayloadCategory.CA_PR_CARD,
    # ── Universal PII ─────────────────────────────────────────────────
    PayloadCategory.EMAIL,
    PayloadCategory.PHONE,
    PayloadCategory.SSN,
    # ── Banking functional / PCI ──────────────────────────────────────
    PayloadCategory.CARD_EXPIRY,
    PayloadCategory.CARD_TRACK,
    PayloadCategory.CARD_TRACK2,
    PayloadCategory.MASKED_PAN,
    PayloadCategory.PIN_BLOCK,
    PayloadCategory.MICR,
    PayloadCategory.ENCRYPTION_KEY,
    PayloadCategory.HSM_KEY,
    PayloadCategory.BANK_REF,
    PayloadCategory.AML_CASE_ID,
    PayloadCategory.ACCOUNT_BALANCE,
    PayloadCategory.FINANCIAL_AMOUNT,
    PayloadCategory.FEDWIRE_IMAD,
    PayloadCategory.CHIPS_UID,
    PayloadCategory.WIRE_REF,
    PayloadCategory.SEPA_REF,
    PayloadCategory.MT103_REF,
    PayloadCategory.ACH_TRACE,
    PayloadCategory.ACH_BATCH,
    PayloadCategory.US_ROUTING,
    PayloadCategory.US_PHONE,
    PayloadCategory.TELLER_ID,
    PayloadCategory.LOAN_NUMBER,
    PayloadCategory.DOB,
    PayloadCategory.ISIN,
    PayloadCategory.INSURANCE_POLICY,
    PayloadCategory.DTI_RATIO,
    PayloadCategory.INCOME_AMOUNT,
})


# ── Core tier ─────────────────────────────────────────────────────────────────
# Banking tier + US national IDs + major European + Australasia + broader PII.
CORE_TIER: frozenset[PayloadCategory] = BANKING_TIER | frozenset({
    # US national identifiers
    PayloadCategory.US_DL,
    PayloadCategory.US_ITIN,
    PayloadCategory.US_EIN,
    PayloadCategory.US_MBI,
    PayloadCategory.US_PASSPORT,
    PayloadCategory.US_DEA,
    PayloadCategory.US_NPI,
    PayloadCategory.US_ZIP4,
    # UK
    PayloadCategory.UK_NIN,
    PayloadCategory.UK_DL,
    PayloadCategory.UK_NHS,
    PayloadCategory.UK_SORT_CODE,
    PayloadCategory.UK_UTR,
    PayloadCategory.UK_PHONE,
    PayloadCategory.UK_PASSPORT,
    # Germany
    PayloadCategory.DE_ID,
    PayloadCategory.DE_TAX_ID,
    PayloadCategory.DE_DL,
    PayloadCategory.DE_PASSPORT,
    PayloadCategory.DE_SOCIAL_INS,
    # France
    PayloadCategory.FR_CNI,
    PayloadCategory.FR_INSEE,
    PayloadCategory.FR_DL,
    PayloadCategory.FR_PASSPORT,
    # Spain
    PayloadCategory.ES_DNI,
    PayloadCategory.ES_DL,
    PayloadCategory.ES_NIE,
    PayloadCategory.ES_NSS,
    PayloadCategory.ES_PASSPORT,
    # Italy / Netherlands / Scandinavia / Switzerland / Poland
    PayloadCategory.IT_CF,
    PayloadCategory.NL_BSN,
    PayloadCategory.NL_DL,
    PayloadCategory.SE_PIN,
    PayloadCategory.NO_FNR,
    PayloadCategory.FI_HETU,
    PayloadCategory.PL_PESEL,
    PayloadCategory.CH_AHV,
    # Australia / NZ
    PayloadCategory.AU_TFN,
    PayloadCategory.AU_MEDICARE,
    PayloadCategory.AU_PASSPORT,
    PayloadCategory.AU_DL,
    PayloadCategory.NZ_IRD,
    PayloadCategory.NZ_DL,
    PayloadCategory.NZ_NHI,
    PayloadCategory.NZ_PASSPORT,
    # Asia
    PayloadCategory.SG_NRIC,
    PayloadCategory.JP_MY_NUMBER,
    PayloadCategory.IN_AADHAAR,
    PayloadCategory.IN_PAN,
    # Latin America — major
    PayloadCategory.BR_CPF,
    PayloadCategory.MX_CURP,
    # Functional / PCI
    PayloadCategory.SESSION_ID,
    PayloadCategory.BIOMETRIC_ID,
    PayloadCategory.DATE_ISO,
    PayloadCategory.EMPLOYEE_ID,
    PayloadCategory.LOAN_NUM_SHORT,
    PayloadCategory.LTV_RATIO,
    PayloadCategory.MERS_MIN,
    PayloadCategory.REG_CTR,
    PayloadCategory.REG_FINCEN,
    PayloadCategory.REG_SAR,
    PayloadCategory.REG_COMPLIANCE_CASE,
    PayloadCategory.CUSIP_NUM,
    PayloadCategory.CINS_NUM,
    PayloadCategory.LEI_NUM,
    PayloadCategory.FIGI_NUM,
    PayloadCategory.SEDOL_NUM,
    PayloadCategory.TICKER_SYMBOL,
    PayloadCategory.REUTERS_RIC,
    PayloadCategory.VALOR_NUM,
    PayloadCategory.WKN_NUM,
    PayloadCategory.MIFID_TX_ID,
})


# ── Regional tier ─────────────────────────────────────────────────────────────
# Core tier + full European + Asia-Pacific + Latin America + Middle East.
REGIONAL_TIER: frozenset[PayloadCategory] = CORE_TIER | frozenset({
    # Europe — full expansion
    PayloadCategory.AT_SVN, PayloadCategory.AT_DL, PayloadCategory.AT_ID_CARD,
    PayloadCategory.AT_PASSPORT, PayloadCategory.AT_TAX_NUM,
    PayloadCategory.BE_NRN, PayloadCategory.BE_DL, PayloadCategory.BE_PASSPORT, PayloadCategory.BE_VAT,
    PayloadCategory.BG_EGN, PayloadCategory.BG_ID_CARD, PayloadCategory.BG_LNC, PayloadCategory.BG_PASSPORT,
    PayloadCategory.HR_OIB, PayloadCategory.HR_DL, PayloadCategory.HR_ID_CARD, PayloadCategory.HR_PASSPORT,
    PayloadCategory.CY_TIN, PayloadCategory.CY_ID_CARD, PayloadCategory.CY_PASSPORT,
    PayloadCategory.CZ_RC, PayloadCategory.CZ_DL, PayloadCategory.CZ_ICO, PayloadCategory.CZ_PASSPORT,
    PayloadCategory.DK_CPR, PayloadCategory.DK_DL, PayloadCategory.DK_PASSPORT,
    PayloadCategory.EE_IK, PayloadCategory.EE_DL, PayloadCategory.EE_PASSPORT,
    PayloadCategory.EU_VAT, PayloadCategory.EU_ETD,
    PayloadCategory.FI_DL, PayloadCategory.FI_PASSPORT,
    PayloadCategory.FR_DL, PayloadCategory.FR_PASSPORT,
    PayloadCategory.GR_AMKA, PayloadCategory.GR_AFM, PayloadCategory.GR_DL,
    PayloadCategory.GR_ID_CARD, PayloadCategory.GR_PASSPORT,
    PayloadCategory.HU_TAJ, PayloadCategory.HU_DL, PayloadCategory.HU_PASSPORT,
    PayloadCategory.HU_PERSONAL_ID, PayloadCategory.HU_TAX_NUM,
    PayloadCategory.IS_KT, PayloadCategory.IS_PASSPORT,
    PayloadCategory.IE_PPS, PayloadCategory.IE_DL, PayloadCategory.IE_EIRCODE, PayloadCategory.IE_PASSPORT,
    PayloadCategory.IT_DL, PayloadCategory.IT_PIVA, PayloadCategory.IT_PASSPORT, PayloadCategory.IT_SSN,
    PayloadCategory.LV_PK, PayloadCategory.LV_DL, PayloadCategory.LV_PASSPORT,
    PayloadCategory.LI_PP, PayloadCategory.LI_PIN,
    PayloadCategory.LT_AK, PayloadCategory.LT_DL, PayloadCategory.LT_PASSPORT,
    PayloadCategory.LU_NIN, PayloadCategory.LU_DL, PayloadCategory.LU_PASSPORT,
    PayloadCategory.MT_ID, PayloadCategory.MT_PASSPORT, PayloadCategory.MT_TIN,
    PayloadCategory.NL_PASSPORT,
    PayloadCategory.NO_D_NUMBER, PayloadCategory.NO_DL, PayloadCategory.NO_PASSPORT,
    PayloadCategory.PL_DL, PayloadCategory.PL_ID_CARD, PayloadCategory.PL_NIP,
    PayloadCategory.PL_PASSPORT, PayloadCategory.PL_REGON,
    PayloadCategory.PT_NIF, PayloadCategory.PT_CC, PayloadCategory.PT_NISS, PayloadCategory.PT_PASSPORT,
    PayloadCategory.RO_CNP, PayloadCategory.RO_CIF, PayloadCategory.RO_DL, PayloadCategory.RO_PASSPORT,
    PayloadCategory.SK_BN, PayloadCategory.SK_DL, PayloadCategory.SK_PASSPORT,
    PayloadCategory.SI_EMSO, PayloadCategory.SI_DL, PayloadCategory.SI_PASSPORT, PayloadCategory.SI_TAX_NUM,
    PayloadCategory.SE_DL, PayloadCategory.SE_ORG_NUM, PayloadCategory.SE_PASSPORT,
    PayloadCategory.CH_DL, PayloadCategory.CH_PASSPORT, PayloadCategory.CH_UID,
    PayloadCategory.TR_TC, PayloadCategory.TR_DL, PayloadCategory.TR_PASSPORT, PayloadCategory.TR_TAX_ID,
    # Asia-Pacific — full
    PayloadCategory.HK_HKID,
    PayloadCategory.BD_NID, PayloadCategory.BD_PASSPORT, PayloadCategory.BD_TIN,
    PayloadCategory.CN_RID, PayloadCategory.CN_PASSPORT, PayloadCategory.MO_ID, PayloadCategory.TW_NID,
    PayloadCategory.ID_NIK, PayloadCategory.ID_NPWP, PayloadCategory.ID_PASSPORT,
    PayloadCategory.IN_DL, PayloadCategory.IN_PASSPORT, PayloadCategory.IN_RATION_CARD, PayloadCategory.IN_VOTER_ID,
    PayloadCategory.JP_DL, PayloadCategory.JP_HEALTH_INS, PayloadCategory.JP_JUMINHYO,
    PayloadCategory.JP_PASSPORT, PayloadCategory.JP_RESIDENCE_CARD,
    PayloadCategory.KR_RRN, PayloadCategory.KR_DL, PayloadCategory.KR_PASSPORT,
    PayloadCategory.LK_NIC, PayloadCategory.LK_NIC_NEW, PayloadCategory.LK_PASSPORT,
    PayloadCategory.MY_MYKAD, PayloadCategory.MY_PASSPORT,
    PayloadCategory.PK_CNIC, PayloadCategory.PK_NICOP, PayloadCategory.PK_PASSPORT,
    PayloadCategory.PH_PHILSYS, PayloadCategory.PH_PASSPORT, PayloadCategory.PH_PHILHEALTH,
    PayloadCategory.PH_SSS, PayloadCategory.PH_TIN, PayloadCategory.PH_UMID,
    PayloadCategory.SG_DL, PayloadCategory.SG_FIN, PayloadCategory.SG_PASSPORT,
    PayloadCategory.TH_NID, PayloadCategory.TH_DL, PayloadCategory.TH_PASSPORT, PayloadCategory.TH_TAX_ID,
    PayloadCategory.VN_CCCD, PayloadCategory.VN_PASSPORT, PayloadCategory.VN_TAX_CODE,
    # Latin America — full
    PayloadCategory.AR_DNI, PayloadCategory.AR_CUIL_CUIT, PayloadCategory.AR_PASSPORT,
    PayloadCategory.BR_CNPJ, PayloadCategory.BR_CNH, PayloadCategory.BR_PASSPORT,
    PayloadCategory.BR_RG, PayloadCategory.BR_SUS,
    PayloadCategory.CL_RUT, PayloadCategory.CL_PASSPORT,
    PayloadCategory.CO_CEDULA, PayloadCategory.CO_NIT, PayloadCategory.CO_NUIP, PayloadCategory.CO_PASSPORT,
    PayloadCategory.CR_CEDULA, PayloadCategory.CR_DIMEX, PayloadCategory.CR_PASSPORT,
    PayloadCategory.EC_CEDULA, PayloadCategory.EC_PASSPORT, PayloadCategory.EC_RUC,
    PayloadCategory.MX_CURP, PayloadCategory.MX_CLAVE_ELECTOR, PayloadCategory.MX_INE_CIC,
    PayloadCategory.MX_INE_OCR, PayloadCategory.MX_NSS, PayloadCategory.MX_PASSPORT, PayloadCategory.MX_RFC,
    PayloadCategory.PY_RUC, PayloadCategory.PY_CEDULA, PayloadCategory.PY_PASSPORT,
    PayloadCategory.PE_DNI, PayloadCategory.PE_CARNET_EXT, PayloadCategory.PE_PASSPORT, PayloadCategory.PE_RUC,
    PayloadCategory.UY_CI, PayloadCategory.UY_PASSPORT, PayloadCategory.UY_RUT,
    PayloadCategory.VE_CEDULA, PayloadCategory.VE_PASSPORT, PayloadCategory.VE_RIF,
    # Middle East
    PayloadCategory.UAE_EID, PayloadCategory.UAE_PASSPORT, PayloadCategory.UAE_VISA,
    PayloadCategory.SA_NID, PayloadCategory.SA_PASSPORT,
    PayloadCategory.ZA_ID, PayloadCategory.ZA_DL, PayloadCategory.ZA_PASSPORT,
    PayloadCategory.IL_ID, PayloadCategory.IL_PASSPORT,
    PayloadCategory.BH_CPR, PayloadCategory.BH_PASSPORT,
    PayloadCategory.IR_MELLI, PayloadCategory.IR_PASSPORT,
    PayloadCategory.IQ_NID, PayloadCategory.IQ_PASSPORT,
    PayloadCategory.JO_NID, PayloadCategory.JO_PASSPORT,
    PayloadCategory.KW_CIVIL, PayloadCategory.KW_PASSPORT,
    PayloadCategory.LB_PP, PayloadCategory.LB_ID,
    PayloadCategory.QA_QID, PayloadCategory.QA_PASSPORT,
})


# ── North America tier (default) ─────────────────────────────────────────────
# Banking tier + US national identifiers + full capital markets identifier set.
# Covers Canada and the United States — the most common North American
# compliance surface for financial institutions operating in both markets.
NORTHAM_TIER: frozenset[PayloadCategory] = BANKING_TIER | frozenset({
    # ── US national identifiers ────────────────────────────────────────
    PayloadCategory.US_DL,
    PayloadCategory.US_ITIN,
    PayloadCategory.US_EIN,
    PayloadCategory.US_MBI,
    PayloadCategory.US_PASSPORT,
    PayloadCategory.US_PASSPORT_CARD,
    PayloadCategory.US_ZIP4,
    PayloadCategory.US_DEA,
    PayloadCategory.US_NPI,
    PayloadCategory.US_KTN,
    # ── Capital markets — securities identifiers ──────────────────────
    PayloadCategory.CUSIP_NUM,
    PayloadCategory.CINS_NUM,
    PayloadCategory.SEDOL_NUM,
    PayloadCategory.FIGI_NUM,
    PayloadCategory.LEI_NUM,
    PayloadCategory.REUTERS_RIC,
    PayloadCategory.TICKER_SYMBOL,
    PayloadCategory.MIFID_TX_ID,
    PayloadCategory.VALOR_NUM,
    PayloadCategory.WKN_NUM,
    # ── Regulatory / compliance ───────────────────────────────────────
    PayloadCategory.MERS_MIN,
    PayloadCategory.REG_CTR,
    PayloadCategory.REG_FINCEN,
    PayloadCategory.REG_SAR,
    PayloadCategory.REG_COMPLIANCE_CASE,
    PayloadCategory.LTV_RATIO,
    # ── Functional / PCI ─────────────────────────────────────────────
    PayloadCategory.SESSION_ID,
    PayloadCategory.BIOMETRIC_ID,
    PayloadCategory.EMPLOYEE_ID,
    PayloadCategory.DATE_ISO,
    PayloadCategory.LOAN_NUM_SHORT,
})


# ── Full tier ─────────────────────────────────────────────────────────────────
# All payloads. Pass include_heuristic=True separately to include heuristic ones.
# This sentinel tells get_payloads to skip category filtering entirely.
FULL_TIER: None = None   # None → no category filter → all payloads


# ── Tier registry ─────────────────────────────────────────────────────────────
VALID_TIERS = {"northam", "banking", "core", "regional", "full"}


def get_tier_categories(tier: str) -> frozenset[PayloadCategory] | None:
    """Return the category set for *tier*, or None for the full tier (no filter)."""
    if tier == "northam":
        return NORTHAM_TIER
    if tier == "banking":
        return BANKING_TIER
    if tier == "core":
        return CORE_TIER
    if tier == "regional":
        return REGIONAL_TIER
    if tier == "full":
        return FULL_TIER
    raise ValueError(f"Unknown tier: {tier!r}. Valid tiers: {', '.join(sorted(VALID_TIERS))}")
