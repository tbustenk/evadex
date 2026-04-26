import re
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator


@register_generator("delimiter")
class DelimiterGenerator(BaseVariantGenerator):
    name = "delimiter"
    applicable_categories = {
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.IBAN,
        PayloadCategory.PHONE,
        PayloadCategory.CA_RAMQ,
        PayloadCategory.CA_ONTARIO_HEALTH,
        PayloadCategory.CA_BC_CARECARD,
        PayloadCategory.CA_AB_HEALTH,
        PayloadCategory.CA_QC_DRIVERS,
        PayloadCategory.CA_ON_DRIVERS,
        PayloadCategory.CA_BC_DRIVERS,
        PayloadCategory.CA_PASSPORT,
        PayloadCategory.CA_MB_HEALTH,
        PayloadCategory.CA_SK_HEALTH,
        PayloadCategory.CA_NS_HEALTH,
        PayloadCategory.CA_NB_HEALTH,
        PayloadCategory.CA_PEI_HEALTH,
        PayloadCategory.CA_NL_HEALTH,
        PayloadCategory.CA_MB_DRIVERS,
        PayloadCategory.CA_SK_DRIVERS,
        PayloadCategory.CA_NS_DRIVERS,
        PayloadCategory.CA_NB_DRIVERS,
        PayloadCategory.CA_PEI_DRIVERS,
        PayloadCategory.CA_NL_DRIVERS,
        PayloadCategory.CA_BUSINESS_NUMBER,
        PayloadCategory.CA_GST_HST,
        PayloadCategory.CA_TRANSIT_NUMBER,
        PayloadCategory.CA_BANK_ACCOUNT,
        # US additional
        PayloadCategory.US_DL,
        PayloadCategory.US_ITIN,
        PayloadCategory.US_EIN,
        PayloadCategory.US_MBI,
        # Europe
        PayloadCategory.UK_NIN,
        PayloadCategory.UK_DL,
        PayloadCategory.DE_ID,
        PayloadCategory.FR_CNI,
        PayloadCategory.ES_DNI,
        PayloadCategory.IT_CF,
        PayloadCategory.NL_BSN,
        PayloadCategory.SE_PIN,
        PayloadCategory.NO_FNR,
        PayloadCategory.FI_HETU,
        PayloadCategory.PL_PESEL,
        PayloadCategory.CH_AHV,
        # Asia-Pacific
        PayloadCategory.AU_MEDICARE,
        PayloadCategory.AU_PASSPORT,
        PayloadCategory.NZ_IRD,
        PayloadCategory.SG_NRIC,
        PayloadCategory.HK_HKID,
        PayloadCategory.JP_MY_NUMBER,
        PayloadCategory.IN_AADHAAR,
        PayloadCategory.IN_PAN,
        # Latin America
        PayloadCategory.BR_CPF,
        PayloadCategory.BR_CNPJ,
        PayloadCategory.MX_CURP,
        PayloadCategory.AR_DNI,
        PayloadCategory.CL_RUT,
        # Middle East & Africa
        PayloadCategory.UAE_EID,
        PayloadCategory.SA_NID,
        PayloadCategory.ZA_ID,
        PayloadCategory.IL_ID,
        # Functional categories
        PayloadCategory.SESSION_ID,
        PayloadCategory.PIN_BLOCK,
        PayloadCategory.BIOMETRIC_ID,
        PayloadCategory.CARD_EXPIRY,
        PayloadCategory.CARD_TRACK,
        PayloadCategory.MICR,
        PayloadCategory.CORP_CLASSIFICATION,
        PayloadCategory.FINANCIAL_AMOUNT,
        PayloadCategory.DATE_ISO,
        PayloadCategory.ICCID,
        PayloadCategory.EDU_EMAIL,
        PayloadCategory.EMPLOYEE_ID,
        PayloadCategory.MNPI,
        PayloadCategory.GPS_COORDS,
        PayloadCategory.INSURANCE_POLICY,
        PayloadCategory.BANK_REF,
        PayloadCategory.LEGAL_CASE,
        PayloadCategory.LOAN_NUMBER,
        PayloadCategory.NDC_CODE,
        PayloadCategory.CARDHOLDER_NAME,
        PayloadCategory.DOB,
        PayloadCategory.POSTAL_CODE,
        PayloadCategory.MASKED_PAN,
        PayloadCategory.PRIVACY_LABEL,
        PayloadCategory.ATTORNEY_CLIENT,
        PayloadCategory.PARCEL_NUMBER,
        PayloadCategory.AML_CASE_ID,
        PayloadCategory.ISIN,
        PayloadCategory.CUSIP_NUM,
        PayloadCategory.CINS_NUM,
        PayloadCategory.SEDOL_NUM,
        PayloadCategory.FIGI_NUM,
        PayloadCategory.LEI_NUM,
        PayloadCategory.TICKER_SYMBOL,
        PayloadCategory.REUTERS_RIC,
        PayloadCategory.VALOR_NUM,
        PayloadCategory.WKN_NUM,
        PayloadCategory.MT103_REF,
        PayloadCategory.MIFID_TX_ID,
        PayloadCategory.CHIPS_UID,
        PayloadCategory.SEPA_REF,
        PayloadCategory.WIRE_REF,
        PayloadCategory.TWITTER_HANDLE,
        PayloadCategory.SUPERVISORY_INFO,
        PayloadCategory.URL_WITH_CREDS,
        PayloadCategory.VIN,
        PayloadCategory.FEDWIRE_IMAD,
        # Africa
        PayloadCategory.EG_NID,
        PayloadCategory.ET_PASSPORT,
        PayloadCategory.GH_CARD,
        PayloadCategory.KE_KRA,
        PayloadCategory.MA_CIN,
        PayloadCategory.NG_BVN,
        PayloadCategory.TZ_NIDA,
        PayloadCategory.TN_CIN,
        PayloadCategory.UG_NIN,
        # Asia-Pacific (additional)
        PayloadCategory.BD_NID,
        PayloadCategory.ID_NIK,
        PayloadCategory.MY_MYKAD,
        PayloadCategory.PK_CNIC,
        PayloadCategory.PH_PHILSYS,
        PayloadCategory.KR_RRN,
        PayloadCategory.LK_NIC,
        PayloadCategory.TH_NID,
        PayloadCategory.VN_CCCD,
        # Europe (additional)
        PayloadCategory.AT_SVN,
        PayloadCategory.BE_NRN,
        PayloadCategory.BG_EGN,
        PayloadCategory.HR_OIB,
        PayloadCategory.CY_TIN,
        PayloadCategory.CZ_RC,
        PayloadCategory.DK_CPR,
        PayloadCategory.EE_IK,
        PayloadCategory.EU_VAT,
        PayloadCategory.GR_AMKA,
        PayloadCategory.HU_TAJ,
        PayloadCategory.IS_KT,
        PayloadCategory.IE_PPS,
        PayloadCategory.LV_PK,
        PayloadCategory.LI_PP,
        PayloadCategory.LT_AK,
        PayloadCategory.LU_NIN,
        PayloadCategory.MT_ID,
        PayloadCategory.PT_NIF,
        PayloadCategory.RO_CNP,
        PayloadCategory.SK_BN,
        PayloadCategory.SI_EMSO,
        PayloadCategory.TR_TC,
        # Latin America (additional)
        PayloadCategory.CO_CEDULA,
        PayloadCategory.CR_CEDULA,
        PayloadCategory.EC_CEDULA,
        PayloadCategory.PY_RUC,
        PayloadCategory.PE_DNI,
        PayloadCategory.UY_CI,
        PayloadCategory.VE_CEDULA,
        # Middle East (additional)
        PayloadCategory.BH_CPR,
        PayloadCategory.IR_MELLI,
        PayloadCategory.IQ_NID,
        PayloadCategory.JO_NID,
        PayloadCategory.KW_CIVIL,
        PayloadCategory.LB_PP,
        PayloadCategory.QA_QID,
    }

    def generate(self, value: str) -> Iterator[Variant]:
        # Strip existing delimiters to get raw alphanumeric string
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        yield self._make_variant(raw, "no_delimiter", "All delimiters removed")

        delimiters = [
            (' ',  "space_delimiter",   "Groups separated by spaces"),
            ('-',  "hyphen_delimiter",  "Groups separated by hyphens"),
            ('.',  "dot_delimiter",     "Groups separated by dots"),
            ('/',  "slash_delimiter",   "Groups separated by slashes"),
            ('\t', "tab_delimiter",     "Groups separated by tabs"),
            ('\n', "newline_delimiter", "Groups separated by newlines"),
        ]

        for sep, technique, desc in delimiters:
            result = sep.join(groups)
            if result != value:
                yield self._make_variant(result, technique, desc)

        # Mixed: alternate space and hyphen
        if len(groups) > 1:
            parts = []
            for i, g in enumerate(groups):
                parts.append(g)
                if i < len(groups) - 1:
                    parts.append(' ' if i % 2 == 0 else '-')
            mixed = ''.join(parts)
            if mixed != value:
                yield self._make_variant(
                    mixed,
                    "mixed_delimiter",
                    "Alternating space and hyphen delimiters",
                )

        # Excessive: double hyphens
        excessive = '--'.join(groups)
        if excessive != value:
            yield self._make_variant(excessive, "excessive_delimiter", "Doubled hyphen delimiters")
