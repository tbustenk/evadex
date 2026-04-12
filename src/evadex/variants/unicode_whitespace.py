import re
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator

# Unicode whitespace characters — all distinct from ASCII space/tab/newline
# used by the delimiter generator. These can bypass regex patterns that only
# check for ASCII \s or specific ASCII separators.
UNICODE_SPACES = [
    ('\u00A0', 'nbsp',              'non-breaking space (U+00A0)'),
    ('\u2002', 'en_space',          'en-space (U+2002)'),
    ('\u2003', 'em_space',          'em-space (U+2003)'),
    ('\u2009', 'thin_space',        'thin space (U+2009)'),
    ('\u2007', 'figure_space',      'figure space (U+2007) — same width as a digit'),
    ('\u202F', 'narrow_nbsp',       'narrow no-break space (U+202F)'),
    ('\u3000', 'ideographic_space', 'ideographic space (U+3000)'),
]


@register_generator("unicode_whitespace")
class UnicodeWhitespaceGenerator(BaseVariantGenerator):
    name = "unicode_whitespace"
    applicable_categories = {
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SSN,
        PayloadCategory.SIN,
        PayloadCategory.IBAN,
        PayloadCategory.PHONE,
        PayloadCategory.ABA_ROUTING,
        PayloadCategory.US_PASSPORT,
        PayloadCategory.AU_TFN,
        PayloadCategory.DE_TAX_ID,
        PayloadCategory.FR_INSEE,
        PayloadCategory.CA_RAMQ,
        PayloadCategory.CA_ONTARIO_HEALTH,
        PayloadCategory.CA_BC_CARECARD,
        PayloadCategory.CA_AB_HEALTH,
        PayloadCategory.CA_QC_DRIVERS,
        PayloadCategory.CA_ON_DRIVERS,
        PayloadCategory.CA_BC_DRIVERS,
        PayloadCategory.CA_PASSPORT,
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
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        for char, tech_suffix, description in UNICODE_SPACES:
            result = char.join(groups)
            if result != value:
                yield self._make_variant(
                    result,
                    f"unicode_{tech_suffix}",
                    f"Groups separated by {description}",
                )

        # Mixed: alternating NBSP and thin space between groups
        if len(groups) > 1:
            parts = []
            for i, g in enumerate(groups):
                parts.append(g)
                if i < len(groups) - 1:
                    parts.append('\u00A0' if i % 2 == 0 else '\u2009')
            result = ''.join(parts)
            if result != value:
                yield self._make_variant(
                    result,
                    "unicode_mixed_spaces",
                    "Alternating non-breaking space and thin space between groups",
                )
