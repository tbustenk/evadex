import re
from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant, PayloadCategory
from evadex.variants.base import BaseVariantGenerator

# U+00AD SOFT HYPHEN — signals a legal line-break point.
# Renderers typically hide it unless the line actually breaks there, so it is
# invisible in most display contexts. Some DLP scanners strip it during
# normalisation (correct behaviour); others pass it through to regex matching,
# causing patterns like \d{16} or \d{4}-\d{4}-... to fail.
SHY = '\u00AD'

# U+2060 WORD JOINER — invisible, inhibits line breaks. Complements SHY as a
# second invisible separator that scanners may treat differently.
WJ = '\u2060'


@register_generator("soft_hyphen")
class SoftHyphenGenerator(BaseVariantGenerator):
    name = "soft_hyphen"
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
        PayloadCategory.AWS_KEY,
        PayloadCategory.GITHUB_TOKEN,
        PayloadCategory.STRIPE_KEY,
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
        yield from self._at_group_boundaries(value)
        yield from self._between_every_char(value)
        yield from self._word_joiner_variants(value)
        yield from self._mixed_invisible(value)

    def _at_group_boundaries(self, value: str) -> Iterator[Variant]:
        """Insert SHY at every 4-character alphanumeric group boundary."""
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        result = SHY.join(groups)
        if result != value:
            yield self._make_variant(
                result,
                "shy_group_boundaries",
                "Soft hyphen (U+00AD) at every 4-char group boundary — invisible in rendering",
            )

        # Also at every 2-char boundary (tighter injection)
        groups2 = [raw[i:i+2] for i in range(0, len(raw), 2)]
        result2 = SHY.join(groups2)
        if result2 != value and result2 != result:
            yield self._make_variant(
                result2,
                "shy_2char_boundaries",
                "Soft hyphen (U+00AD) at every 2-char boundary",
            )

    def _between_every_char(self, value: str) -> Iterator[Variant]:
        """Insert SHY between every character — maximum injection density."""
        result = SHY.join(value)
        yield self._make_variant(
            result,
            "shy_between_every_char",
            "Soft hyphen (U+00AD) inserted between every character",
        )

    def _word_joiner_variants(self, value: str) -> Iterator[Variant]:
        """Same boundary patterns using word joiner (U+2060) instead of soft hyphen."""
        raw = re.sub(r'[^A-Za-z0-9]', '', value)
        groups = [raw[i:i+4] for i in range(0, len(raw), 4)]

        result = WJ.join(groups)
        if result != value:
            yield self._make_variant(
                result,
                "wj_group_boundaries",
                "Word joiner (U+2060) at every 4-char group boundary — inhibits line breaks invisibly",
            )

        result_every = WJ.join(value)
        yield self._make_variant(
            result_every,
            "wj_between_every_char",
            "Word joiner (U+2060) inserted between every character",
        )

    def _mixed_invisible(self, value: str) -> Iterator[Variant]:
        """Alternate SHY and WJ between characters — harder to filter with a single strip pass."""
        chars = list(value)
        parts = []
        for i, c in enumerate(chars):
            parts.append(c)
            if i < len(chars) - 1:
                parts.append(SHY if i % 2 == 0 else WJ)
        result = ''.join(parts)
        yield self._make_variant(
            result,
            "mixed_shy_wj",
            "Alternating soft hyphen and word joiner between every character",
        )
