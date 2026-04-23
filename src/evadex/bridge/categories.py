"""Map siphon-c2 coarse categories to evadex fine-grained payload categories.

The C2 dashboard reports metrics by six coarse groups (PCI · PII · PHI · CRED
· SECRET · CRYPTO). evadex's native taxonomy is ~300 fine categories from
:class:`evadex.core.result.PayloadCategory`. This module owns the mapping
both ways so the bridge can:

  * take a C2 category name and expand it into the underlying evadex ids
    (for ``POST /v1/evadex/run`` and ``POST /v1/evadex/generate``), and
  * roll a per-fine-category scan result back up into C2 buckets for
    ``GET /v1/evadex/metrics``.
"""
from __future__ import annotations

from typing import Iterable


# Coarse C2 category  →  fine evadex PayloadCategory values.
# Kept small and explicit. Anything not listed here rolls up under "OTHER"
# in :func:`bucket_for_category`.
C2_TO_EVADEX: dict[str, list[str]] = {
    "PCI": [
        "credit_card",
        "iban",
        "swift_bic",
        "aba_routing",
        "card_expiry",
        "card_track",
        "masked_pan",
        "micr",
    ],
    "PII": [
        "ssn",
        "sin",
        "email",
        "phone",
        "ca_ramq",
        "ca_ontario_health",
        "ca_bc_carecard",
        "ca_ab_health",
        "ca_mb_health",
        "ca_sk_health",
        "ca_ns_health",
        "ca_nb_health",
        "ca_pei_health",
        "ca_nl_health",
        "ca_qc_drivers",
        "ca_on_drivers",
        "ca_bc_drivers",
        "ca_mb_drivers",
        "ca_sk_drivers",
        "ca_ns_drivers",
        "ca_nb_drivers",
        "ca_pei_drivers",
        "ca_nl_drivers",
        "ca_passport",
        "us_passport",
        "us_dl",
        "dob",
        "postal_code",
    ],
    "PHI": [
        "us_npi",
        "us_mbi",
        "au_medicare",
        "ca_ramq",
        "ca_ontario_health",
        "ca_bc_carecard",
        "ca_ab_health",
        "ca_mb_health",
        "ca_sk_health",
        "ca_ns_health",
        "ca_nb_health",
        "ca_pei_health",
        "ca_nl_health",
        "ndc_code",
        "insurance_policy",
    ],
    "CRED": [
        "aws_key",
        "github_token",
        "stripe_key",
        "slack_token",
        "jwt",
        "url_with_creds",
    ],
    "SECRET": [
        "session_id",
        "pin_block",
        "mnpi",
        "attorney_client",
        "supervisory_info",
        "corp_classification",
    ],
    "CRYPTO": [
        "bitcoin",
        "ethereum",
    ],
    "CLASSIFIED": [
        "classification",
        "corp_classification",
        "privacy_label",
    ],
}

# Reverse index — evadex category → coarse C2 bucket. Built once at import.
_EVADEX_TO_C2: dict[str, str] = {}
for _bucket, _cats in C2_TO_EVADEX.items():
    for _c in _cats:
        # First bucket wins so we stay deterministic for categories listed
        # under more than one coarse group (e.g. ca_ramq is both PII + PHI).
        _EVADEX_TO_C2.setdefault(_c, _bucket)


def expand(c2_category: str) -> list[str]:
    """Return evadex categories for a C2 coarse bucket.

    Unknown names return an empty list so callers can decide whether to
    error or fall back to a tier.
    """
    return list(C2_TO_EVADEX.get(c2_category.upper(), []))


def expand_many(c2_categories: Iterable[str]) -> list[str]:
    """Expand a list of C2 buckets, deduplicated, preserving first-seen order."""
    seen: dict[str, None] = {}
    for name in c2_categories:
        for c in expand(name):
            seen.setdefault(c, None)
    return list(seen.keys())


def bucket_for_category(evadex_category: str) -> str:
    """Return the C2 coarse bucket for an evadex fine category.

    Anything not mapped returns ``"OTHER"`` so the caller can still roll
    it up without losing it.
    """
    return _EVADEX_TO_C2.get(evadex_category, "OTHER")


def all_buckets() -> list[str]:
    """Stable list of coarse C2 buckets, display order."""
    return ["PCI", "PII", "PHI", "CRED", "SECRET", "CRYPTO", "CLASSIFIED"]


# ── Full catalog for the run-controls UI ───────────────────────────
# The bridge surfaces every registered payload category so the C2's
# checkbox panel can populate dynamically. Adding a new entry to
# ``PayloadCategory`` automatically appears in the panel — no UI
# change required, so long as the classifier below can place it.

# Display order for the "groups" dict the endpoint returns. Anything
# the classifier produces that isn't listed here sorts to the end.
CATALOG_GROUP_ORDER: tuple[str, ...] = (
    "Credit Cards",
    "Banking",
    "Canadian IDs",
    "US IDs",
    "European IDs",
    "Asia-Pacific IDs",
    "Latin America IDs",
    "Middle East & Africa IDs",
    "Healthcare",
    "Secrets & Credentials",
    "Crypto",
    "Classification",
    "Regulatory & Legal",
    "PII",
    "Other",
)

# Explicit classifications for categories whose name doesn't carry a
# regional prefix we can key on. Anything not in here falls through to
# the prefix map and then to the heuristic keyword scan below.
_CATALOG_EXPLICIT: dict[str, str] = {
    # Credit cards / PCI payment
    "credit_card":      "Credit Cards",
    "card_expiry":      "Credit Cards",
    "card_track":       "Credit Cards",
    "card_track2":      "Credit Cards",
    "masked_pan":       "Credit Cards",
    "cardholder_name":  "Credit Cards",
    # Banking — non-regional rails & refs
    "iban":             "Banking",
    "swift_bic":        "Banking",
    "aba_routing":      "Banking",
    "micr":             "Banking",
    "pin_block":        "Banking",
    "fedwire_imad":     "Banking",
    "chips_uid":        "Banking",
    "wire_ref":         "Banking",
    "sepa_ref":         "Banking",
    "ach_trace":        "Banking",
    "ach_batch":        "Banking",
    "bank_ref":         "Banking",
    "account_balance":  "Banking",
    "financial_amount": "Banking",
    "teller_id":        "Banking",
    "loan_number":      "Banking",
    "loan_num_short":   "Banking",
    "ltv_ratio":        "Banking",
    "dti_ratio":        "Banking",
    "income_amount":    "Banking",
    "aml_case_id":      "Banking",
    "isin":             "Banking",
    "cusip_num":        "Banking",
    "figi_num":         "Banking",
    "lei_num":          "Banking",
    "sedol_num":        "Banking",
    "ticker_symbol":    "Banking",
    "mers_min":         "Banking",
    "title_deed":       "Banking",
    # PII — the coarse global basics
    "ssn":           "US IDs",
    "sin":           "Canadian IDs",
    "email":         "PII",
    "phone":         "PII",
    "dob":           "PII",
    "postal_code":   "PII",
    "edu_email":     "PII",
    "employee_id":   "PII",
    "gender_marker": "PII",
    "gps_coords":    "PII",
    "date_iso":      "PII",
    "biometric_id":  "PII",
    "iccid":         "PII",
    "hashtag":       "PII",
    # Healthcare — non-regional
    "insurance_policy": "Healthcare",
    "ndc_code":         "Healthcare",
    "icd10_code":       "Healthcare",
    "health_plan_id":   "Healthcare",
    "dea_number":       "Healthcare",
    # Crypto
    "bitcoin":  "Crypto",
    "ethereum": "Crypto",
    # Secrets & credentials
    "aws_key":            "Secrets & Credentials",
    "github_token":       "Secrets & Credentials",
    "stripe_key":         "Secrets & Credentials",
    "slack_token":        "Secrets & Credentials",
    "jwt":                "Secrets & Credentials",
    "url_with_creds":     "Secrets & Credentials",
    "url_with_token":     "Secrets & Credentials",
    "session_id":         "Secrets & Credentials",
    "encryption_key":     "Secrets & Credentials",
    "hsm_key":            "Secrets & Credentials",
    "random_api_key":     "Secrets & Credentials",
    "random_token":       "Secrets & Credentials",
    "random_secret":      "Secrets & Credentials",
    "encoded_credential": "Secrets & Credentials",
    "assignment_secret":  "Secrets & Credentials",
    "gated_secret":       "Secrets & Credentials",
    # Classification / data labels
    "classification":      "Classification",
    "corp_classification": "Classification",
    "privacy_label":       "Classification",
    "pc_ccpa":             "Classification",
    "pc_ferpa":            "Classification",
    "pc_gdpr":             "Classification",
    "pc_glba":             "Classification",
    "pc_npi_label":        "Classification",
    "pc_phi":              "Classification",
    "pc_pii":              "Classification",
    "pc_sox":              "Classification",
    # Regulatory / legal
    "mnpi":                   "Regulatory & Legal",
    "attorney_client":        "Regulatory & Legal",
    "supervisory_info":       "Regulatory & Legal",
    "legal_case":             "Regulatory & Legal",
    "court_docket":           "Regulatory & Legal",
    "priv_legal":             "Regulatory & Legal",
    "priv_litigation_hold":   "Regulatory & Legal",
    "priv_privileged_info":   "Regulatory & Legal",
    "priv_priv_conf":         "Regulatory & Legal",
    "priv_protected":         "Regulatory & Legal",
    "priv_work_product":      "Regulatory & Legal",
    "reg_ctr":                "Regulatory & Legal",
    "reg_compliance_case":    "Regulatory & Legal",
    "reg_fincen":             "Regulatory & Legal",
    "reg_ofac":               "Regulatory & Legal",
    "reg_sar":                "Regulatory & Legal",
    "frl_invest_restricted":  "Regulatory & Legal",
    "frl_market_sensitive":   "Regulatory & Legal",
    "frl_pre_decisional":     "Regulatory & Legal",
    "sup_exam_findings":      "Regulatory & Legal",
    "sup_non_public":         "Regulatory & Legal",
    "sup_restricted_sup":     "Regulatory & Legal",
    "sup_supervisory_conf":   "Regulatory & Legal",
    "sup_supervisory_ctrl":   "Regulatory & Legal",
    "unknown":                "Other",
    # Banking — cheques & instruments
    "cashier_check":   "Banking",
    "check_number":    "Banking",
    "parcel_number":   "Banking",
    "insurance_claim": "Healthcare",
    # Document-classification families (corp_*, dc_*, frl_*).
    "corp_dnd":              "Classification",
    "corp_embargoed":        "Classification",
    "corp_eyes_only":        "Classification",
    "corp_highly_conf":      "Classification",
    "corp_internal_only":    "Classification",
    "corp_need_to_know":     "Classification",
    "corp_proprietary":      "Classification",
    "corp_restricted":       "Classification",
    "dc_classified_conf":    "Classification",
    "dc_cui":                "Classification",
    "dc_fouo":               "Classification",
    "dc_les":                "Classification",
    "dc_noforn":             "Classification",
    "dc_sbu":                "Classification",
    "frl_draft_not_circ":    "Regulatory & Legal",
    "frl_info_barrier":      "Regulatory & Legal",
    "frl_inside_info":       "Regulatory & Legal",
    # Secrets — specific providers & key shapes the heuristic misses.
    "db_connection_string":  "Secrets & Credentials",
    "github_oauth":          "Secrets & Credentials",
    "github_pat":            "Secrets & Credentials",
    "slack_webhook":         "Secrets & Credentials",
    "stripe_pk":             "Secrets & Credentials",
    "dc_secret":             "Secrets & Credentials",
    "aws_secret_key":        "Secrets & Credentials",
    "bearer_token":          "Secrets & Credentials",
    "google_api_key":        "Secrets & Credentials",
    # Crypto — additional chains.
    "litecoin":       "Crypto",
    "monero":         "Crypto",
    "ripple":         "Crypto",
    "bitcoin_bech32": "Crypto",
    "bitcoin_cash":   "Crypto",
    # PII — identifiers that aren't clearly regional.
    "geohash":        "PII",
    "idfa_idfv":      "PII",
    "imei":           "PII",
    "imeisv":         "PII",
    "ipv4_address":   "PII",
    "ipv6_address":   "PII",
    "mac_address":    "PII",
    "meid":           "PII",
    "twitter_handle": "PII",
    "vin":            "PII",
    "work_permit":    "PII",
}

# Regional two-letter prefixes. Order matters: longer prefixes win so
# ``uae_`` beats ``ua_``.
_CATALOG_PREFIX_MAP: tuple[tuple[str, str], ...] = (
    ("ca_",   "Canadian IDs"),
    ("us_",   "US IDs"),
    # Europe — EU/EEA + UK/CH
    ("uk_", "European IDs"),
    ("de_", "European IDs"), ("fr_", "European IDs"), ("es_", "European IDs"),
    ("it_", "European IDs"), ("nl_", "European IDs"), ("se_", "European IDs"),
    ("no_", "European IDs"), ("fi_", "European IDs"), ("pl_", "European IDs"),
    ("ch_", "European IDs"), ("at_", "European IDs"), ("be_", "European IDs"),
    ("bg_", "European IDs"), ("hr_", "European IDs"), ("cy_", "European IDs"),
    ("cz_", "European IDs"), ("dk_", "European IDs"), ("ee_", "European IDs"),
    ("eu_", "European IDs"), ("gr_", "European IDs"), ("hu_", "European IDs"),
    ("is_", "European IDs"), ("ie_", "European IDs"), ("lv_", "European IDs"),
    ("li_", "European IDs"), ("lt_", "European IDs"), ("lu_", "European IDs"),
    ("mt_", "European IDs"), ("pt_", "European IDs"), ("ro_", "European IDs"),
    ("sk_", "European IDs"), ("si_", "European IDs"), ("rs_", "European IDs"),
    ("ua_", "European IDs"), ("md_", "European IDs"), ("xk_", "European IDs"),
    ("al_", "European IDs"), ("ba_", "European IDs"), ("mk_", "European IDs"),
    # Asia-Pacific
    ("au_", "Asia-Pacific IDs"), ("nz_", "Asia-Pacific IDs"),
    ("sg_", "Asia-Pacific IDs"), ("hk_", "Asia-Pacific IDs"),
    ("jp_", "Asia-Pacific IDs"), ("in_", "Asia-Pacific IDs"),
    ("kr_", "Asia-Pacific IDs"), ("cn_", "Asia-Pacific IDs"),
    ("tw_", "Asia-Pacific IDs"), ("th_", "Asia-Pacific IDs"),
    ("vn_", "Asia-Pacific IDs"), ("id_", "Asia-Pacific IDs"),
    ("ph_", "Asia-Pacific IDs"), ("my_", "Asia-Pacific IDs"),
    ("pk_", "Asia-Pacific IDs"), ("lk_", "Asia-Pacific IDs"),
    ("bd_", "Asia-Pacific IDs"), ("mo_", "Asia-Pacific IDs"),
    ("kh_", "Asia-Pacific IDs"), ("la_", "Asia-Pacific IDs"),
    ("mm_", "Asia-Pacific IDs"), ("mn_", "Asia-Pacific IDs"),
    ("np_", "Asia-Pacific IDs"), ("bt_", "Asia-Pacific IDs"),
    ("bn_", "Asia-Pacific IDs"), ("af_", "Asia-Pacific IDs"),
    ("fj_", "Asia-Pacific IDs"), ("pg_", "Asia-Pacific IDs"),
    ("ws_", "Asia-Pacific IDs"), ("to_", "Asia-Pacific IDs"),
    ("vu_", "Asia-Pacific IDs"), ("tv_", "Asia-Pacific IDs"),
    ("sb_", "Asia-Pacific IDs"), ("nr_", "Asia-Pacific IDs"),
    ("ki_", "Asia-Pacific IDs"), ("fm_", "Asia-Pacific IDs"),
    ("mh_", "Asia-Pacific IDs"), ("pw_", "Asia-Pacific IDs"),
    # Latin America
    ("br_", "Latin America IDs"), ("mx_", "Latin America IDs"),
    ("ar_", "Latin America IDs"), ("cl_", "Latin America IDs"),
    ("co_", "Latin America IDs"), ("pe_", "Latin America IDs"),
    ("uy_", "Latin America IDs"), ("ve_", "Latin America IDs"),
    ("bo_", "Latin America IDs"), ("py_", "Latin America IDs"),
    ("ec_", "Latin America IDs"), ("gy_", "Latin America IDs"),
    ("sr_", "Latin America IDs"), ("cr_", "Latin America IDs"),
    ("cu_", "Latin America IDs"), ("do_", "Latin America IDs"),
    ("ht_", "Latin America IDs"), ("jm_", "Latin America IDs"),
    ("bb_", "Latin America IDs"), ("bs_", "Latin America IDs"),
    ("bz_", "Latin America IDs"), ("gd_", "Latin America IDs"),
    ("kn_", "Latin America IDs"), ("lc_", "Latin America IDs"),
    ("vc_", "Latin America IDs"), ("tt_", "Latin America IDs"),
    ("ag_", "Latin America IDs"), ("dm_", "Latin America IDs"),
    # Middle East & Africa (longer prefixes first so uae_ beats ua_,
    # which lives under Europe).
    ("uae_", "Middle East & Africa IDs"),
    ("sa_",  "Middle East & Africa IDs"), ("za_", "Middle East & Africa IDs"),
    ("il_",  "Middle East & Africa IDs"), ("tr_", "Middle East & Africa IDs"),
    ("eg_",  "Middle East & Africa IDs"), ("qa_", "Middle East & Africa IDs"),
    ("kw_",  "Middle East & Africa IDs"), ("bh_", "Middle East & Africa IDs"),
    ("om_",  "Middle East & Africa IDs"), ("ir_", "Middle East & Africa IDs"),
    ("iq_",  "Middle East & Africa IDs"), ("jo_", "Middle East & Africa IDs"),
    ("lb_",  "Middle East & Africa IDs"), ("sy_", "Middle East & Africa IDs"),
    ("ye_",  "Middle East & Africa IDs"), ("ps_", "Middle East & Africa IDs"),
    ("ae_",  "Middle East & Africa IDs"),
    # Africa — broader set
    ("ng_", "Middle East & Africa IDs"), ("ke_", "Middle East & Africa IDs"),
    ("ma_", "Middle East & Africa IDs"), ("dz_", "Middle East & Africa IDs"),
    ("tn_", "Middle East & Africa IDs"), ("et_", "Middle East & Africa IDs"),
    ("gh_", "Middle East & Africa IDs"), ("tz_", "Middle East & Africa IDs"),
    ("ug_", "Middle East & Africa IDs"), ("rw_", "Middle East & Africa IDs"),
    ("ao_", "Middle East & Africa IDs"), ("bj_", "Middle East & Africa IDs"),
    ("bw_", "Middle East & Africa IDs"), ("bf_", "Middle East & Africa IDs"),
    ("bi_", "Middle East & Africa IDs"), ("cm_", "Middle East & Africa IDs"),
    ("cv_", "Middle East & Africa IDs"), ("cf_", "Middle East & Africa IDs"),
    ("td_", "Middle East & Africa IDs"), ("km_", "Middle East & Africa IDs"),
    ("cd_", "Middle East & Africa IDs"), ("cg_", "Middle East & Africa IDs"),
    ("ci_", "Middle East & Africa IDs"), ("dj_", "Middle East & Africa IDs"),
    ("er_", "Middle East & Africa IDs"), ("ga_", "Middle East & Africa IDs"),
    ("gm_", "Middle East & Africa IDs"), ("gn_", "Middle East & Africa IDs"),
    ("gw_", "Middle East & Africa IDs"), ("gq_", "Middle East & Africa IDs"),
    ("sz_", "Middle East & Africa IDs"), ("ls_", "Middle East & Africa IDs"),
    ("lr_", "Middle East & Africa IDs"), ("ly_", "Middle East & Africa IDs"),
    ("mg_", "Middle East & Africa IDs"), ("mw_", "Middle East & Africa IDs"),
    ("ml_", "Middle East & Africa IDs"), ("mr_", "Middle East & Africa IDs"),
    ("mu_", "Middle East & Africa IDs"), ("mz_", "Middle East & Africa IDs"),
    ("na_", "Middle East & Africa IDs"), ("ne_", "Middle East & Africa IDs"),
    ("re_", "Middle East & Africa IDs"), ("sh_", "Middle East & Africa IDs"),
    ("sc_", "Middle East & Africa IDs"), ("sn_", "Middle East & Africa IDs"),
    ("sl_", "Middle East & Africa IDs"), ("so_", "Middle East & Africa IDs"),
    ("ss_", "Middle East & Africa IDs"), ("sd_", "Middle East & Africa IDs"),
    ("tg_", "Middle East & Africa IDs"), ("zm_", "Middle East & Africa IDs"),
    ("zw_", "Middle East & Africa IDs"),
    # Caucasus & Central Asia
    ("am_", "Asia-Pacific IDs"), ("az_", "Asia-Pacific IDs"),
    ("ge_", "Asia-Pacific IDs"), ("kz_", "Asia-Pacific IDs"),
    ("kg_", "Asia-Pacific IDs"), ("tj_", "Asia-Pacific IDs"),
    ("tm_", "Asia-Pacific IDs"), ("uz_", "Asia-Pacific IDs"),
    # Russia / Belarus — geography leans Europe here for banking purposes.
    ("ru_", "European IDs"), ("by_", "European IDs"),
)


def classify_category(value: str) -> str:
    """Return the catalog group a raw evadex category id belongs to.

    Lookup order: explicit override → regional prefix → healthcare /
    secret keyword scan → "Other".
    """
    if value in _CATALOG_EXPLICIT:
        return _CATALOG_EXPLICIT[value]
    # Longest-prefix-first so e.g. "uae_" beats "ua_".
    for prefix, group in sorted(
        _CATALOG_PREFIX_MAP, key=lambda p: -len(p[0])
    ):
        if value.startswith(prefix):
            # Healthcare overrides for regional health-card ids — the
            # UI wants clinical payloads grouped together regardless
            # of geography.
            if ("_health" in value or "_carecard" in value
                or "_ramq" in value or "medicare" in value
                or "_nhs" in value or "_npi" in value
                or "_mbi" in value):
                return "Healthcare"
            return group
    # Last-resort keyword scan for categories with no regional prefix.
    if any(t in value for t in ("_key", "_token", "_secret", "api_key")):
        return "Secrets & Credentials"
    if any(t in value for t in ("health", "medicare", "nhs", "clinical", "drug")):
        return "Healthcare"
    if any(t in value for t in ("crypto", "bitcoin", "ethereum", "wallet")):
        return "Crypto"
    if any(t in value for t in ("classif", "confidential", "top_secret")):
        return "Classification"
    return "Other"


def group_all_categories() -> dict:
    """Catalog of every registered evadex payload category.

    Imports :class:`evadex.core.result.PayloadCategory` lazily so the
    bridge module stays importable in contexts where the core enum
    hasn't been initialised yet (tests, reduced deploys). Returns a
    shape the ``GET /v1/evadex/categories`` endpoint hands to the UI::

        {
          "groups": { "Credit Cards": [...], "Canadian IDs": [...], ... },
          "total":  489,
          "group_order": ["Credit Cards", "Banking", ...],
        }
    """
    from evadex.core.result import PayloadCategory  # lazy — see docstring

    buckets: dict[str, list[str]] = {}
    for member in PayloadCategory:
        raw = member.value
        if raw in ("unknown",):
            # Skip sentinels — they'd never be selected on purpose.
            continue
        group = classify_category(raw)
        buckets.setdefault(group, []).append(raw)

    # Deterministic display order: groups first by CATALOG_GROUP_ORDER,
    # then any unknown groups alphabetically; ids inside each group
    # alphabetical for stable UI.
    ordered_groups: dict[str, list[str]] = {}
    seen = set()
    for g in CATALOG_GROUP_ORDER:
        if g in buckets:
            ordered_groups[g] = sorted(buckets[g])
            seen.add(g)
    for g in sorted(buckets):
        if g not in seen:
            ordered_groups[g] = sorted(buckets[g])

    total = sum(len(v) for v in ordered_groups.values())
    return {
        "groups":      ordered_groups,
        "total":       total,
        "group_order": list(ordered_groups.keys()),
    }
