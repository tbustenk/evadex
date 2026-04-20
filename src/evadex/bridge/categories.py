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
