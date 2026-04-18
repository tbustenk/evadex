"""Plain-text writer for evadex generate."""
from __future__ import annotations

import datetime
from collections import defaultdict
from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory


_SECTION_TITLES: dict[PayloadCategory, str] = {
    PayloadCategory.CREDIT_CARD: "Credit Card Numbers",
    PayloadCategory.SSN:         "Social Security Numbers",
    PayloadCategory.SIN:         "Canadian Social Insurance Numbers",
    PayloadCategory.IBAN:        "International Bank Account Numbers (IBAN)",
    PayloadCategory.SWIFT_BIC:   "SWIFT / BIC Codes",
    PayloadCategory.ABA_ROUTING: "ABA Routing Numbers",
    PayloadCategory.BITCOIN:     "Bitcoin Addresses",
    PayloadCategory.ETHEREUM:    "Ethereum Addresses",
    PayloadCategory.US_PASSPORT: "US Passport Numbers",
    PayloadCategory.AU_TFN:      "Australian Tax File Numbers",
    PayloadCategory.DE_TAX_ID:   "German Tax Identification Numbers",
    PayloadCategory.FR_INSEE:    "French INSEE / NIR Numbers",
    PayloadCategory.AWS_KEY:     "AWS Access Keys",
    PayloadCategory.GITHUB_TOKEN:"GitHub Tokens",
    PayloadCategory.STRIPE_KEY:  "Stripe API Keys",
    PayloadCategory.SLACK_TOKEN: "Slack Tokens",
    PayloadCategory.JWT:         "JSON Web Tokens",
    PayloadCategory.CLASSIFICATION: "Classification Labels",
    PayloadCategory.EMAIL:       "Email Addresses",
    PayloadCategory.PHONE:       "Phone Numbers",
}


def write_txt(entries: list[GeneratedEntry], path: str) -> None:
    from evadex.generate.writers import (
        _active_template, _active_noise_level, _active_density, _active_seed,
    )

    # If a non-generic template is active, use the template system
    if _active_template != "generic":
        from evadex.generate.templates import apply_template
        lines = apply_template(
            _active_template, entries,
            seed=_active_seed,
            noise_level=_active_noise_level,
            density=_active_density,
        )
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return

    # Default generic format
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    today = datetime.date.today().isoformat()
    lines: list[str] = [
        "DLP TEST DOCUMENT",
        "=" * 60,
        f"Generated: {today}",
        "CONFIDENTIAL — For DLP Scanner Testing Only",
        "",
        f"Total entries: {len(entries)}",
        f"Categories:    {len(by_cat)}",
        "",
    ]

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        title = _SECTION_TITLES.get(cat, cat.value.replace("_", " ").title())
        lines += [
            f"{'─' * 60}",
            f"  {title}  ({len(cat_entries)} entries)",
            f"{'─' * 60}",
            "",
        ]
        for i, e in enumerate(cat_entries, 1):
            lines.append(f"  {i:>4}. {e.embedded_text}")
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
