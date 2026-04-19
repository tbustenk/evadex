"""Document templates for evadex generate — control structure and tone of output."""
from __future__ import annotations

import datetime
import random
from collections import defaultdict
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry


# ── Noise / filler text ──────────────────────────────────────────────────────

_BUSINESS_FILLER = [
    "As per our internal compliance procedures, all data must be handled in accordance with applicable privacy legislation.",
    "The following records have been extracted from the production database for review purposes only.",
    "This report is generated as part of our ongoing data quality assurance initiative.",
    "All information contained herein is subject to our data retention policy (DRP-2024-Rev3).",
    "Access to this document is restricted to authorized personnel with appropriate security clearance.",
    "Please ensure all sensitive data is redacted before distribution to external parties.",
    "The compliance team has reviewed and approved the release of this data for internal testing.",
    "This information is classified as INTERNAL USE ONLY and must not be shared outside the organization.",
    "Records marked with an asterisk (*) require additional verification before processing.",
    "The data controller has been notified of this extraction per GDPR Article 30 requirements.",
    "Quarterly reconciliation is required for all accounts listed in Section B below.",
    "The risk assessment for this data set was completed on {date} with an overall rating of LOW.",
    "Business continuity planning requires maintaining offline copies of critical customer records.",
    "The audit trail for all modifications to these records is maintained in the central logging system.",
    "Retention period for the records in this document: 7 years from date of last transaction.",
]


def _noise_lines(rng: random.Random, noise_level: str, count: int) -> list[str]:
    """Return filler text lines appropriate for the noise level."""
    today = datetime.date.today().isoformat()
    if noise_level == "low":
        n = max(1, count // 10)
    elif noise_level == "high":
        n = max(3, count // 2)
    else:  # medium
        n = max(2, count // 5)
    chosen = rng.choices(_BUSINESS_FILLER, k=n)
    return [line.format(date=today) for line in chosen]


# ── Template formatters ──────────────────────────────────────────────────────
# Each returns a list of text lines ready for writing.

def format_generic(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Default mixed prose and table format (existing behaviour)."""
    lines: list[str] = []
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(noise)
        lines.append("")

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        title = cat.value.replace("_", " ").title()
        lines.append(f"=== {title} ===")
        lines.append("")
        for i, e in enumerate(cat_entries, 1):
            lines.append(f"  {i}. {e.embedded_text}")
        lines.append("")
    return lines


def format_invoice(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Payment invoice layout with line items and totals."""
    today = datetime.date.today()
    inv_no = f"INV-{rng.randint(100000, 999999)}"
    lines = [
        "=" * 60,
        "                      INVOICE",
        "=" * 60,
        f"  Invoice #:     {inv_no}",
        f"  Date:          {today.isoformat()}",
        f"  Due Date:      {(today + datetime.timedelta(days=30)).isoformat()}",
        "  Payment Terms: Net 30",
        "",
        "  Bill To:                        Ship To:",
        "  Acme Financial Corp.            Global Processing Inc.",
        "  123 Bay Street, Suite 400       456 King Street West",
        "  Toronto, ON M5J 2T3            Toronto, ON M5V 1K4",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    lines.append("  " + "-" * 56)
    lines.append(f"  {'#':>4}  {'Description':<30} {'Amount':>10}  {'Ref':>10}")
    lines.append("  " + "-" * 56)

    running_total = 0.0
    for i, e in enumerate(entries, 1):
        amount = rng.uniform(50, 5000)
        running_total += amount
        desc = e.embedded_text[:30] if len(e.embedded_text) > 30 else e.embedded_text
        lines.append(f"  {i:>4}  {desc:<30} {amount:>10.2f}  {e.variant_value[:10]:>10}")

    lines.append("  " + "-" * 56)
    lines.append(f"  {'':>4}  {'SUBTOTAL':<30} {running_total:>10.2f}")
    lines.append(f"  {'':>4}  {'TAX (13% HST)':<30} {running_total * 0.13:>10.2f}")
    lines.append(f"  {'':>4}  {'TOTAL':<30} {running_total * 1.13:>10.2f}")
    lines.append("  " + "-" * 56)
    lines.append("")
    lines.append("  Payment Methods: Wire transfer, cheque, or credit card.")
    lines.append("")
    return lines


def format_statement(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Bank statement format with transaction history."""
    today = datetime.date.today()
    acct = f"****{rng.randint(1000, 9999)}"
    lines = [
        "=" * 70,
        "                    ACCOUNT STATEMENT",
        "=" * 70,
        f"  Account:       {acct}",
        f"  Statement:     {today.strftime('%B %Y')}",
        f"  Opening Bal:   ${rng.uniform(1000, 50000):,.2f}",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    lines.append(f"  {'Date':<12} {'Description':<35} {'Debit':>10} {'Credit':>10} {'Ref'}")
    lines.append("  " + "-" * 78)

    balance = rng.uniform(1000, 50000)
    for i, e in enumerate(entries):
        dt = today - datetime.timedelta(days=len(entries) - i)
        is_debit = rng.random() < 0.6
        amount = rng.uniform(10, 3000)
        desc = e.embedded_text[:35] if len(e.embedded_text) > 35 else e.embedded_text
        if is_debit:
            balance -= amount
            lines.append(f"  {dt.isoformat():<12} {desc:<35} {amount:>10.2f} {'':>10} {e.variant_value[:12]}")
        else:
            balance += amount
            lines.append(f"  {dt.isoformat():<12} {desc:<35} {'':>10} {amount:>10.2f} {e.variant_value[:12]}")

    lines.append("  " + "-" * 78)
    lines.append(f"  Closing Balance: ${balance:,.2f}")
    lines.append("")
    return lines


def format_hr_record(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """HR employee record with personal information fields."""
    first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Michael", "Jennifer"]
    last_names = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown", "Lee", "Taylor"]
    depts = ["Finance", "Compliance", "HR", "IT", "Operations", "Legal", "Risk", "Treasury"]

    lines = [
        "=" * 60,
        "          HUMAN RESOURCES — EMPLOYEE RECORDS",
        "=" * 60,
        f"  Generated: {datetime.date.today().isoformat()}",
        "  Classification: CONFIDENTIAL — HR USE ONLY",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    emp_id = rng.randint(10000, 99999)
    for i, e in enumerate(entries):
        if i % 5 == 0:
            emp_id += 1
            first = rng.choice(first_names)
            last = rng.choice(last_names)
            dept = rng.choice(depts)
            lines.append("-" * 60)
            lines.append(f"  Employee ID:    EMP-{emp_id}")
            lines.append(f"  Name:           {first} {last}")
            lines.append(f"  Department:     {dept}")
            lines.append(f"  Start Date:     {(datetime.date.today() - datetime.timedelta(days=rng.randint(30, 3650))).isoformat()}")
            lines.append("  Status:         Active")

        field = e.category.value.replace("_", " ").title()
        lines.append(f"  {field + ':':<18}{e.embedded_text}")

    lines.append("-" * 60)
    lines.append("")
    return lines


def format_audit_report(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Internal audit report with findings and recommendations."""
    today = datetime.date.today()
    audit_no = f"AUD-{today.year}-{rng.randint(100, 999)}"
    lines = [
        "=" * 70,
        "            INTERNAL AUDIT REPORT",
        "=" * 70,
        f"  Audit Reference:   {audit_no}",
        f"  Report Date:       {today.isoformat()}",
        "  Auditor:           Compliance & Risk Management Division",
        "  Scope:             PCI-DSS Data Handling Compliance Review",
        "  Classification:    CONFIDENTIAL",
        "",
        "  1. EXECUTIVE SUMMARY",
        "  " + "-" * 50,
        "  This audit examined data handling practices for sensitive",
        "  financial and personal information across production systems.",
        "  The following findings document instances of sensitive data",
        "  discovered during the review period.",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    lines.append("  2. DETAILED FINDINGS")
    lines.append("  " + "-" * 50)

    severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_weights = [0.1, 0.3, 0.4, 0.2]

    for i, e in enumerate(entries, 1):
        sev = rng.choices(severity, weights=severity_weights, k=1)[0]
        lines.append(f"  Finding {i:>3}: [{sev}]")
        lines.append(f"    Category:    {e.category.value}")
        lines.append(f"    Evidence:    {e.embedded_text}")
        if e.technique:
            lines.append(f"    Evasion:     {e.technique} ({e.generator_name})")
        lines.append(f"    Action:      Remediate within {'24h' if sev == 'CRITICAL' else '72h' if sev == 'HIGH' else '2 weeks'}")
        lines.append("")

    lines.append("  3. RECOMMENDATIONS")
    lines.append("  " + "-" * 50)
    lines.append("  - Implement automated DLP scanning for all outbound channels")
    lines.append("  - Review evasion technique coverage in current scanner configuration")
    lines.append("  - Schedule follow-up audit within 90 days")
    lines.append("")
    return lines


def format_source_code(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Realistic source code with hardcoded sensitive values."""
    lines = [
        "#!/usr/bin/env python3",
        '"""Application configuration and database setup — DO NOT COMMIT."""',
        "",
        "import os",
        "import logging",
        "",
        "logger = logging.getLogger(__name__)",
        "",
        "# --- Database Configuration ---",
        'DB_HOST = "db.internal.acmecorp.com"',
        'DB_PORT = 5432',
        'DB_NAME = "customer_prod"',
        'DB_PASSWORD = "secretpassword123"  # TODO: move to vault',
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"',
        "",
    ]

    if noise_level != "low":
        lines += [
            "",
            "# Application settings",
            "MAX_RETRIES = 3",
            "TIMEOUT_SECONDS = 30",
            'LOG_LEVEL = "INFO"',
            "",
        ]

    langs = ["python", "javascript", "generic"]
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        var_base = cat.value.upper()
        lang = rng.choice(langs)

        lines.append(f"# --- {cat.value.replace('_', ' ').title()} Data ---")

        if lang == "python":
            for i, e in enumerate(cat_entries):
                var_name = f"{var_base}_{i}" if i > 0 else var_base
                comment = f"  # evasion: {e.technique}" if e.technique else ""
                if rng.random() < 0.3:
                    lines.append(f'{var_name} = "{e.variant_value}"{comment}  # TODO: remove before commit')
                elif rng.random() < 0.5:
                    lines.append(f'os.environ["{var_name}"] = "{e.variant_value}"{comment}')
                else:
                    lines.append(f'{var_name} = "{e.variant_value}"{comment}')

                if noise_level == "high" and rng.random() < 0.4:
                    lines.append(f'logger.debug(f"Loaded {var_name}={{len({var_name})}} chars")')

        elif lang == "javascript":
            lines.append("")
            for i, e in enumerate(cat_entries):
                var_name = cat.value.lower() + (f"_{i}" if i > 0 else "")
                comment = f"  // evasion: {e.technique}" if e.technique else ""
                if rng.random() < 0.3:
                    lines.append(f'const {var_name} = "{e.variant_value}";{comment}  // FIXME: hardcoded')
                elif rng.random() < 0.5:
                    lines.append(f'process.env.{var_name.upper()} = "{e.variant_value}";{comment}')
                else:
                    lines.append(f'let {var_name} = "{e.variant_value}";{comment}')

        else:  # generic
            for i, e in enumerate(cat_entries):
                lines.append(f'# {cat.value}[{i}] = {e.variant_value}')

        lines.append("")

    lines += [
        "",
        "# --- End of configuration ---",
        'if __name__ == "__main__":',
        '    print("Config loaded successfully")',
        "",
    ]
    return lines


def format_config_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Application config files (INI/YAML/ENV) with sensitive values."""
    formats = ["env", "ini", "yaml"]
    fmt = rng.choice(formats)

    lines: list[str] = []

    if fmt == "env":
        lines += [
            "# Application Configuration — CONFIDENTIAL",
            f"# Generated: {datetime.date.today().isoformat()}",
            "",
            "# Database",
            "DB_HOST=localhost",
            "DB_PORT=5432",
            "DB_NAME=customer_prod",
            'DB_PASSWORD=secret123',
            "",
            "# API Keys",
            "STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT7en6bh8Xy9mPqZ",
            "",
        ]
        for e in entries:
            key = e.category.value.upper()
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"{key}={e.variant_value}{comment}")
            if noise_level == "high":
                lines.append(f"# Verified: {datetime.date.today().isoformat()}")

    elif fmt == "ini":
        lines += [
            "; Application Configuration — CONFIDENTIAL",
            f"; Generated: {datetime.date.today().isoformat()}",
            "",
            "[database]",
            "host = localhost",
            "port = 5432",
            "name = customer_prod",
            "password = secret123",
            "",
            "[credentials]",
        ]
        for e in entries:
            key = e.category.value.lower()
            lines.append(f"{key} = {e.variant_value}")

    else:  # yaml
        lines += [
            "# Application Configuration — CONFIDENTIAL",
            f"# Generated: {datetime.date.today().isoformat()}",
            "",
            "database:",
            "  host: localhost",
            "  port: 5432",
            "  name: customer_prod",
            "  password: secret123",
            "",
            "credentials:",
        ]
        for e in entries:
            key = e.category.value.lower()
            lines.append(f"  {key}: \"{e.variant_value}\"")

    lines.append("")
    return lines


def format_chat_log(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Messaging/chat export with sensitive values shared between participants."""
    names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Michael", "Jennifer", "Alex", "Wei"]
    participants = rng.sample(names, min(4, len(names)))

    base_dt = datetime.datetime(2026, 4, 17, 9, 0, 0)

    lines = [
        f"Chat Export — {datetime.date.today().isoformat()}",
        "Channel: #compliance-sensitive-data",
        f"Participants: {', '.join(participants)}",
        "=" * 50,
        "",
    ]

    filler_msgs = [
        "let me check on that",
        "one sec",
        "ok here's what I found",
        "can you verify this?",
        "sending it now",
        "thanks, got it",
        "I'll update the ticket",
        "sure, see below",
        "hold on, pulling it up",
        "confirmed",
    ]

    for i, e in enumerate(entries):
        ts = base_dt + datetime.timedelta(minutes=i * rng.randint(1, 5))
        ts_str = ts.strftime("%H:%M")
        sender = rng.choice(participants)

        # Occasionally add filler messages for noise
        if noise_level != "low" and rng.random() < (0.5 if noise_level == "high" else 0.25):
            filler_ts = ts - datetime.timedelta(seconds=rng.randint(10, 50))
            filler_sender = rng.choice([p for p in participants if p != sender] or participants)
            lines.append(f"[{filler_ts.strftime('%H:%M')}] {filler_sender}: {rng.choice(filler_msgs)}")

        cat_label = e.category.value.replace("_", " ")
        prompts = [
            f"here's the {cat_label}: {e.variant_value}",
            f"the {cat_label} is {e.variant_value}",
            f"{e.embedded_text}",
            f"found it — {e.variant_value}",
            f"can you process this? {e.variant_value}",
        ]
        lines.append(f"[{ts_str}] {sender}: {rng.choice(prompts)}")

    lines.append("")
    lines.append("--- End of chat export ---")
    lines.append("")
    return lines


def format_medical_record(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Clinical notes and patient records with health identifiers."""
    first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily"]
    last_names = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown"]
    conditions = [
        "Type 2 Diabetes Mellitus",
        "Essential Hypertension",
        "Major Depressive Disorder",
        "Chronic Lower Back Pain",
        "Generalized Anxiety Disorder",
        "Hyperlipidemia",
        "Osteoarthritis, bilateral knees",
        "Atrial Fibrillation",
    ]
    medications = [
        "Metformin 500mg BID", "Lisinopril 10mg daily", "Sertraline 50mg daily",
        "Naproxen 500mg PRN", "Atorvastatin 20mg HS", "Metoprolol 25mg BID",
        "Gabapentin 300mg TID", "Acetaminophen 500mg PRN",
    ]

    today = datetime.date.today()
    lines = [
        "=" * 70,
        "              CLINICAL RECORD — CONFIDENTIAL",
        "=" * 70,
        "  Facility:     Regional Medical Centre",
        f"  Report Date:  {today.isoformat()}",
        "  ** PROTECTED HEALTH INFORMATION — HIPAA / PHIPA **",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    patient_id = rng.randint(100000, 999999)
    for i, e in enumerate(entries):
        if i % 4 == 0:
            patient_id += 1
            first = rng.choice(first_names)
            last = rng.choice(last_names)
            dob = f"{rng.randint(1940, 2005)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
            condition = rng.choice(conditions)
            med = rng.choice(medications)
            lines.append("-" * 70)
            lines.append(f"  Patient:      {first} {last}")
            lines.append(f"  MRN:          MRN-{patient_id}")
            lines.append(f"  DOB:          {dob}")
            lines.append(f"  Dx:           {condition}")
            lines.append(f"  Medications:  {med}")

        field = e.category.value.replace("_", " ").title()
        lines.append(f"  {field + ':':<20} {e.embedded_text}")

    lines.append("-" * 70)
    lines.append("  ** END OF RECORD **")
    lines.append("")
    return lines


# ── Public API ───────────────────────────────────────────────────────────────

def format_env_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """``.env``-style file where every entry becomes a KEY=VALUE line.

    Targets Siphon's ``EntropyMode::Assignment`` detection: the assignment
    regex matches ``KEY=`` before each value so every high-entropy payload
    is in assignment context.
    """
    lines = [
        "# Environment configuration for evadex test corpus",
        "# Generated for DLP scanner entropy-mode evaluation",
        "",
        "NODE_ENV=production",
        "LOG_LEVEL=info",
        "PORT=8080",
        "",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        for i, e in enumerate(by_cat[cat]):
            var_name = cat.value.upper() + (f"_{i}" if i > 0 else "")
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"{var_name}={e.variant_value}{comment}")

    if noise_level != "low":
        lines += [
            "",
            "# Feature flags",
            "FEATURE_FLAG_BETA=true",
            "FEATURE_FLAG_CACHING=true",
            "MAX_CONNECTIONS=100",
            "",
        ]

    return lines


def format_secrets_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """YAML-style secrets file mixing a keyword header with high-entropy values.

    Targets Siphon's ``EntropyMode::Gated`` mode: every value sits under a
    keyword like ``api_key:`` or ``secret:`` so the 80-char gating window
    catches it.
    """
    keywords = [
        "api_key", "secret_key", "access_token", "private_key",
        "password", "bearer_token", "signing_key", "encryption_key",
    ]

    lines = [
        "# Secrets manifest — for scanner evaluation only",
        "version: 1",
        "secrets:",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        for i, e in enumerate(by_cat[cat]):
            kw = rng.choice(keywords)
            name = f"{cat.value}_{i}" if i > 0 else cat.value
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"  - name: {name}")
            lines.append(f"    {kw}: {e.variant_value}{comment}")
            lines.append("    environment: production")

    return lines


def format_code_with_secrets(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Source code with high-entropy values hardcoded bare — no keyword, no assignment.

    Values are emitted as positional arguments to function calls so that
    only ``EntropyMode::All`` (flag everything high-entropy) catches them.
    Complements ``source_code`` which puts them in assignment context.
    """
    lines = [
        "#!/usr/bin/env python3",
        '"""Entropy-focused bare-value placement — exercises EntropyMode::All."""',
        "",
        "import hashlib",
        "",
        "def _verify(token, nonce, signature):",
        "    return hashlib.sha256(token.encode()).hexdigest() == signature",
        "",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        lines.append(f"# {cat.value.replace('_', ' ').title()}")
        for e in cat_entries:
            # Bare value — no assignment, no keyword nearby. Function call
            # hides the value as a positional literal so only EntropyMode::All
            # (or a keyword Siphon happens to treat as context) catches it.
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f'_verify("{e.variant_value}", "nonce_abc", "sig_xyz"){comment}')
        lines.append("")

    return lines


def format_lsh_variants(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Render a document containing N near-duplicate sections of a base
    text — one section per entry. Each section restates the same base
    paragraph with a different distortion rate, reporting the empirical
    Jaccard similarity to the base in the section header.

    Use this template to produce fixtures for testing a DLP scanner's
    LSH document-similarity engine. The single output file contains
    multiple variants stitched together; split on the
    ``--- VARIANT N ---`` separator to get individual documents to
    feed into ``siphon lsh query``.
    """
    from evadex.lsh import BASE_DOCUMENTS, distorted_variant, jaccard_similarity

    base_id = "loan_decision"
    base = BASE_DOCUMENTS[base_id]

    n = max(1, len(entries))
    if n == 1:
        rates = [0.0]
    else:
        # Smoothly span from no distortion to heavy distortion.
        rates = [round(i / (n - 1) * 0.5, 4) for i in range(n)]

    lines: list[str] = [
        "=" * 70,
        f"  LSH NEAR-DUPLICATE VARIANTS — base document: {base_id}",
        f"  {n} variants spanning distortion rates 0%–{int(rates[-1] * 100)}%",
        "=" * 70,
        "",
    ]

    for idx, (rate, entry) in enumerate(zip(rates, entries)):
        variant = distorted_variant(base, rate, rng) if rate > 0 else base
        # Splice the entry's sensitive value into the variant so each
        # near-duplicate carries a distinct PII payload — exactly the
        # property an LSH scan should preserve across variants.
        variant = f"{variant} Reference identifier: {entry.variant_value}."
        empirical = jaccard_similarity(base, variant)
        lines.append(f"--- VARIANT {idx} ---")
        lines.append(f"Distortion rate: {rate:.0%}  "
                     f"Empirical Jaccard vs base: {empirical:.0%}  "
                     f"Embedded category: {entry.category.value}")
        lines.append("")
        lines.append(variant)
        lines.append("")

    return lines


_FORMATTERS = {
    "generic": format_generic,
    "invoice": format_invoice,
    "statement": format_statement,
    "hr_record": format_hr_record,
    "audit_report": format_audit_report,
    "source_code": format_source_code,
    "config_file": format_config_file,
    "chat_log": format_chat_log,
    "medical_record": format_medical_record,
    "env_file": format_env_file,
    "secrets_file": format_secrets_file,
    "code_with_secrets": format_code_with_secrets,
    "lsh_variants": format_lsh_variants,
}


def apply_template(
    template: str,
    entries: list[GeneratedEntry],
    seed: Optional[int] = None,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Apply a named template to entries, returning formatted text lines."""
    formatter = _FORMATTERS.get(template, format_generic)
    rng = random.Random(seed)
    return formatter(entries, rng, noise_level=noise_level, density=density)
