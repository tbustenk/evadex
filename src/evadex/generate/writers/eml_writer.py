"""EML (email) writer for evadex generate."""
from __future__ import annotations

import datetime
import random
from collections import defaultdict
from email.message import EmailMessage

from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory

_NAMES = [
    ("John Smith", "john.smith@acmebank.com"),
    ("Sarah Chen", "sarah.chen@globalfinance.ca"),
    ("David Wilson", "david.wilson@rbc.example.com"),
    ("Maria Garcia", "maria.garcia@compliance-corp.com"),
    ("Robert Johnson", "robert.johnson@paymentservices.net"),
    ("Emily Brown", "emily.brown@treasuryops.ca"),
    ("Michael Lee", "michael.lee@auditgroup.com"),
    ("Jennifer Taylor", "jennifer.taylor@hrservices.ca"),
    ("James Anderson", "james.anderson@investco.com"),
    ("Lisa Martinez", "lisa.martinez@securepay.net"),
]

_SUBJECTS = [
    "Re: Customer Account Update — Action Required",
    "FW: Q4 Compliance Audit — Sensitive Data Report",
    "Payment Processing Summary — {date}",
    "Employee Records Update — Confidential",
    "Transaction Verification Request — Urgent",
    "Monthly Statement Reconciliation — {date}",
    "KYC Documentation — Customer File",
    "Internal Audit Findings — Draft",
    "Payroll Data Submission — {date}",
    "Account Migration — Data Transfer",
]


def write_eml(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    today = datetime.date.today()

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    sender = rng.choice(_NAMES)
    recipient = rng.choice([n for n in _NAMES if n != sender])

    subject = rng.choice(_SUBJECTS).format(date=today.isoformat())

    # Build body
    body_lines: list[str] = [
        f"Hi {recipient[0].split()[0]},",
        "",
        "Please find the requested data below. This information is confidential",
        "and should be handled according to our data protection policy.",
        "",
    ]

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        title = cat.value.replace("_", " ").title()
        body_lines.append(f"--- {title} ---")
        body_lines.append("")
        for i, e in enumerate(cat_entries, 1):
            body_lines.append(f"  {i}. {e.embedded_text}")
        body_lines.append("")

    body_lines += [
        "Please confirm receipt and let me know if you need any additional details.",
        f"Please find attached the statement for card {entries[0].plain_value}" if entries else "",
        "",
        "Best regards,",
        sender[0],
        f"{sender[0].split()[0]}'s Office | Compliance & Risk Management",
        f"Tel: +1 (416) 555-{rng.randint(1000, 9999)}",
    ]

    msg = EmailMessage()
    msg["From"] = f"{sender[0]} <{sender[1]}>"
    msg["To"] = f"{recipient[0]} <{recipient[1]}>"
    msg["Subject"] = subject
    msg["Date"] = today.strftime("%a, %d %b %Y %H:%M:%S -0400")
    msg["MIME-Version"] = "1.0"
    msg["X-Mailer"] = "Microsoft Outlook 16.0"
    msg["X-Priority"] = "3"
    msg.set_content("\n".join(body_lines))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(msg.as_string())
