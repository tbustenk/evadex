"""MBOX writer for evadex generate — Unix mailbox format.

Each generated entry becomes one email message in the mailbox. A
fraction of bodies are base64-encoded so the test suite exercises
both ``Content-Transfer-Encoding: 7bit`` and ``base64`` decode paths
in Siphon's ``extract_mbox`` (``crates/siphon-core/src/extractors.rs``).
"""
from __future__ import annotations

import base64
import datetime
import random
from email.utils import format_datetime, formataddr

from evadex.generate.generator import GeneratedEntry


_FROM_ADDRS = [
    ("Sarah Chen", "sarah.chen@globalfinance.ca"),
    ("Robert Johnson", "rjohnson@acmebank.com"),
    ("Maria Wilson", "m.wilson@compliance-team.local"),
    ("Wei Tanaka", "wei.tanaka@operations.bank"),
    ("Priya Kumar", "p.kumar@treasury.bank"),
    ("Ahmed Hassan", "ahassan@audit.bank"),
]
_TO_ADDRS = [
    ("John Smith", "john.smith@acmebank.com"),
    ("Jennifer Park", "jennifer.park@risk.bank"),
    ("Michael Lee", "mlee@operations.bank"),
    ("Lisa Garcia", "l.garcia@compliance-team.local"),
]
_SUBJECT_TEMPLATES = [
    "Transaction verification — case {ref}",
    "Wire transfer reconciliation Q1",
    "Customer KYC update — ref {ref}",
    "Compliance review findings",
    "Account reconciliation request",
    "Fraud alert investigation — {ref}",
    "Quarterly audit follow-up",
    "Wire return notification — {ref}",
]


def _format_message(
    msg_id: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
    use_base64: bool,
) -> str:
    """Render one RFC 5322 message including a leading ``From `` line
    so it's a valid mbox-`From-style member."""
    sender = rng.choice(_FROM_ADDRS)
    recipient = rng.choice(_TO_ADDRS)
    ref = f"{rng.randint(100000, 999999)}"
    subj = rng.choice(_SUBJECT_TEMPLATES).format(ref=ref)
    sent = base_dt + datetime.timedelta(minutes=msg_id * 7)

    body = (
        f"Hi {recipient[0].split()[0]},\n\n"
        f"Per our compliance review, please find the requested "
        f"data below for case {ref}.\n\n"
        f"Reference value: {entry.variant_value}\n"
        f"Category: {entry.category.value}\n"
        f"Context: {entry.embedded_text}\n\n"
        f"Please handle in accordance with our data protection "
        f"policy. Reply if any clarification is needed.\n\n"
        f"Best regards,\n{sender[0]}\n"
    )

    headers = [
        f"From {sender[1]} {sent.strftime('%a %b %d %H:%M:%S %Y')}",
        f"From: {formataddr(sender)}",
        f"To: {formataddr(recipient)}",
        f"Subject: {subj}",
        f"Date: {format_datetime(sent)}",
        f"Message-ID: <{ref}-{msg_id}@evadex.bank>",
        "MIME-Version: 1.0",
    ]

    if use_base64:
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
        # Wrap to RFC-friendly 76-char lines.
        wrapped = "\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76))
        headers.append('Content-Type: text/plain; charset="utf-8"')
        headers.append("Content-Transfer-Encoding: base64")
        return "\n".join(headers) + "\n\n" + wrapped + "\n\n"

    headers.append('Content-Type: text/plain; charset="utf-8"')
    headers.append("Content-Transfer-Encoding: 7bit")
    return "\n".join(headers) + "\n\n" + body + "\n"


def write_mbox(entries: list[GeneratedEntry], path: str) -> None:
    """Write a Unix mailbox file containing one message per entry.

    Roughly one in three messages uses base64 transfer encoding so
    Siphon's mbox extractor decode path gets exercised.
    """
    rng = random.Random(42)
    base_dt = datetime.datetime(2026, 4, 17, 9, 0, 0,
                                tzinfo=datetime.timezone.utc)

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for i, e in enumerate(entries, 1):
            use_base64 = (i % 3 == 0)
            fh.write(_format_message(i, base_dt, rng, e, use_base64))
