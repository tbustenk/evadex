"""MBOX writer for evadex generate — Unix mailbox format.

Each generated entry becomes one email message in the mailbox. The
resulting file exercises realistic DLP signal:

* **Mixed read / unread** — ``Status: RO`` (read + old) vs ``Status: O``
  (new, unread), driven by rng so a scan sees a realistic ratio.
* **Diverse senders and recipients** — rotated independently per
  message so no single correspondent dominates, plus occasional CC.
* **Attachment references** — a subset of messages include MIME parts
  whose ``Content-Disposition: attachment; filename=...`` points at a
  plausible filename but carries no bytes (the disposition header is
  what DLP mail scanners pivot on, not the payload).
* **Phishing / spam simulations** — a subset are styled as credential
  phishing with evasion-tier obfuscation (homoglyphs, zero-width
  spaces) around the sensitive value so entropy-based filters get
  exercised alongside keyword filters.
* **Transfer encodings** — roughly one in three bodies is base64
  encoded so Siphon's ``extract_mbox`` decode path runs in both the
  ``7bit`` and ``base64`` branches.
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
    ("Olivia Tremblay", "olivia.tremblay@caissepop.ca"),
    ("Liam Gagnon", "liam.gagnon@banqueroyale.ca"),
    ("Noah Desjardins", "noah.desjardins@desjardins.example.com"),
    ("Charlotte Roy", "c.roy@treasury.bank"),
]
_TO_ADDRS = [
    ("John Smith", "john.smith@acmebank.com"),
    ("Jennifer Park", "jennifer.park@risk.bank"),
    ("Michael Lee", "mlee@operations.bank"),
    ("Lisa Garcia", "l.garcia@compliance-team.local"),
    ("Emma Brown", "emma.brown@treasuryops.ca"),
    ("James Anderson", "james.anderson@investco.com"),
]
_CC_ADDRS = [
    ("Compliance Bot", "compliance-noreply@acmebank.com"),
    ("Audit Records", "audit-records@audit.bank"),
    ("Risk Desk", "risk-desk@operations.bank"),
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

# Phishing subject lines use urgency + authority cues the way real
# credential-harvest campaigns do. Keeps DLP and phishing-simulation
# corpora usable from the same mbox.
_PHISH_SUBJECTS = [
    "URGENT: Verify your account — suspicious login detected",
    "Action required: your wire transfer has been HELD",
    "[SECURITY] Password expires in 24 hours — confirm now",
    "Your payroll deposit was declined — re-enter banking info",
    "Compliance notice: account update required immediately",
    "FINAL NOTICE — tax refund pending verification",
]

_ATTACHMENT_NAMES = [
    "Q1_statement.pdf",
    "KYC_update_form.docx",
    "audit_findings_draft.xlsx",
    "wire_reconciliation.csv",
    "customer_records_export.zip",
    "compliance_report_2026.pdf",
]


# ── Evasion helpers for phishing variants ────────────────────────────
# Kept tiny and local: the real evasion stack is huge but a mailbox
# only needs enough noise to look plausible and trip naive filters.

_HOMOGLYPHS = {
    "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х",
}
_ZWSP = "​"


def _homoglyph(text: str, rng: random.Random) -> str:
    return "".join(_HOMOGLYPHS.get(ch, ch) if rng.random() < 0.35 else ch
                   for ch in text)


def _zwsp_split(text: str, rng: random.Random) -> str:
    # Insert a zero-width space every ~3 chars so visual rendering is
    # unchanged but exact-match filters miss.
    out: list[str] = []
    for i, ch in enumerate(text):
        out.append(ch)
        if i and i % 3 == 0 and rng.random() < 0.5:
            out.append(_ZWSP)
    return "".join(out)


def _evade(text: str, rng: random.Random) -> str:
    if rng.random() < 0.5:
        return _homoglyph(text, rng)
    return _zwsp_split(text, rng)


# ── Per-message rendering ─────────────────────────────────────────────

def _phishing_body(
    recipient: tuple[str, str],
    entry: GeneratedEntry,
    rng: random.Random,
) -> str:
    """Credential-phishing body with lightly-obfuscated sensitive data."""
    obfuscated = _evade(entry.variant_value, rng)
    return (
        f"Dear {recipient[0].split()[0]},\n\n"
        f"We detected unusual activity on your account. To keep access, "
        f"verify the details below within 24 hours or your account will "
        f"be suspended.\n\n"
        f"Verification reference: {obfuscated}\n\n"
        f"If you did not authorise this action, click here to secure "
        f"your account: http://secure-acmebank-verify.example.com/login\n\n"
        f"Thank you,\n"
        f"Account Security Team\n"
        f"Acme Bank\n"
    )


def _legit_body(
    sender: tuple[str, str],
    recipient: tuple[str, str],
    entry: GeneratedEntry,
    ref: str,
) -> str:
    return (
        f"Hi {recipient[0].split()[0]},\n\n"
        f"Per our compliance review, please find the requested data "
        f"below for case {ref}.\n\n"
        f"Reference value: {entry.variant_value}\n"
        f"Category: {entry.category.value}\n"
        f"Context: {entry.embedded_text}\n\n"
        f"Please handle in accordance with our data protection policy. "
        f"Reply if any clarification is needed.\n\n"
        f"Best regards,\n{sender[0]}\n"
    )


def _status_header(is_read: bool) -> str:
    # mutt/procmail convention: R = Read, O = Old (seen before).
    # Absence of ``R`` means unread. ``X-Status`` carries per-client
    # state, which we vary slightly so a scanner looking for either
    # header finds realistic data.
    if is_read:
        return "Status: RO\nX-Status: "
    return "Status: O\nX-Status: N"


def _format_phishing(
    msg_id: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
) -> str:
    # Phishing messages almost always come from a fake lookalike sender.
    fake_name, fake_addr = rng.choice([
        ("Account Security", "no-reply@acmebank-secure.example.com"),
        ("ACME Bank", "security@acmebank-support.example"),
        ("Payroll Notice", "payroll-noreply@bank-update.example.com"),
    ])
    recipient = rng.choice(_TO_ADDRS)
    subj = rng.choice(_PHISH_SUBJECTS)
    sent = base_dt + datetime.timedelta(minutes=msg_id * 7)
    ref = f"{rng.randint(100000, 999999)}"
    body = _phishing_body(recipient, entry, rng)
    # Phishing stays unread far more often than legit mail — that's what
    # triggers the "urgency" psychology in the first place.
    status = _status_header(is_read=rng.random() < 0.15)
    headers = [
        f"From {fake_addr} {sent.strftime('%a %b %d %H:%M:%S %Y')}",
        f"From: {formataddr((fake_name, fake_addr))}",
        f"To: {formataddr(recipient)}",
        f"Subject: {subj}",
        f"Date: {format_datetime(sent)}",
        f"Message-ID: <{ref}-phish-{msg_id}@acmebank-secure.example.com>",
        "MIME-Version: 1.0",
        status,
        "X-Spam-Flag: YES",
        "X-Evadex-Simulation: phishing",
        'Content-Type: text/plain; charset="utf-8"',
        "Content-Transfer-Encoding: 7bit",
    ]
    return "\n".join(headers) + "\n\n" + body + "\n"


def _format_with_attachment(
    msg_id: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
) -> str:
    """Multipart message with a referenced (zero-byte) attachment part."""
    sender = rng.choice(_FROM_ADDRS)
    recipient = rng.choice(_TO_ADDRS)
    ref = f"{rng.randint(100000, 999999)}"
    subj = rng.choice(_SUBJECT_TEMPLATES).format(ref=ref)
    sent = base_dt + datetime.timedelta(minutes=msg_id * 7)
    fname = rng.choice(_ATTACHMENT_NAMES)
    status = _status_header(is_read=rng.random() < 0.6)
    boundary = f"=_evadex_{msg_id}_{rng.randint(10000, 99999)}"
    body = _legit_body(sender, recipient, entry, ref)

    headers = [
        f"From {sender[1]} {sent.strftime('%a %b %d %H:%M:%S %Y')}",
        f"From: {formataddr(sender)}",
        f"To: {formataddr(recipient)}",
        f"Cc: {formataddr(rng.choice(_CC_ADDRS))}",
        f"Subject: {subj}",
        f"Date: {format_datetime(sent)}",
        f"Message-ID: <{ref}-{msg_id}@evadex.bank>",
        "MIME-Version: 1.0",
        status,
        # "Referenced, not embedded" — the part is declared but we
        # deliberately write a stub. Real scanners key off the
        # disposition header and filename, which is what we want to
        # exercise here.
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
    ]
    parts = [
        f"--{boundary}",
        'Content-Type: text/plain; charset="utf-8"',
        "Content-Transfer-Encoding: 7bit",
        "",
        body,
        f"--{boundary}",
        'Content-Type: application/octet-stream',
        f'Content-Disposition: attachment; filename="{fname}"',
        "Content-Transfer-Encoding: base64",
        "X-Evadex-Attachment-Reference: true",
        "",
        # Zero-byte stub — scanners see the disposition but no payload.
        "",
        f"--{boundary}--",
        "",
    ]
    return "\n".join(headers) + "\n\n" + "\n".join(parts) + "\n"


def _format_standard(
    msg_id: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
    use_base64: bool,
) -> str:
    """Plain single-part message — the most common shape in the mailbox."""
    sender = rng.choice(_FROM_ADDRS)
    recipient = rng.choice(_TO_ADDRS)
    ref = f"{rng.randint(100000, 999999)}"
    subj = rng.choice(_SUBJECT_TEMPLATES).format(ref=ref)
    sent = base_dt + datetime.timedelta(minutes=msg_id * 7)
    body = _legit_body(sender, recipient, entry, ref)
    status = _status_header(is_read=rng.random() < 0.55)

    headers = [
        f"From {sender[1]} {sent.strftime('%a %b %d %H:%M:%S %Y')}",
        f"From: {formataddr(sender)}",
        f"To: {formataddr(recipient)}",
        f"Subject: {subj}",
        f"Date: {format_datetime(sent)}",
        f"Message-ID: <{ref}-{msg_id}@evadex.bank>",
        "MIME-Version: 1.0",
        status,
    ]
    # Occasional CC to make threading/header parsing nontrivial.
    if rng.random() < 0.3:
        headers.insert(-2, f"Cc: {formataddr(rng.choice(_CC_ADDRS))}")

    if use_base64:
        encoded = base64.b64encode(body.encode("utf-8")).decode("ascii")
        wrapped = "\n".join(encoded[i:i + 76] for i in range(0, len(encoded), 76))
        headers.append('Content-Type: text/plain; charset="utf-8"')
        headers.append("Content-Transfer-Encoding: base64")
        return "\n".join(headers) + "\n\n" + wrapped + "\n\n"

    headers.append('Content-Type: text/plain; charset="utf-8"')
    headers.append("Content-Transfer-Encoding: 7bit")
    return "\n".join(headers) + "\n\n" + body + "\n"


def write_mbox(entries: list[GeneratedEntry], path: str) -> None:
    """Write a Unix mailbox with a mix of standard, attachment-bearing,
    and phishing-simulation messages.

    Roughly:
      * 10 % phishing simulations (``X-Evadex-Simulation: phishing``)
      * 20 % standard messages with a referenced attachment part
      * 33 % base64-encoded bodies (among the standard messages)
    """
    from evadex.generate.writers import _active_seed
    rng = random.Random(_active_seed if _active_seed is not None else 42)
    base_dt = datetime.datetime(
        2026, 4, 17, 9, 0, 0, tzinfo=datetime.timezone.utc
    )

    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for i, e in enumerate(entries, 1):
            roll = rng.random()
            if roll < 0.10:
                fh.write(_format_phishing(i, base_dt, rng, e))
            elif roll < 0.30:
                fh.write(_format_with_attachment(i, base_dt, rng, e))
            else:
                fh.write(_format_standard(i, base_dt, rng, e, use_base64=(i % 3 == 0)))
