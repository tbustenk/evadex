"""EML (email) writer for evadex generate.

Supports two modes controlled by the writer template:

* ``generic`` (default) — a single RFC-822 email whose body lists the
  generated entries grouped by category. Matches the original behaviour
  and keeps existing tests stable.

* ``email_thread`` — a realistic 3–8 message conversation rendered as
  one ``.eml`` file. The latest message is at the top with prior
  messages quoted below (``> `` prefix), mirroring how Outlook, Gmail,
  and Thunderbird export a thread. Sensitive values are distributed
  across the thread so the DLP scanner sees them in conversational
  context, not just a bulleted list.
"""
from __future__ import annotations

import datetime
import random
from collections import defaultdict
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory

# Canadian-flavoured participants — names that pass a "looks real" sniff
# test at a bank compliance desk and email domains that blend internal
# bank mailers with external counterparties.
_NAMES: list[tuple[str, str]] = [
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
    ("Priya Kumar", "p.kumar@treasury.bank"),
    ("Ahmed Hassan", "ahassan@audit.bank"),
    ("Wei Tanaka", "wei.tanaka@operations.bank"),
    ("Olivia Tremblay", "olivia.tremblay@caissepop.ca"),
    ("Liam Gagnon", "liam.gagnon@banqueroyale.ca"),
    ("Noah Desjardins", "noah.desjardins@desjardins.example.com"),
]

_SUBJECTS: list[str] = [
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

# Subjects for a fresh thread (no Re:/FW: yet).
_THREAD_SEED_SUBJECTS: list[str] = [
    "Customer KYC refresh — case {ref}",
    "Wire transfer approval — reference {ref}",
    "Q1 compliance review — sensitive records",
    "Fraud investigation — case {ref}",
    "Payroll reconciliation for April",
    "Account migration plan — phase 2",
    "Audit follow-up — customer file {ref}",
    "Cross-border payment query — {ref}",
]

# Realistic banking/compliance chain openers, replies, and closers.
_OPENERS: list[str] = [
    "Hi {name}, following up on our earlier conversation,",
    "Hi {name}, please see below for the information you requested,",
    "Hi {name}, forwarding this across for your records,",
    "Hi {name}, looping you in on this thread,",
    "Hi {name}, circling back on the compliance review,",
]

_REPLY_OPENERS: list[str] = [
    "Thanks {name}, a few follow-up items on the below:",
    "Hi {name}, quick note — we should flag this for the audit team.",
    "{name}, confirming receipt. One clarification before we proceed:",
    "Thanks — passing these along so you have everything in one place.",
    "Picking this back up — had a chat with risk management earlier.",
]

_CLOSERS: list[str] = [
    "Let me know if anything looks off.",
    "Happy to jump on a call if easier.",
    "Please confirm you've seen this when you get a chance.",
    "Flag me if you need anything else from my side.",
    "Cheers,",
]


def _sign(name: str, title: str) -> list[str]:
    first = name.split()[0]
    return [
        "",
        "Best regards,",
        name,
        f"{title}",
        f"{first}'s Office | Compliance & Risk Management",
    ]


def _quote(lines: list[str]) -> list[str]:
    """Prefix each line with ``> `` (standard plain-text quoting)."""
    return [("> " + ln) if ln else ">" for ln in lines]


def _build_generic_single(entries: list[GeneratedEntry], rng: random.Random) -> EmailMessage:
    """Original single-email body — one message listing entries by category."""
    today = datetime.date.today()
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    sender = rng.choice(_NAMES)
    recipient = rng.choice([n for n in _NAMES if n != sender])
    subject = rng.choice(_SUBJECTS).format(date=today.isoformat())

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
    return msg


def _chunk_entries(entries: list[GeneratedEntry], n_chunks: int) -> list[list[GeneratedEntry]]:
    """Split ``entries`` into exactly ``n_chunks`` roughly-equal chunks.
    Empty chunks are allowed when len(entries) < n_chunks so every
    message still gets *some* prose (see _compose_turn)."""
    if n_chunks <= 0:
        return []
    # ceil division keeps earlier messages fuller than later ones, which
    # matches how real threads tend to front-load the data dump.
    size = max(1, (len(entries) + n_chunks - 1) // n_chunks)
    chunks = [entries[i:i + size] for i in range(0, len(entries), size)]
    while len(chunks) < n_chunks:
        chunks.append([])
    return chunks[:n_chunks]


def _compose_turn(
    turn_idx: int,
    total_turns: int,
    sender: tuple[str, str],
    recipient: tuple[str, str],
    cc_list: list[tuple[str, str]],
    chunk: list[GeneratedEntry],
    ref: str,
    rng: random.Random,
) -> list[str]:
    """Render one message body (no headers, no quoting) as a list of lines."""
    first_name = recipient[0].split()[0]
    if turn_idx == 0:
        opener = rng.choice(_OPENERS).format(name=first_name)
    else:
        opener = rng.choice(_REPLY_OPENERS).format(name=first_name)

    lines: list[str] = [opener, ""]

    if chunk:
        if turn_idx == 0:
            lines.append(
                f"Below are the sensitive records tied to case {ref}. "
                f"Please handle per the data protection policy (DRP-2024)."
            )
        else:
            lines.append(
                "A couple more items came in on this — flagging so we "
                "have them all in one place:"
            )
        lines.append("")
        for e in chunk:
            lines.append(f"  • {e.embedded_text}")
        lines.append("")
    else:
        lines.append(
            "No new records on my end — just confirming that we're aligned "
            "on the next step before end of day."
        )
        lines.append("")

    if turn_idx == total_turns - 1:
        lines.append("Closing this thread once you've reviewed — thanks for the quick turnaround.")
    else:
        lines.append(rng.choice(_CLOSERS))

    title = "Compliance & Risk Management"
    lines += _sign(sender[0], title)
    if cc_list:
        lines.append("CC: " + ", ".join(f"{n} <{a}>" for n, a in cc_list))
    return lines


def _build_thread(entries: list[GeneratedEntry], rng: random.Random) -> EmailMessage:
    """Build a single .eml representing a 3–8 message conversation.

    The outer message is the most recent reply; every earlier message
    is quoted inline below it using ``> `` prefixes, exactly how a
    mail client renders a thread you'd forward to compliance."""
    n_turns = rng.randint(3, 8)
    participants = rng.sample(_NAMES, k=min(len(_NAMES), max(2, min(4, n_turns))))
    # Alternate sender/recipient turn-by-turn; CC the remaining participants.
    sender0 = participants[0]
    recipient0 = participants[1]
    cc_pool = participants[2:]
    ref = f"{rng.randint(100000, 999999)}"
    seed_subject = rng.choice(_THREAD_SEED_SUBJECTS).format(ref=ref)
    base_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=rng.randint(0, 3))

    chunks = _chunk_entries(entries, n_turns)

    # Build each turn in chronological order (0 = first message), then
    # render the thread with the newest turn on top.
    turns: list[dict] = []
    for t in range(n_turns):
        # Alternate sender/recipient each turn.
        if t % 2 == 0:
            sender, recipient = sender0, recipient0
        else:
            sender, recipient = recipient0, sender0
        # Rotate one CC off the list every other turn to feel real.
        cc_here = cc_pool[: max(0, len(cc_pool) - (t % 2))]
        body_lines = _compose_turn(
            turn_idx=t,
            total_turns=n_turns,
            sender=sender,
            recipient=recipient,
            cc_list=cc_here,
            chunk=chunks[t],
            ref=ref,
            rng=rng,
        )
        sent = base_date + datetime.timedelta(hours=t * rng.randint(1, 6))
        turns.append({
            "sender": sender,
            "recipient": recipient,
            "cc": cc_here,
            "subject": (f"Re: {seed_subject}" if t > 0 else seed_subject),
            "date": sent,
            "body": body_lines,
            "message_id": make_msgid(domain="evadex.bank"),
        })

    # Newest turn is at the top; older turns quoted beneath.
    newest = turns[-1]
    older = list(reversed(turns[:-1]))

    rendered: list[str] = list(newest["body"])
    for prior in older:
        attribution = (
            f"On {prior['date'].strftime('%a, %d %b %Y at %H:%M')}, "
            f"{prior['sender'][0]} <{prior['sender'][1]}> wrote:"
        )
        rendered.append("")
        rendered.append(attribution)
        rendered.extend(_quote(prior["body"]))

    msg = EmailMessage()
    msg["From"] = formataddr(newest["sender"])
    msg["To"] = formataddr(newest["recipient"])
    if newest["cc"]:
        msg["Cc"] = ", ".join(formataddr(c) for c in newest["cc"])
    msg["Subject"] = newest["subject"]
    msg["Date"] = newest["date"].strftime("%a, %d %b %Y %H:%M:%S -0400")
    msg["Message-ID"] = newest["message_id"]
    # Threading headers — In-Reply-To is the immediate parent; References
    # is the full chain. Both are required for mail clients to stitch the
    # thread back together after export.
    if len(turns) > 1:
        msg["In-Reply-To"] = turns[-2]["message_id"]
        msg["References"] = " ".join(t["message_id"] for t in turns[:-1])
    msg["MIME-Version"] = "1.0"
    msg["X-Mailer"] = "Microsoft Outlook 16.0"
    msg["X-Priority"] = "3"
    msg["X-Thread-Length"] = str(n_turns)
    msg.set_content("\n".join(rendered))
    return msg


def write_eml(entries: list[GeneratedEntry], path: str) -> None:
    from evadex.generate.writers import _active_template, _active_seed

    rng = random.Random(_active_seed if _active_seed is not None else 42)

    template = (_active_template or "generic").lower()
    if template == "email_thread":
        msg = _build_thread(entries, rng)
    else:
        msg = _build_generic_single(entries, rng)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(msg.as_string())
