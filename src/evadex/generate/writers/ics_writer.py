"""iCalendar (.ics) writer for evadex generate.

Each generated entry becomes one VEVENT. Sensitive payloads land in
``DESCRIPTION``, ``SUMMARY``, and ``ATTENDEE`` properties — the
fields Siphon's ``extract_ics`` walks.

Lines are CRLF-terminated and folded at 75 octets per RFC 5545 so
the fixture is parseable by any conformant calendar client.
"""
from __future__ import annotations

import datetime
import random

from evadex.generate.generator import GeneratedEntry


_ATTENDEES = [
    "sarah.chen@globalfinance.ca",
    "rjohnson@acmebank.com",
    "m.wilson@compliance-team.local",
    "p.kumar@treasury.bank",
    "ahassan@audit.bank",
    "j.park@risk.bank",
]

_SUMMARY_TEMPLATES = [
    "KYC review meeting — {value}",
    "Wire-transfer reconciliation — case {value}",
    "Quarterly audit walkthrough",
    "Incident response sync — ref {value}",
    "Customer escalation: {value}",
    "Compliance findings review",
]

_LOCATIONS = [
    "Toronto HQ — 4th Floor Boardroom",
    "Conference Bridge: +1-416-555-0142",
    "Microsoft Teams (link in invite)",
    "Calgary Office — Room 302",
    "Zoom Bridge",
]


def _escape_ics_text(s: str) -> str:
    """RFC 5545 text-property escaping: backslash, semicolon, comma,
    and newline get backslash-escaped."""
    return (
        s.replace("\\", "\\\\")
         .replace(";", "\\;")
         .replace(",", "\\,")
         .replace("\n", "\\n")
         .replace("\r", "")
    )


def _fold(line: str) -> list[str]:
    """RFC 5545 line folding: split at 75 octets, continuation lines
    begin with a single space."""
    if len(line) <= 75:
        return [line]
    out: list[str] = [line[:75]]
    rest = line[75:]
    while rest:
        out.append(" " + rest[:74])
        rest = rest[74:]
    return out


def _vevent(
    idx: int,
    base_dt: datetime.datetime,
    rng: random.Random,
    entry: GeneratedEntry,
) -> list[str]:
    start = base_dt + datetime.timedelta(days=idx, hours=rng.randint(0, 7))
    end = start + datetime.timedelta(hours=1)
    uid = f"{idx}-{rng.randint(100000, 999999)}@evadex.bank"

    organizer = rng.choice(_ATTENDEES)
    n_attend = rng.randint(2, 4)
    attendees = rng.sample(_ATTENDEES, min(n_attend, len(_ATTENDEES)))

    summary = _escape_ics_text(
        rng.choice(_SUMMARY_TEMPLATES).format(value=entry.variant_value)
    )
    description = _escape_ics_text(
        f"Agenda: review of {entry.category.value} case data. "
        f"Reference value: {entry.variant_value}. "
        f"Background: {entry.embedded_text} "
        f"Please review prior to the meeting."
    )
    location = _escape_ics_text(rng.choice(_LOCATIONS))

    lines = [
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTAMP:{start.strftime('%Y%m%dT%H%M%SZ')}",
        f"DTSTART:{start.strftime('%Y%m%dT%H%M%SZ')}",
        f"DTEND:{end.strftime('%Y%m%dT%H%M%SZ')}",
        f"SUMMARY:{summary}",
        f"LOCATION:{location}",
        f"DESCRIPTION:{description}",
        f"ORGANIZER;CN={organizer}:mailto:{organizer}",
    ]
    for a in attendees:
        lines.append(f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:{a}")
    lines.append("CLASS:CONFIDENTIAL")
    lines.append("END:VEVENT")

    folded: list[str] = []
    for ln in lines:
        folded.extend(_fold(ln))
    return folded


def write_ics(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    base_dt = datetime.datetime(2026, 5, 1, 9, 0, 0,
                                tzinfo=datetime.timezone.utc)

    out: list[str] = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//evadex//DLP Test Suite//EN",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
    ]
    for i, e in enumerate(entries):
        out.extend(_vevent(i, base_dt, rng, e))
    out.append("END:VCALENDAR")

    # RFC 5545 specifies CRLF.
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write("\r\n".join(out) + "\r\n")
