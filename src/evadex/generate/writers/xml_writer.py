"""XML writer for evadex generate — financial messaging format (ISO 20022 style)."""
from __future__ import annotations

import datetime
import random
from collections import defaultdict
from xml.sax.saxutils import escape

from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory


def _indent(level: int) -> str:
    return "  " * level


def write_xml(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    today = datetime.date.today().isoformat()

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    lines: list[str] = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.001.09"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">',
        f'{_indent(1)}<CstmrCdtTrfInitn>',
        f'{_indent(2)}<GrpHdr>',
        f'{_indent(3)}<MsgId>EVADEX-{today}-001</MsgId>',
        f'{_indent(3)}<CreDtTm>{today}T00:00:00</CreDtTm>',
        f'{_indent(3)}<NbOfTxs>{len(entries)}</NbOfTxs>',
        f'{_indent(3)}<InitgPty>',
        f'{_indent(4)}<Nm>Evadex DLP Test Suite</Nm>',
        f'{_indent(3)}</InitgPty>',
        f'{_indent(2)}</GrpHdr>',
    ]

    currencies = ["CAD", "USD", "EUR", "GBP", "CHF"]
    names = ["John Smith", "Sarah Chen", "David Wilson", "Maria Garcia",
             "Robert Johnson", "Emily Brown", "Michael Lee", "Jennifer Taylor"]

    for i, e in enumerate(entries, 1):
        amount = f"{rng.uniform(100, 50000):.2f}"
        ccy = rng.choice(currencies)
        name = rng.choice(names)
        val = escape(e.variant_value)

        lines.append(f'{_indent(2)}<PmtInf>')
        lines.append(f'{_indent(3)}<PmtInfId>PMT-{i:06d}</PmtInfId>')
        lines.append(f'{_indent(3)}<PmtMtd>TRF</PmtMtd>')
        lines.append(f'{_indent(3)}<ReqdExctnDt>{today}</ReqdExctnDt>')
        lines.append(f'{_indent(3)}<Dbtr>')
        lines.append(f'{_indent(4)}<Nm>{escape(name)}</Nm>')
        lines.append(f'{_indent(3)}</Dbtr>')
        lines.append(f'{_indent(3)}<CdtTrfTxInf>')
        lines.append(f'{_indent(4)}<PmtId>')
        lines.append(f'{_indent(5)}<EndToEndId>E2E-{i:06d}</EndToEndId>')
        lines.append(f'{_indent(4)}</PmtId>')
        lines.append(f'{_indent(4)}<Amt Ccy="{ccy}">{amount}</Amt>')

        # Place the sensitive value in the appropriate XML element
        cat = e.category
        if cat == PayloadCategory.IBAN:
            lines.append(f'{_indent(4)}<CdtrAcct>')
            lines.append(f'{_indent(5)}<Id>')
            lines.append(f'{_indent(6)}<IBAN>{val}</IBAN>')
            lines.append(f'{_indent(5)}</Id>')
            lines.append(f'{_indent(4)}</CdtrAcct>')
        elif cat == PayloadCategory.SWIFT_BIC:
            lines.append(f'{_indent(4)}<CdtrAgt>')
            lines.append(f'{_indent(5)}<FinInstnId>')
            lines.append(f'{_indent(6)}<BIC>{val}</BIC>')
            lines.append(f'{_indent(5)}</FinInstnId>')
            lines.append(f'{_indent(4)}</CdtrAgt>')
        elif cat == PayloadCategory.CREDIT_CARD:
            lines.append(f'{_indent(4)}<Cdtr>')
            lines.append(f'{_indent(5)}<Nm>{escape(name)}</Nm>')
            lines.append(f'{_indent(4)}</Cdtr>')
            lines.append(f'{_indent(4)}<RmtInf>')
            lines.append(f'{_indent(5)}<Ustrd>Card: {val}</Ustrd>')
            lines.append(f'{_indent(4)}</RmtInf>')
        else:
            lines.append(f'{_indent(4)}<Cdtr>')
            lines.append(f'{_indent(5)}<Nm>{escape(name)}</Nm>')
            lines.append(f'{_indent(4)}</Cdtr>')
            lines.append(f'{_indent(4)}<RmtInf>')
            lines.append(f'{_indent(5)}<Ustrd>{escape(e.embedded_text)}</Ustrd>')
            lines.append(f'{_indent(4)}</RmtInf>')

        if e.technique:
            lines.append(f'{_indent(4)}<!-- evasion: {escape(e.technique)} via {escape(e.generator_name or "")} -->')

        lines.append(f'{_indent(3)}</CdtTrfTxInf>')
        lines.append(f'{_indent(2)}</PmtInf>')

    lines.append(f'{_indent(1)}</CstmrCdtTrfInitn>')
    lines.append('</Document>')
    lines.append('')

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
