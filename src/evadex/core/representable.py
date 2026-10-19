"""Which file strategies can carry a variant's value at all.

DOCX and XLSX are XML containers (OOXML). XML 1.0 forbids the C0 control
characters other than tab, newline and carriage return, and the
non-characters U+FFFE/U+FFFF, so a value carrying one of them has no DOCX or
XLSX fixture: python-docx and openpyxl both refuse to write it. Until 3.41.1
that refusal surfaced as an *error* on the submission — 185 DOCX and 185 XLSX
errors per northam run, one per category — which ``evadex ci`` counts against
``--max-error-rate`` as if the scanner had failed to answer.

PDF has the same shape of limit with a different cause. A PDF text string is
a run of glyphs from a font, so the fixture can carry a character only if
one of the fonts it embeds has a glyph for it; there is no glyph for a
control character or a tab, and which other characters have one depends on
the fonts found on the machine (:mod:`evadex.adapters.dlpscan.pdf_fonts`).
Until 3.42.0 the fixture replaced every character outside Latin-1 with
``?`` and submitted that, so the pdf figure for the regional-digit, zero-
width and homoglyph techniques measured the fixture, not the scanner.

Either way the scanner never saw those submissions, and could not have: the
evasion is not representable in the format. That is a fact about the
fixture, not a verdict on the scanner, so the engine leaves such
``(variant, strategy)`` pairs out of the run and reports how many it left
out, instead of submitting them and recording an error or a miss. The text
strategy carries everything.

The PDF font coverage is not known here — this module has no fonts — so the
fixture registers a provider with :func:`register_pdf_charset`. Without one
(nothing has imported the file builder) only the control-character rule
applies.
"""

from __future__ import annotations

import re
from typing import Callable

# Everything XML 1.0 (section 2.2, "Char") leaves out below U+10000:
# C0 controls except HT/LF/CR, and the two non-characters in the BMP.
XML_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")

# Strategies whose fixture is an XML container.
XML_STRATEGIES: frozenset[str] = frozenset({"docx", "xlsx"})

# A PDF text string has no glyph for a control character, and fpdf2 has no
# layout for a tab. Newline and carriage return are line breaks, which the
# fixture renders with `multi_cell`, so they stay.
PDF_FORBIDDEN = re.compile("[\x00-\x09\x0b\x0c\x0e-\x1f\x7f￾￿]")
PDF_STRATEGY = "pdf"
PDF_LINE_BREAKS: frozenset[str] = frozenset({"\n", "\r"})

CharsetProvider = Callable[[], "frozenset[int] | None"]
_pdf_charset_provider: CharsetProvider | None = None


def register_pdf_charset(provider: CharsetProvider | None) -> CharsetProvider | None:
    """Install the callable that says which code points the PDF fixture's
    fonts can draw (``None`` to forget it). Returns the previous provider so
    a test can restore it."""
    global _pdf_charset_provider
    previous = _pdf_charset_provider
    _pdf_charset_provider = provider
    return previous


def pdf_charset() -> frozenset[int] | None:
    """The PDF fixture's glyph coverage, or ``None`` when nothing has said."""
    return _pdf_charset_provider() if _pdf_charset_provider is not None else None


class UnrepresentableError(ValueError):
    """The text cannot be stored in the requested fixture format."""


def unrepresentable_chars(text: str, strategy: str) -> list[str]:
    """Characters in ``text`` that a ``strategy`` fixture cannot carry.

    Empty for the text strategy, for XML text that XML can hold, and for PDF
    text every embedded font between them can draw.
    """
    if strategy in XML_STRATEGIES:
        return sorted({m.group() for m in XML_FORBIDDEN.finditer(text)})
    if strategy == PDF_STRATEGY:
        bad = {m.group() for m in PDF_FORBIDDEN.finditer(text)}
        charset = pdf_charset()
        if charset is not None:
            bad.update(
                c
                for c in text
                if c not in PDF_LINE_BREAKS
                and ord(c) not in charset
                and not PDF_FORBIDDEN.match(c)
            )
        return sorted(bad)
    return []


def representable(text: str, strategy: str) -> bool:
    """Can a ``strategy`` fixture hold ``text`` verbatim?"""
    return not unrepresentable_chars(text, strategy)


def describe_unrepresentable(text: str, strategy: str) -> str:
    """One line saying which characters stop ``text`` going into ``strategy``."""
    chars = ", ".join(f"U+{ord(c):04X}" for c in unrepresentable_chars(text, strategy))
    if strategy == PDF_STRATEGY:
        return (
            f"pdf cannot carry {chars}: no PDF fixture font has a glyph for it "
            f"(a text string has none for a control character), so this variant "
            f"has no pdf fixture"
        )
    return (
        f"{strategy} cannot carry {chars}: XML 1.0 forbids control characters, "
        f"so this variant has no {strategy} fixture"
    )


def why_unrepresentable(strategies: set[str] | frozenset[str]) -> str:
    """The reasons, as one clause, for a summary line covering ``strategies``."""
    reasons = []
    if strategies & XML_STRATEGIES:
        reasons.append("XML forbids control characters")
    if PDF_STRATEGY in strategies:
        reasons.append("no PDF fixture font has a glyph for them")
    return "; ".join(reasons)
