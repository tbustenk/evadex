"""Which file strategies can carry a variant's value at all.

DOCX and XLSX are XML containers (OOXML). XML 1.0 forbids the C0 control
characters other than tab, newline and carriage return, and the
non-characters U+FFFE/U+FFFF, so a value carrying one of them has no DOCX or
XLSX fixture: python-docx and openpyxl both refuse to write it. Until 3.41.1
that refusal surfaced as an *error* on the submission — 185 DOCX and 185 XLSX
errors per northam run, one per category — which ``evadex ci`` counts against
``--max-error-rate`` as if the scanner had failed to answer.

The scanner never saw those submissions, and could not have: the evasion is
not representable in the format. That is a fact about the fixture, not a
verdict on the scanner, so the engine leaves such (variant, strategy) pairs
out of the run and reports how many it left out, instead of submitting them
and recording an error. The text and PDF strategies still carry them.

Only one generator produces such a value today: ``barcode_evasion``'s
``barcode_split`` marks the split point with U+001E, an instruction to the
barcode renderer that the text path passes through as a control character.
"""

from __future__ import annotations

import re

# Everything XML 1.0 (section 2.2, "Char") leaves out below U+10000:
# C0 controls except HT/LF/CR, and the two non-characters in the BMP.
XML_FORBIDDEN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")

# Strategies whose fixture is an XML container.
XML_STRATEGIES: frozenset[str] = frozenset({"docx", "xlsx"})


class UnrepresentableError(ValueError):
    """The text cannot be stored in the requested fixture format."""


def unrepresentable_chars(text: str, strategy: str) -> list[str]:
    """Characters in ``text`` that a ``strategy`` fixture cannot carry.

    Empty for every strategy that is not an XML container, and for text that
    XML can hold.
    """
    if strategy not in XML_STRATEGIES:
        return []
    return sorted({m.group() for m in XML_FORBIDDEN.finditer(text)})


def representable(text: str, strategy: str) -> bool:
    """Can a ``strategy`` fixture hold ``text`` verbatim?"""
    return not unrepresentable_chars(text, strategy)


def describe_unrepresentable(text: str, strategy: str) -> str:
    """One line saying which characters stop ``text`` going into ``strategy``."""
    chars = ", ".join(f"U+{ord(c):04X}" for c in unrepresentable_chars(text, strategy))
    return (
        f"{strategy} cannot carry {chars}: XML 1.0 forbids control characters, "
        f"so this variant has no {strategy} fixture"
    )
