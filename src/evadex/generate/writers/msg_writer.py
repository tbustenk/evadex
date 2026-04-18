"""MSG (Outlook message) writer for evadex generate.

Limitation: generates EML-format content saved with .msg extension.
True MSG binary format requires the compoundfiles or extract-msg library
which adds complexity for minimal DLP-testing benefit — the textual content
is identical and most DLP scanners extract text the same way.
"""
from __future__ import annotations

from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers.eml_writer import write_eml


def write_msg(entries: list[GeneratedEntry], path: str) -> None:
    """Write an EML-format email saved with .msg extension.

    Note: This produces RFC 2822 email content, not the proprietary
    Outlook MSG binary format.  For DLP testing purposes the text
    content is identical.
    """
    write_eml(entries, path)
