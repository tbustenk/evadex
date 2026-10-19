"""``FileBuilder.build`` refuses text a fixture cannot hold, by name.

python-docx and openpyxl refuse too, with "All strings must be XML
compatible: Unicode or ASCII, no NULL bytes or control characters". That
message does not say which character or that the variant simply has no
fixture in this format, and it arrived as a per-submission *error* in scan
output. The builder now raises before either library gets the text. fpdf2
does not refuse at all — it drops a glyph a TrueType font lacks with a
warning — so for pdf the builder is the only thing that says no.
"""

from __future__ import annotations

import pytest

from evadex.adapters.dlpscan.file_builder import FileBuilder
from evadex.core.representable import UnrepresentableError

SENTENCE = "Employee SSN 742-1\x1e8-5503 on file."


@pytest.mark.parametrize("fmt", ["docx", "xlsx"])
def test_xml_containers_refuse_control_characters_by_code_point(fmt):
    with pytest.raises(UnrepresentableError) as exc:
        FileBuilder.build(SENTENCE, fmt)
    assert "U+001E" in str(exc.value)
    assert fmt in str(exc.value)


def test_pdf_refuses_the_control_character_too():
    """A PDF text string is glyphs; there is no glyph for U+001E. Until 3.42.0
    the fixture wrote the raw byte into the content stream and the pdf
    strategy reported the variant as a miss."""
    pytest.importorskip("fpdf")
    with pytest.raises(UnrepresentableError) as exc:
        FileBuilder.build(SENTENCE, "pdf")
    assert "U+001E" in str(exc.value) and "pdf" in str(exc.value)


def test_pdf_builds_ordinary_text_and_a_newline():
    pytest.importorskip("fpdf")
    data, mime = FileBuilder.build("Employee SSN 742-18-5503\non file.", "pdf")
    assert data.startswith(b"%PDF") and mime == "application/pdf"


@pytest.mark.parametrize("fmt", ["docx", "xlsx"])
def test_xml_containers_still_build_ordinary_text(fmt):
    pytest.importorskip("docx" if fmt == "docx" else "openpyxl")
    data, _ = FileBuilder.build("Employee SSN 742-18-5503 on file.", fmt)
    assert data[:2] == b"PK", "an OOXML container is a zip"
