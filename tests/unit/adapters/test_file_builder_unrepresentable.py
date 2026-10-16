"""``FileBuilder.build`` refuses text an XML container cannot hold, by name.

python-docx and openpyxl refuse too, with "All strings must be XML
compatible: Unicode or ASCII, no NULL bytes or control characters". That
message does not say which character or that the variant simply has no
fixture in this format, and it arrived as a per-submission *error* in scan
output. The builder now raises before either library gets the text.
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


def test_pdf_still_carries_the_control_character():
    pytest.importorskip("fpdf")
    data, mime = FileBuilder.build(SENTENCE, "pdf")
    assert data.startswith(b"%PDF") and mime == "application/pdf"


@pytest.mark.parametrize("fmt", ["docx", "xlsx"])
def test_xml_containers_still_build_ordinary_text(fmt):
    pytest.importorskip("docx" if fmt == "docx" else "openpyxl")
    data, _ = FileBuilder.build("Employee SSN 742-18-5503 on file.", fmt)
    assert data[:2] == b"PK", "an OOXML container is a zip"
