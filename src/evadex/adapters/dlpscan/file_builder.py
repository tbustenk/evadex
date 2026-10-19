import io
from typing import Literal

from evadex.adapters.dlpscan import pdf_fonts
from evadex.core.representable import (
    UnrepresentableError,
    describe_unrepresentable,
    register_pdf_charset,
    representable,
)

try:
    from docx import Document

    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

try:
    from fpdf import FPDF

    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

try:
    import openpyxl

    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False


DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PDF_MIME = "application/pdf"
XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

NOISE_SENTENCES = [
    "This document contains confidential business information.",
    "Please handle with care and do not distribute.",
    "For internal use only.",
    "Authorized personnel only.",
]

# The PDF fixture's fonts decide which characters the pdf strategy can carry.
# Tell the engine, so a variant no font can draw is left out of the run and
# counted as such, rather than built with the character missing.
register_pdf_charset(pdf_fonts.charset)


class FileBuilder:
    @staticmethod
    def build(text: str, fmt: Literal["docx", "pdf", "xlsx"]) -> tuple[bytes, str]:
        """Build an in-memory document containing text. Returns (bytes, mime_type).
        Never writes to disk — uses io.BytesIO only.

        Raises :class:`UnrepresentableError` when ``fmt`` is an XML container
        (docx, xlsx) and ``text`` holds a character XML 1.0 forbids, or when
        ``fmt`` is pdf and no fixture font has a glyph for a character in
        ``text`` (a control character never does). The libraries would fail
        anyway — python-docx with a message about "all strings", fpdf2 by
        dropping the glyph — this names the character and says the variant
        has no fixture in that format. The engine normally filters these
        out before they get here (evadex.core.representable).
        """
        if not representable(text, fmt):
            raise UnrepresentableError(describe_unrepresentable(text, fmt))
        if fmt == "docx":
            return FileBuilder._build_docx(text), DOCX_MIME
        elif fmt == "pdf":
            return FileBuilder._build_pdf(text), PDF_MIME
        elif fmt == "xlsx":
            return FileBuilder._build_xlsx(text), XLSX_MIME
        else:
            raise ValueError(f"Unknown format: {fmt!r}")

    @staticmethod
    def _build_docx(text: str) -> bytes:
        if not HAS_DOCX:
            raise RuntimeError("python-docx is required for DOCX generation")
        doc = Document()
        doc.add_paragraph(NOISE_SENTENCES[0])
        doc.add_paragraph(NOISE_SENTENCES[1])
        doc.add_paragraph(text)
        doc.add_paragraph(NOISE_SENTENCES[2])
        buf = io.BytesIO()
        doc.save(buf)
        return buf.getvalue()

    @staticmethod
    def _build_pdf(text: str) -> bytes:
        """Render ``text`` as itself, or not at all.

        Latin-1 text is drawn with fpdf2's core Helvetica, as every fixture
        before 3.42.0 was: nothing to parse or embed (~2 ms), and the PDF a
        Latin-1 value produces is the same kind as in every earlier baseline.
        Anything else is drawn with the TrueType fonts :mod:`pdf_fonts`
        found — the fewest that between them draw the text (~40 ms, paid
        only by the third of variants that need it) — and a character none
        of them can draw was refused by :meth:`build` before this ran. There
        is deliberately no ``errors="replace"`` here: until 3.42.0 that is
        what turned every non-Latin-1 character into ``?`` and made the pdf
        strategy measure the fixture instead of the scanner. ``multi_cell``
        rather than ``cell`` so a newline inside a value is a line break, as
        it is in the text strategy, rather than an unrenderable glyph.
        """
        if not HAS_FPDF:
            raise RuntimeError("fpdf2 is required for PDF generation")
        pdf = FPDF()
        pdf.add_page()
        chosen = (
            [] if pdf_fonts.core_can_draw(text) else pdf_fonts.fonts().fonts_for(text)
        )
        if chosen:
            for family, path in chosen:
                kwargs = (
                    {"collection_font_number": 0}
                    if path.suffix.lower() == ".ttc"
                    else {}
                )
                pdf.add_font(family, fname=str(path), **kwargs)
            pdf.set_font(chosen[0][0], size=12)
            if len(chosen) > 1:
                pdf.set_fallback_fonts(
                    [family for family, _ in chosen[1:]], exact_match=False
                )
        else:
            pdf.set_font(pdf_fonts.CORE_FONT, size=12)

        for sentence in NOISE_SENTENCES[:2]:
            pdf.multi_cell(0, 10, sentence, new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 10, text, new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 10, NOISE_SENTENCES[2], new_x="LMARGIN", new_y="NEXT")

        buf = io.BytesIO()
        pdf.output(buf)
        return buf.getvalue()

    @staticmethod
    def _build_xlsx(text: str) -> bytes:
        if not HAS_OPENPYXL:
            raise RuntimeError("openpyxl is required for XLSX generation")
        wb = openpyxl.Workbook()
        ws = wb.active
        ws["A1"] = NOISE_SENTENCES[0]
        ws["A2"] = text
        ws["A3"] = NOISE_SENTENCES[1]
        ws["B1"] = "Document ID"
        ws["B2"] = "12345"
        ws["C1"] = "Classification"
        ws["C2"] = "Confidential"
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()
