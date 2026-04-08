"""Format-specific document writers for evadex generate."""
from __future__ import annotations

from typing import Callable
from evadex.generate.generator import GeneratedEntry


def get_writer(fmt: str) -> Callable[[list[GeneratedEntry], str], None]:
    """Return the write function for the given format string."""
    if fmt == "csv":
        from evadex.generate.writers.csv_writer import write_csv
        return write_csv
    if fmt == "txt":
        from evadex.generate.writers.txt_writer import write_txt
        return write_txt
    if fmt == "xlsx":
        from evadex.generate.writers.xlsx_writer import write_xlsx
        return write_xlsx
    if fmt == "docx":
        from evadex.generate.writers.docx_writer import write_docx
        return write_docx
    if fmt == "pdf":
        from evadex.generate.writers.pdf_writer import write_pdf
        return write_pdf
    raise ValueError(f"Unknown format: {fmt!r}")
