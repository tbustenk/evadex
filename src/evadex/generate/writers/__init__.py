"""Format-specific document writers for evadex generate."""
from __future__ import annotations

from typing import Callable, Optional
from evadex.generate.generator import GeneratedEntry

# Module-level config for template/noise/density — set by CLI before writing.
_active_template: str = "generic"
_active_noise_level: str = "medium"
_active_density: str = "medium"
_active_seed: Optional[int] = None
_active_barcode_type: str = "qr"
_active_language: str = "en"


def set_writer_config(
    template: str = "generic",
    noise_level: str = "medium",
    density: str = "medium",
    seed: Optional[int] = None,
    barcode_type: str = "qr",
    language: str = "en",
) -> None:
    """Set template/noise config for subsequent writer calls."""
    global _active_template, _active_noise_level, _active_density, _active_seed
    global _active_barcode_type, _active_language
    _active_template = template
    _active_noise_level = noise_level
    _active_density = density
    _active_seed = seed
    _active_barcode_type = barcode_type
    _active_language = language


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
    if fmt == "eml":
        from evadex.generate.writers.eml_writer import write_eml
        return write_eml
    if fmt == "msg":
        from evadex.generate.writers.msg_writer import write_msg
        return write_msg
    if fmt == "json":
        from evadex.generate.writers.json_writer import write_json
        return write_json
    if fmt == "xml":
        from evadex.generate.writers.xml_writer import write_xml
        return write_xml
    if fmt == "sql":
        from evadex.generate.writers.sql_writer import write_sql
        return write_sql
    if fmt == "log":
        from evadex.generate.writers.log_writer import write_log
        return write_log
    if fmt == "png":
        from evadex.generate.writers.barcode_writer import write_png
        return write_png
    if fmt == "jpg":
        from evadex.generate.writers.barcode_writer import write_jpg
        return write_jpg
    if fmt == "multi_barcode_png":
        from evadex.generate.writers.barcode_writer import write_multi_barcode_png
        return write_multi_barcode_png
    if fmt == "edm_json":
        from evadex.generate.writers.edm_json_writer import write_edm_json
        return write_edm_json
    if fmt == "parquet":
        from evadex.generate.writers.parquet_writer import write_parquet
        return write_parquet
    if fmt == "sqlite":
        from evadex.generate.writers.sqlite_writer import write_sqlite
        return write_sqlite
    if fmt == "zip":
        from evadex.generate.writers.archive_writer import write_zip
        return write_zip
    if fmt == "zip_nested":
        from evadex.generate.writers.archive_writer import write_zip_nested
        return write_zip_nested
    if fmt == "7z":
        from evadex.generate.writers.archive_writer import write_7z
        return write_7z
    if fmt == "mbox":
        from evadex.generate.writers.mbox_writer import write_mbox
        return write_mbox
    if fmt == "ics":
        from evadex.generate.writers.ics_writer import write_ics
        return write_ics
    if fmt == "warc":
        from evadex.generate.writers.warc_writer import write_warc
        return write_warc
    raise ValueError(f"Unknown format: {fmt!r}")
