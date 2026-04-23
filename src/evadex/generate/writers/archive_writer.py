"""ZIP / nested-ZIP / 7z archive writers for evadex generate.

These produce realistic multi-file archives with sensitive data spread
across the inner files — exactly the shape Siphon's archive extractors
in ``crates/siphon-core/src/extractors.rs`` are designed to walk.

**Findings worth knowing while reading these writers:**

* ``extract_zip_archive`` in extractors.rs only walks ``*.xml`` entries
  for OOXML formats (docx / xlsx / pptx). For a plain ``.zip`` whose
  contents are ``.txt`` / ``.csv`` / ``.json``, format is detected as
  ``"zip"`` and the per-format match yields ``None`` — meaning text
  inside plain ZIPs is *not extracted* by Siphon. Generating those
  fixtures still has value: it documents the gap and produces test
  data for any future patch.
* The 7z extractor *does* extract text from txt/csv/json/etc inside
  the archive (1 MB per file, 100 KB content cap). 7z fixtures should
  exercise detection cleanly.
* No nested-archive recursion is performed by any extractor — a ZIP
  inside a ZIP yields only the inner zip's filename in the parent
  walk, never its contents.
* Caps to stay under: 100 MB input file, 500 MB total uncompressed,
  100 MB per entry, 10 000 entries, 100:1 compression ratio.
"""
from __future__ import annotations

import io
import json
import random
import zipfile

from evadex.generate.generator import GeneratedEntry


SEVENZIP_DEPS_HINT = (
    "7-Zip generation requires optional dependencies. "
    "Install with: pip install evadex[archives]"
)


# ── Inner-file naming ──────────────────────────────────────────────────────

# Realistic banking filenames — the kind a DLP scanner will see in a
# real production file share, not "test1.txt", "test2.txt".
_INNER_FILE_TEMPLATES: list[tuple[str, str]] = [
    ("customer_data.csv", "csv"),
    ("transactions_q1.csv", "csv"),
    ("transactions_q2.csv", "csv"),
    ("kyc_records.csv", "csv"),
    ("account_summary.txt", "txt"),
    ("audit_log.txt", "txt"),
    ("report_q1.txt", "txt"),
    ("compliance_findings.txt", "txt"),
    ("config.json", "json"),
    ("payment_batch.json", "json"),
    ("notes.txt", "txt"),
    ("README.txt", "txt"),
]


def _split_entries(
    entries: list[GeneratedEntry], n_files: int
) -> list[list[GeneratedEntry]]:
    """Distribute entries roughly evenly across n_files."""
    if n_files <= 0:
        return [entries]
    buckets: list[list[GeneratedEntry]] = [[] for _ in range(n_files)]
    for i, e in enumerate(entries):
        buckets[i % n_files].append(e)
    return buckets


def _render_csv(entries: list[GeneratedEntry]) -> str:
    """One CSV file's worth of payload data. Header + rows."""
    lines = [
        "customer_id,category,sensitive_value,evasion_technique,context"
    ]
    for i, e in enumerate(entries, 1):
        # Quote any value containing commas or quotes — the DLP scanner
        # needs valid CSV to walk row-by-row.
        val = '"' + e.variant_value.replace('"', '""').replace("\n", " ") + '"'
        ctx = '"' + e.embedded_text.replace('"', '""').replace("\n", " ") + '"'
        tech = e.technique or ""
        lines.append(f"CUST-{i:06d},{e.category.value},{val},{tech},{ctx}")
    return "\n".join(lines) + "\n"


def _render_txt(entries: list[GeneratedEntry]) -> str:
    """Plain-text dump — sentences with embedded values."""
    lines = ["CONFIDENTIAL — INTERNAL USE ONLY", "=" * 60, ""]
    for e in entries:
        lines.append(e.embedded_text)
    return "\n".join(lines) + "\n"


def _render_json(entries: list[GeneratedEntry]) -> str:
    """Structured JSON dump — array of records."""
    records = []
    for i, e in enumerate(entries, 1):
        records.append({
            "id": i,
            "category": e.category.value,
            "value": e.variant_value,
            "context": e.embedded_text,
            "technique": e.technique,
        })
    return json.dumps(records, indent=2, ensure_ascii=False) + "\n"


_RENDERERS = {
    "csv": _render_csv,
    "txt": _render_txt,
    "json": _render_json,
}


def _build_inner_files(
    entries: list[GeneratedEntry], rng: random.Random
) -> list[tuple[str, bytes]]:
    """Produce a list of (filename, bytes) inner files distributing
    *entries* across realistic banking filenames."""
    n_files = max(1, min(len(_INNER_FILE_TEMPLATES), len(entries) // 5 or 1))
    file_specs = rng.sample(_INNER_FILE_TEMPLATES, n_files)
    buckets = _split_entries(entries, n_files)

    out: list[tuple[str, bytes]] = []
    for (fname, kind), bucket in zip(file_specs, buckets):
        renderer = _RENDERERS[kind]
        text = renderer(bucket)
        out.append((fname, text.encode("utf-8")))
    return out


# ── ZIP ────────────────────────────────────────────────────────────────────

def write_zip(entries: list[GeneratedEntry], path: str) -> None:
    """Plain ZIP archive containing 4–12 inner files (csv/txt/json) with
    sensitive data spread across them.

    Note: Siphon's plain-ZIP extractor only walks ``*.xml`` entries
    (see module docstring). Use 7z if you need the test corpus to
    actually be scanned end to end.
    """
    rng = random.Random(42)
    inner = _build_inner_files(entries, rng)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for fname, data in inner:
            z.writestr(fname, data)
        # Manifest so a human reader can see at a glance what's inside —
        # also gives the scanner a small XML payload (Siphon walks .xml).
        manifest = (
            "<manifest>\n"
            f"  <generated>evadex</generated>\n"
            f"  <file_count>{len(inner)}</file_count>\n"
            "  <classification>CONFIDENTIAL</classification>\n"
            "</manifest>\n"
        )
        z.writestr("manifest.xml", manifest)


def write_zip_nested(entries: list[GeneratedEntry], path: str) -> None:
    """ZIP-inside-ZIP, three levels deep. Sensitive data lives in the
    deepest archive only — exercises recursive archive extraction
    (which Siphon currently does not perform).

    Layout::

        outer.zip
          ├── outer_README.txt          (no sensitive data)
          └── level1.zip
                ├── level1_notes.txt    (no sensitive data)
                └── level2.zip
                      ├── level2_index.txt
                      └── level3.zip
                            ├── customer_data.csv  ← sensitive payload
                            ├── audit_log.txt      ← sensitive payload
                            └── …
    """
    rng = random.Random(42)
    inner_files = _build_inner_files(entries, rng)

    # Build the deepest archive first, in memory, then nest outward.
    def _zip_bytes(files: list[tuple[str, bytes]]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for fname, data in files:
                z.writestr(fname, data)
        return buf.getvalue()

    level3 = _zip_bytes(inner_files)
    level2 = _zip_bytes([
        ("level2_index.txt",
         b"Contents indexed for compliance review.\n"
         b"See level3.zip for the payload corpus.\n"),
        ("level3.zip", level3),
    ])
    level1 = _zip_bytes([
        ("level1_notes.txt",
         b"Compliance notes attached. Inner archive sealed.\n"),
        ("level2.zip", level2),
    ])
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "outer_README.txt",
            b"This archive contains nested archives for DLP "
            b"recursive-extraction testing. Sensitive data is "
            b"in level3.zip three levels down.\n",
        )
        z.writestr("level1.zip", level1)


# ── 7z ─────────────────────────────────────────────────────────────────────

def write_7z(entries: list[GeneratedEntry], path: str) -> None:
    """7-Zip archive with the same inner-file structure as ``write_zip``
    but compressed with LZMA2. Siphon's 7z extractor *does* read text
    files (txt / csv / json / …) up to 1 MB each, so this format is
    the right choice when you want detection to actually fire."""
    try:
        import py7zr  # type: ignore
    except ImportError as exc:
        raise RuntimeError(SEVENZIP_DEPS_HINT) from exc

    rng = random.Random(42)
    inner = _build_inner_files(entries, rng)
    with py7zr.SevenZipFile(path, "w") as a:
        for fname, data in inner:
            a.writestr(data, fname)
