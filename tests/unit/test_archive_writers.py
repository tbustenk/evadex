"""Tests for the archive / message-format writers added in v3.12.0."""
from __future__ import annotations

import io
import mailbox
import pathlib
import zipfile

import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers.archive_writer import (
    SEVENZIP_DEPS_HINT,
    write_zip,
    write_zip_nested,
    write_7z,
)
from evadex.generate.writers.ics_writer import write_ics
from evadex.generate.writers.mbox_writer import write_mbox
from evadex.generate.writers.warc_writer import write_warc


def _entry(
    cat: PayloadCategory,
    value: str,
    technique: str | None = None,
) -> GeneratedEntry:
    return GeneratedEntry(
        category=cat,
        plain_value=value,
        variant_value=value,
        technique=technique,
        generator_name=None,
        transform_name=None,
        has_keywords=False,
        embedded_text=f"Reference: {value}",
    )


@pytest.fixture
def entries() -> list[GeneratedEntry]:
    return [
        _entry(PayloadCategory.CREDIT_CARD, f"4532015112{i:06d}")
        for i in range(20)
    ] + [
        _entry(PayloadCategory.SIN, f"046 454 {i:03d}") for i in range(10)
    ]


# ── zip ────────────────────────────────────────────────────────────────────

def test_write_zip_produces_valid_archive(tmp_path: pathlib.Path, entries):
    out = tmp_path / "test.zip"
    write_zip(entries, str(out))

    assert out.exists() and out.stat().st_size > 0
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    # Always at least one inner file plus the manifest.
    assert len(names) >= 2
    assert "manifest.xml" in names


def test_write_zip_inner_files_have_realistic_names(tmp_path, entries):
    out = tmp_path / "test.zip"
    write_zip(entries, str(out))
    with zipfile.ZipFile(out) as z:
        names = z.namelist()
    # All inner-file names should look like banking artifacts, not test1.txt.
    realistic = {"customer_data.csv", "transactions_q1.csv", "kyc_records.csv",
                 "audit_log.txt", "report_q1.txt", "config.json", "notes.txt",
                 "README.txt", "compliance_findings.txt", "transactions_q2.csv",
                 "account_summary.txt", "payment_batch.json", "manifest.xml"}
    assert set(names).issubset(realistic), f"Unexpected names: {names}"


def test_write_zip_inner_files_carry_payload(tmp_path, entries):
    """Sensitive values must actually be present inside the archive —
    otherwise the fixture is useless for DLP testing."""
    out = tmp_path / "test.zip"
    write_zip(entries, str(out))
    with zipfile.ZipFile(out) as z:
        joined = b"".join(z.read(n) for n in z.namelist())
    # At least the first credit-card value should appear somewhere.
    assert b"4532015112000000" in joined


# ── zip_nested ─────────────────────────────────────────────────────────────

def test_write_zip_nested_three_levels(tmp_path, entries):
    out = tmp_path / "nested.zip"
    write_zip_nested(entries, str(out))

    with zipfile.ZipFile(out) as outer:
        assert "level1.zip" in outer.namelist()
        with zipfile.ZipFile(io.BytesIO(outer.read("level1.zip"))) as l1:
            assert "level2.zip" in l1.namelist()
            with zipfile.ZipFile(io.BytesIO(l1.read("level2.zip"))) as l2:
                assert "level3.zip" in l2.namelist()
                with zipfile.ZipFile(io.BytesIO(l2.read("level3.zip"))) as l3:
                    assert len(l3.namelist()) >= 1


def test_write_zip_nested_payload_only_in_innermost(tmp_path, entries):
    """The whole point of zip_nested is that the payload is only at the
    bottom — the outer levels must not carry sensitive data."""
    out = tmp_path / "nested.zip"
    write_zip_nested(entries, str(out))

    with zipfile.ZipFile(out) as outer:
        outer_concat = b"".join(
            outer.read(n) for n in outer.namelist() if not n.endswith(".zip")
        )
    assert b"4532015112000000" not in outer_concat


# ── 7z ─────────────────────────────────────────────────────────────────────

def test_write_7z_produces_valid_archive(tmp_path, entries):
    py7zr = pytest.importorskip("py7zr")
    out = tmp_path / "test.7z"
    write_7z(entries, str(out))

    assert out.exists() and out.stat().st_size > 0
    with py7zr.SevenZipFile(out) as a:
        names = a.getnames()
    assert len(names) >= 1


def test_write_7z_missing_dep_raises_friendly_runtime_error(monkeypatch, tmp_path, entries):
    """If py7zr isn't installed, the writer must raise a RuntimeError
    carrying the install hint — not a bare ImportError."""
    import sys
    monkeypatch.setitem(sys.modules, "py7zr", None)
    with pytest.raises(RuntimeError) as exc:
        write_7z(entries, str(tmp_path / "x.7z"))
    assert "evadex[archives]" in str(exc.value) or SEVENZIP_DEPS_HINT in str(exc.value)


# ── mbox ───────────────────────────────────────────────────────────────────

def test_write_mbox_message_count_matches_entries(tmp_path, entries):
    out = tmp_path / "test.mbox"
    write_mbox(entries, str(out))

    box = mailbox.mbox(str(out))
    msgs = list(box)
    assert len(msgs) == len(entries)


def test_write_mbox_mixes_base64_and_plain_bodies(tmp_path, entries):
    out = tmp_path / "test.mbox"
    write_mbox(entries, str(out))

    text = out.read_text(encoding="utf-8")
    assert "Content-Transfer-Encoding: base64" in text
    assert "Content-Transfer-Encoding: 7bit" in text


def test_write_mbox_payload_appears_in_messages(tmp_path, entries):
    out = tmp_path / "test.mbox"
    write_mbox(entries, str(out))
    text = out.read_text(encoding="utf-8")
    # First entry's plain value should be present (or its base64 encoding —
    # the deterministic base64-every-3rd ordering means message 1 is plain).
    assert "4532015112000000" in text


# ── ics ────────────────────────────────────────────────────────────────────

def test_write_ics_event_count_matches_entries(tmp_path, entries):
    out = tmp_path / "test.ics"
    write_ics(entries, str(out))
    text = out.read_text(encoding="utf-8")
    assert text.count("BEGIN:VEVENT") == len(entries)
    assert text.count("END:VEVENT") == len(entries)
    assert text.startswith("BEGIN:VCALENDAR")
    assert text.rstrip().endswith("END:VCALENDAR")


def test_write_ics_uses_crlf(tmp_path, entries):
    """RFC 5545 mandates CRLF — many parsers will reject LF-only output."""
    out = tmp_path / "test.ics"
    write_ics(entries, str(out))
    raw = out.read_bytes()
    assert b"\r\n" in raw


# ── warc ───────────────────────────────────────────────────────────────────

def test_write_warc_record_count(tmp_path, entries):
    out = tmp_path / "test.warc"
    write_warc(entries, str(out))
    raw = out.read_bytes()
    # Count records via WARC-Record-ID — exactly one per record header,
    # unlike "WARC/1.1" which also appears in the warcinfo body.
    assert raw.count(b"WARC-Record-ID:") == len(entries) + 1
    assert b"WARC-Type: warcinfo" in raw
    assert raw.count(b"WARC-Type: response") == len(entries)


def test_write_warc_payload_in_html_body(tmp_path, entries):
    out = tmp_path / "test.warc"
    write_warc(entries, str(out))
    raw = out.read_bytes()
    assert b"4532015112000000" in raw


# ── archive_evasion variant generator ──────────────────────────────────────

def test_archive_evasion_emits_all_four_techniques():
    from evadex.variants.archive_evasion import (
        ARCHIVE_EVASION_TECHNIQUES,
        ArchiveEvasionGenerator,
    )
    gen = ArchiveEvasionGenerator()
    techniques = {v.technique for v in gen.generate("4532015112830366")}
    assert techniques == set(ARCHIVE_EVASION_TECHNIQUES)


def test_archive_evasion_skipped_for_empty_value():
    from evadex.variants.archive_evasion import ArchiveEvasionGenerator
    assert list(ArchiveEvasionGenerator().generate("")) == []


def test_archive_evasion_not_in_random_pool():
    """archive_evasion must be auto_applicable=False so its container-only
    markers do not leak into random text-pipeline selection."""
    from evadex.variants.archive_evasion import ArchiveEvasionGenerator
    assert ArchiveEvasionGenerator.auto_applicable is False
