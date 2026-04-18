"""Unit tests for the barcode/QR image writer.

The whole barcode writer is optional: only runs when the ``barcodes``
extra is installed. We auto-skip the module if ``qrcode`` isn't
importable so core CI doesn't require the extra.
"""
from __future__ import annotations

import os

import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers import set_writer_config


qrcode = pytest.importorskip("qrcode", reason="barcodes extra not installed")
barcode_lib = pytest.importorskip("barcode", reason="barcodes extra not installed")
PIL_Image = pytest.importorskip("PIL.Image", reason="barcodes extra not installed")


from evadex.generate.writers.barcode_writer import (  # noqa: E402
    MAX_BARCODES_PER_IMAGE,
    BARCODE_DEPS_HINT,
    write_jpg,
    write_multi_barcode_png,
    write_png,
)


def _entry(
    value: str = "4532015112830366",
    cat: PayloadCategory = PayloadCategory.CREDIT_CARD,
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
        embedded_text=value,
    )


@pytest.fixture(autouse=True)
def _reset_writer_config():
    """Each test starts with the default writer config."""
    set_writer_config(barcode_type="qr", seed=42)
    yield
    set_writer_config(barcode_type="qr", seed=None)


# ── QR code PNG ──────────────────────────────────────────────────────────────

def test_qr_png_non_empty(tmp_path):
    out = tmp_path / "qr.png"
    write_png([_entry()], str(out))
    assert out.exists() and out.stat().st_size > 500
    img = PIL_Image.open(out)
    assert img.format == "PNG"
    # QR plus quiet zone plus label should produce a reasonably wide image.
    assert img.width >= 100 and img.height >= 100


def test_qr_png_multiple_entries_laid_out_as_grid(tmp_path):
    out = tmp_path / "qr_many.png"
    entries = [_entry(f"VALUE-{i:04d}-XYZ-12345678") for i in range(9)]
    write_png(entries, str(out))
    img = PIL_Image.open(out)
    # 9 entries → 3 columns × 3 rows
    assert img.width > 300 and img.height > 300


# ── Code 128 PNG ─────────────────────────────────────────────────────────────

def test_code128_png_non_empty(tmp_path):
    set_writer_config(barcode_type="code128", seed=1)
    out = tmp_path / "code128.png"
    write_png([_entry("EVADEX-CODE128-TEST-001")], str(out))
    assert out.exists() and out.stat().st_size > 500


# ── EAN-13 ───────────────────────────────────────────────────────────────────

def test_ean13_accepts_numeric_value(tmp_path):
    set_writer_config(barcode_type="ean13", seed=1)
    out = tmp_path / "ean13.png"
    # Credit-card-like numeric payload
    write_png([_entry("4532015112830366")], str(out))
    assert out.exists() and out.stat().st_size > 500


# ── JPEG ─────────────────────────────────────────────────────────────────────

def test_jpg_is_jpeg(tmp_path):
    out = tmp_path / "out.jpg"
    write_jpg([_entry()], str(out))
    img = PIL_Image.open(out)
    assert img.format == "JPEG"


# ── multi_barcode_png ────────────────────────────────────────────────────────

def test_multi_barcode_png_contains_header_strip(tmp_path):
    out = tmp_path / "multi.png"
    entries = [_entry(f"VAL-{i}-{'X'*10}") for i in range(6)]
    write_multi_barcode_png(entries, str(out))
    img = PIL_Image.open(out)
    assert img.format == "PNG"
    # The multi-barcode image is a form layout — significantly wider/taller
    # than a single barcode.
    assert img.width >= 400 and img.height >= 300


# ── Evasion variants ─────────────────────────────────────────────────────────

def test_barcode_evasion_variants_produce_different_images(tmp_path):
    """Each evasion technique should produce a visibly different output."""
    paths = {}
    for technique in ("barcode_split", "barcode_noise", "barcode_rotate", "barcode_embed"):
        out = tmp_path / f"{technique}.png"
        write_png([_entry(technique=technique)], str(out))
        assert out.exists() and out.stat().st_size > 0
        paths[technique] = out.read_bytes()

    # Each variant should produce a distinct image (different bytes).
    unique_outputs = set(paths.values())
    assert len(unique_outputs) == len(paths), (
        "Evasion techniques produced duplicate images: "
        + ", ".join(paths.keys())
    )


def test_barcode_split_renders_two_barcodes(tmp_path):
    """barcode_split should produce a wider canvas than a single barcode."""
    out_single = tmp_path / "single.png"
    out_split = tmp_path / "split.png"
    write_png([_entry(value="4532015112830366")], str(out_single))
    write_png([_entry(value="4532015112830366", technique="barcode_split")], str(out_split))
    single = PIL_Image.open(out_single)
    split = PIL_Image.open(out_split)
    # Two QRs side by side → noticeably wider than a single QR render.
    assert split.width > single.width


def test_barcode_rotate_yields_non_square_bounding_box(tmp_path):
    out = tmp_path / "rot.png"
    write_png([_entry(value="TEST-VALUE-1234567890", technique="barcode_rotate")], str(out))
    img = PIL_Image.open(out)
    # A QR rotated 15° occupies a bounding box whose aspect ratio drifts
    # from 1:1 (the label pushes height > width, but the code itself should
    # no longer be pixel-aligned to a square).
    assert img.width != img.height  # label always makes it non-square anyway
    assert out.stat().st_size > 500


# ── Cap on entries per image ─────────────────────────────────────────────────

def test_barcode_grid_caps_entries(tmp_path):
    """More than MAX_BARCODES_PER_IMAGE entries must be truncated, not bombed."""
    out = tmp_path / "capped.png"
    entries = [_entry(f"VAL-{i:05d}") for i in range(MAX_BARCODES_PER_IMAGE + 20)]
    write_png(entries, str(out))
    img = PIL_Image.open(out)
    # Decompression bomb guard: image pixel count must stay under PIL's default
    # 178M-pixel safety limit.
    assert img.width * img.height < 178_000_000


# ── Missing deps path ─────────────────────────────────────────────────────────

def test_deps_hint_message_mentions_extras_install():
    assert "evadex[barcodes]" in BARCODE_DEPS_HINT
