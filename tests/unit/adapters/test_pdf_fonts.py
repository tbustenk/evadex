"""The PDF fixture embeds real fonts, and refuses what none of them can draw.

Until 3.42.0 ``_build_pdf`` asked for a "DejaVu" font fpdf2 does not ship,
caught the error and fell back to Helvetica with ``errors="replace"``, so
every character outside Latin-1 reached the scanner as ``?``. With a real
TrueType font fpdf2 has the opposite failure: a glyph the font lacks is
dropped with a log warning. Both make the pdf figure a statement about the
fixture. These tests pin the replacement: fonts are found and their coverage
read, the engine is told what the fixture can carry, and the builder never
substitutes.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from evadex.adapters.dlpscan import pdf_fonts
from evadex.adapters.dlpscan.pdf_fonts import (
    CORE_CHARSET,
    ENV_VAR,
    PdfFonts,
    candidate_paths,
    discover,
)
from evadex.core.representable import UnrepresentableError, pdf_charset, representable


@pytest.fixture(autouse=True)
def _fresh_discovery():
    pdf_fonts.reset()
    yield
    pdf_fonts.reset()


# ── where to look ──────────────────────────────────────────────────────────────


def test_env_var_paths_come_first_in_order_and_deduplicated(tmp_path):
    a, b = tmp_path / "a.ttf", tmp_path / "b.ttf"
    env = {ENV_VAR: os.pathsep.join([str(a), str(b), str(a)])}
    paths = candidate_paths(env=env, platform="linux")
    assert paths[:2] == [a, b]
    assert paths.count(a) == 1
    # The platform list follows.
    assert any(p.name == "DejaVuSans.ttf" for p in paths[2:])


def test_windows_candidates_live_under_the_font_directories(tmp_path):
    env = {"WINDIR": str(tmp_path / "win"), "LOCALAPPDATA": str(tmp_path / "local")}
    paths = candidate_paths(env=env, platform="win32")
    assert paths and all(
        p.parent
        in {
            tmp_path / "win" / "Fonts",
            tmp_path / "local" / "Microsoft" / "Windows" / "Fonts",
        }
        for p in paths
    )
    assert paths[0].name == "arial.ttf"


def test_macos_and_linux_lists_are_absolute():
    for platform in ("darwin", "linux"):
        for p in candidate_paths(env={}, platform=platform):
            assert p.as_posix().startswith("/"), (platform, p)


# ── what was found ─────────────────────────────────────────────────────────────


def test_nothing_usable_means_the_core_font_and_latin_1(tmp_path):
    missing = tmp_path / "nope.ttf"
    garbage = tmp_path / "bad.ttf"
    garbage.write_bytes(b"not a font")
    wrong_suffix = tmp_path / "notes.txt"
    wrong_suffix.write_bytes(b"x")
    found = discover([missing, garbage, wrong_suffix])
    assert not found.embedded
    assert found.names == ("Helvetica",)
    assert found.charset == CORE_CHARSET
    assert ord("A") in found.charset and ord("é") in found.charset
    assert ord("€") not in found.charset and 0x0661 not in found.charset
    assert found.fonts_for("anything") == []


def test_coverage_is_the_union_and_fonts_for_picks_the_fewest(tmp_path, monkeypatch):
    latin = tmp_path / "latin.ttf"
    arabic = tmp_path / "arabic.ttf"
    khmer = tmp_path / "khmer.ttf"
    for p in (latin, arabic, khmer):
        p.write_bytes(b"stub")
    cov = {
        latin: frozenset(map(ord, "SN0123456789- ")),
        arabic: frozenset(range(0x0660, 0x066A)) | frozenset(map(ord, "SN -")),
        khmer: frozenset(range(0x17E0, 0x17EA)),
    }
    monkeypatch.setattr(pdf_fonts, "glyph_coverage", lambda p: cov[p])

    found = discover([latin, arabic, khmer])
    assert found.embedded and found.paths == (latin, arabic, khmer)
    assert found.charset == cov[latin] | cov[arabic] | cov[khmer] | CORE_CHARSET
    assert found.families == ("EvadexPdf0", "EvadexPdf1", "EvadexPdf2")

    # ASCII: the primary alone. Arabic-Indic: primary plus the one font that
    # adds the missing glyphs. Khmer: primary plus khmer, not arabic.
    assert [p for _, p in found.fonts_for("SSN 123-45-6789")] == [latin]
    assert [p for _, p in found.fonts_for("SSN ١٢٣-٤٥-٦٧٨٩")] == [latin, arabic]
    assert [p for _, p in found.fonts_for("SSN ១២៣")] == [latin, khmer]


def test_discovery_is_cached_and_registered_with_the_engine(tmp_path, monkeypatch):
    calls = []

    def fake_discover(paths=None):
        calls.append(1)
        return PdfFonts((), CORE_CHARSET)

    monkeypatch.setattr(pdf_fonts, "discover", fake_discover)
    assert pdf_fonts.fonts() is pdf_fonts.fonts()
    assert len(calls) == 1
    # file_builder registered pdf_fonts.charset as the provider at import.
    import evadex.adapters.dlpscan.file_builder  # noqa: F401

    assert pdf_charset() == CORE_CHARSET


# ── the builder ────────────────────────────────────────────────────────────────


def _core_only(monkeypatch):
    monkeypatch.setattr(
        pdf_fonts, "discover", lambda paths=None: PdfFonts((), CORE_CHARSET)
    )


def test_builder_refuses_what_no_font_can_draw_instead_of_substituting(monkeypatch):
    pytest.importorskip("fpdf")
    _core_only(monkeypatch)
    from evadex.adapters.dlpscan.file_builder import FileBuilder

    assert not representable("SSN ١٢٣-٤٥-٦٧٨٩", "pdf")
    with pytest.raises(UnrepresentableError) as exc:
        FileBuilder.build("SSN ١٢٣-٤٥-٦٧٨٩", "pdf")
    assert "U+0661" in str(exc.value) and "pdf" in str(exc.value)

    # Zero-width joiners are outside Latin-1 too; before 3.42.0 they became '?'.
    assert not representable("1‍2‍3", "pdf")


def test_builder_with_the_core_font_still_builds_latin_1(monkeypatch):
    pytest.importorskip("fpdf")
    _core_only(monkeypatch)
    from evadex.adapters.dlpscan.file_builder import FileBuilder

    data, _ = FileBuilder.build(
        "Facture: carte 4532 0151 1283 0366, montant 12 éléments", "pdf"
    )
    assert data.startswith(b"%PDF")
    assert b"/FontFile2" not in data, "the core font is not embedded"


def test_tab_and_controls_have_no_glyph_in_any_font(monkeypatch):
    _core_only(monkeypatch)
    pdf_fonts.fonts()
    assert not representable("1234\t5678", "pdf")
    assert not representable("12\x1e34", "pdf")
    assert representable("1234\n5678", "pdf"), "a newline is a line break, not a glyph"


def _any_real_font() -> Path | None:
    for p in candidate_paths():
        if p.is_file() and p.suffix.lower() in {".ttf", ".otf"}:
            return p
    return None


def test_a_real_font_is_embedded_and_widens_what_pdf_carries(monkeypatch):
    """Runs only where a candidate font exists (every dev box and the
    Docker image; CI runners vary). Proves the TrueType path end to end:
    the font is embedded, and a character it covers is carried as itself
    rather than refused or replaced."""
    pytest.importorskip("fpdf")
    font = _any_real_font()
    if font is None:
        pytest.skip("no candidate TrueType font on this machine")
    monkeypatch.setenv(ENV_VAR, str(font))
    pdf_fonts.reset()
    found = pdf_fonts.fonts()
    assert found.embedded and found.paths[0] == font
    assert CORE_CHARSET < found.charset
    assert ord("€") in found.charset, f"{font.name} should cover the euro sign"

    from evadex.adapters.dlpscan.file_builder import FileBuilder

    data, _ = FileBuilder.build("Betrag 12,50 € auf Karte 4532015112830366", "pdf")
    assert data.startswith(b"%PDF")
    assert b"/FontFile2" in data or b"/FontFile3" in data, "the font is embedded"

    # Latin-1 text keeps the core font even when TrueType fonts are present:
    # cheaper, and the same fixture every earlier baseline measured.
    data, _ = FileBuilder.build("Facture: carte 4532015112830366, 12 éléments", "pdf")
    assert b"/FontFile2" not in data and b"/FontFile3" not in data
