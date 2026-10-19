"""The fonts the PDF fixture is built with, and which characters they can draw.

A PDF text string is a run of glyphs from an embedded font, so a PDF fixture
can carry a variant only if some font it embeds has a glyph for every
character in it. fpdf2's core fonts (Helvetica and friends) are not embedded
and cover Latin-1 and nothing else; fpdf2 raises on anything outside it.
Until 3.42.0 the fixture asked for a "DejaVu" font fpdf2 does not ship,
caught the error, and fell back to Helvetica with ``errors="replace"`` — so
every Arabic-Indic digit, zero-width joiner and homoglyph became ``?`` before
the scanner saw the file. On the 2026-10-15 northam re-baseline that was
2,980 of the 3,534 variants Siphon detected in text and missed in PDF: the
fixture, not the extractor.

A real TrueType font fixes most of that, but not by itself. fpdf2 does not
raise for a glyph a TrueType font lacks; it logs a warning and **drops the
character**, so a fullwidth or Khmer digit would vanish from the fixture and
the submission would test an empty value. Hence ``charset``: the union of
the embedded fonts' cmaps, which :mod:`evadex.core.representable` consults so
the engine leaves such ``(variant, pdf)`` pairs out of the run and says so,
as it does for control characters in XML containers.

Fonts are found, not shipped. ``EVADEX_PDF_FONTS`` (``os.pathsep``-separated
``.ttf`` / ``.otf`` / ``.ttc`` paths) is consulted first, then a short list
of fonts commonly present on each platform. With none found the fixture
uses Helvetica and the pdf strategy carries Latin-1 only, which
``evadex doctor`` reports.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

log = logging.getLogger(__name__)

ENV_VAR = "EVADEX_PDF_FONTS"

#: fpdf2's built-in font; used when no TrueType font is found.
CORE_FONT = "Helvetica"

#: What fpdf2 can encode for a core font: Latin-1's printable range
#: (probed 2026-10-16 against fpdf2 2.8.7 — U+0080–U+00FF accepted, U+20AC
#: refused). The C1 controls encode but draw nothing, so they are left out.
CORE_CHARSET: frozenset[int] = frozenset(range(0x20, 0x7F)) | frozenset(
    range(0xA0, 0x100)
)

#: Stop after this many fonts; each one found widens the charset and costs a
#: cmap read at discovery. Everything after the first few is per-script
#: coverage.
MAX_FONTS = 12

# Preference order matters: the first font found is the primary, the rest
# are fpdf2 fallbacks consulted only for glyphs the primary lacks.
_LINUX = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/TTF/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/noto/NotoSans-Regular.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSans.ttf",
    "/usr/share/fonts/truetype/freefont/FreeSerif.ttf",
    "/usr/share/fonts/gnu-free/FreeSerif.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansKhmer-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMyanmar-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansTibetan-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMongolian-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansNKo-Regular.ttf",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
)
_MACOS = (
    "/Library/Fonts/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/Library/Fonts/DejaVuSans.ttf",
    "/System/Library/Fonts/Supplemental/Khmer Sangam MN.ttc",
    "/System/Library/Fonts/Supplemental/Myanmar Sangam MN.ttc",
    "/System/Library/Fonts/Supplemental/Kailasa.ttc",
)
# Relative to each Windows font directory. No single Windows font covers the
# scripts the regional-digit techniques use, so this is one font per script
# family after Arial.
_WINDOWS = (
    "arial.ttf",  # Latin, Greek, Cyrillic, Arabic (incl. Arabic-Indic digits), Hebrew
    "segoeui.ttf",
    "seguisym.ttf",  # symbols, zero-width and bidi controls
    "Nirmala.ttc",  # Devanagari, Bengali and the other Indic scripts
    "LeelawUI.ttf",  # Thai, Lao, Khmer, Buginese
    "mmrtext.ttf",  # Myanmar
    "monbaiti.ttf",  # Mongolian
    "himalaya.ttf",  # Tibetan
    "ebrima.ttf",  # N'Ko, Tifinagh, Vai, Osmanya
    "malgun.ttf",  # Korean, and the fullwidth forms
    "msgothic.ttc",  # Japanese, and the fullwidth forms
)

_FONT_SUFFIXES = frozenset({".ttf", ".otf", ".ttc"})


@dataclass(frozen=True)
class PdfFonts:
    """The fonts a PDF fixture embeds, and the code points they cover between them."""

    #: Empty when no TrueType font was found and the core font is in use.
    paths: tuple[Path, ...]
    #: Every code point at least one of ``paths`` has a glyph for (or
    #: :data:`CORE_CHARSET` for the core font).
    charset: frozenset[int]
    #: Per-font coverage, parallel to ``paths``; what the builder uses to pick
    #: the fewest fonts that cover a given text.
    coverage: tuple[frozenset[int], ...] = ()

    @property
    def embedded(self) -> bool:
        return bool(self.paths)

    @property
    def families(self) -> tuple[str, ...]:
        """fpdf2 family names, one per path. Stable, ASCII, and ours."""
        return tuple(f"EvadexPdf{i}" for i in range(len(self.paths)))

    @property
    def names(self) -> tuple[str, ...]:
        """Human-readable: the file stems, or the core font."""
        return tuple(p.stem for p in self.paths) or (CORE_FONT,)

    def fonts_for(self, text: str) -> list[tuple[str, Path]]:
        """The fewest ``(family, path)`` pairs, in preference order, that
        between them draw every character of ``text`` the fonts can draw.

        The primary is always first — it carries the fixture's ASCII prose —
        and a fallback is added only for a character none of the fonts chosen
        so far has. Adding a font to an fpdf2 document means parsing it, so
        this keeps an ASCII fixture at one font and an Arabic-Indic one at
        two, instead of embedding every font found on the machine.
        """
        if not self.paths:
            return []
        chosen = [0]
        covered = set(self.coverage[0]) if self.coverage else set()
        wanted = {ord(c) for c in text if not c.isspace()}
        for i in range(1, len(self.paths)):
            if wanted <= covered:
                break
            cov = self.coverage[i] if i < len(self.coverage) else frozenset()
            if wanted & (cov - covered):
                chosen.append(i)
                covered |= cov
        return [(self.families[i], self.paths[i]) for i in chosen]


def candidate_paths(
    env: Mapping[str, str] | None = None,
    platform: str | None = None,
) -> list[Path]:
    """Where to look, in order: ``EVADEX_PDF_FONTS`` first, then the platform list.

    Pure function of its arguments so it can be tested without touching the
    machine; the defaults are the real environment and platform.
    """
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    out: list[Path] = []
    seen: set[str] = set()

    def add(p: Path) -> None:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)

    for item in env.get(ENV_VAR, "").split(os.pathsep):
        if item.strip():
            add(Path(item.strip()).expanduser())

    if platform.startswith("win"):
        dirs = [Path(env.get("WINDIR") or r"C:\Windows") / "Fonts"]
        local = env.get("LOCALAPPDATA")
        if local:
            dirs.append(Path(local) / "Microsoft" / "Windows" / "Fonts")
        for d in dirs:
            for name in _WINDOWS:
                add(d / name)
    elif platform == "darwin":
        for p in _MACOS:
            add(Path(p))
    else:
        for p in _LINUX:
            add(Path(p))
    return out


def glyph_coverage(path: Path) -> frozenset[int]:
    """The code points ``path`` has a glyph for, from its best cmap subtable.

    For a collection (``.ttc``) the first face is read, which is also the
    face fpdf2 embeds (``collection_font_number=0``).
    """
    from fontTools.ttLib import (
        TTFont,
    )  # a dependency of fpdf2, so always present with it

    kwargs = {"fontNumber": 0} if path.suffix.lower() == ".ttc" else {}
    with TTFont(str(path), lazy=True, **kwargs) as font:
        cmap = font.getBestCmap() or {}
        return frozenset(cmap)


def discover(paths: list[Path] | None = None) -> PdfFonts:
    """Read the cmap of every usable candidate and return what was found.

    A missing file, an unexpected suffix or a font fontTools cannot read is
    skipped with a log line; it never fails the run. With nothing usable the
    result names no paths and carries :data:`CORE_CHARSET`.
    """
    found: list[Path] = []
    coverage: list[frozenset[int]] = []
    charset: set[int] = set()
    for p in candidate_paths() if paths is None else paths:
        if p.suffix.lower() not in _FONT_SUFFIXES or not p.is_file():
            continue
        try:
            cov = glyph_coverage(p)
        except Exception as exc:  # noqa: BLE001 — a bad font file is a skip, not a crash
            log.warning("PDF fixture font %s skipped: %s", p, exc)
            continue
        if not cov:
            continue
        found.append(p)
        coverage.append(cov)
        charset |= cov
        if len(found) >= MAX_FONTS:
            break
    if not found:
        return PdfFonts((), CORE_CHARSET)
    # Latin-1 is always carried: the builder draws it with the core font
    # whatever was found, so the charset says so even if an operator's
    # EVADEX_PDF_FONTS points at a font that lacks it.
    return PdfFonts(tuple(found), frozenset(charset) | CORE_CHARSET, tuple(coverage))


def core_can_draw(text: str) -> bool:
    """Can fpdf2's core font render ``text`` as itself (line breaks aside)?

    The builder uses the core font whenever it can: no font to parse, no
    subset to embed, about 2 ms a fixture against ~40 ms with a TrueType
    font — and the fixture for a Latin-1 value stays byte-for-byte the kind
    of PDF every run before 3.42.0 produced, so those figures still compare.
    """
    return all(ord(c) in CORE_CHARSET or c in "\n\r" for c in text)


_cached: PdfFonts | None = None


def fonts() -> PdfFonts:
    """The fonts in use, discovered once per process."""
    global _cached
    if _cached is None:
        _cached = discover()
        if _cached.embedded:
            log.info(
                "PDF fixture fonts: %s (%d code points)",
                ", ".join(_cached.names),
                len(_cached.charset),
            )
        else:
            log.warning(
                "no TrueType font found for the PDF fixture; using %s, so the pdf "
                "strategy carries Latin-1 only. Set %s to a Unicode .ttf to carry more.",
                CORE_FONT,
                ENV_VAR,
            )
    return _cached


def charset() -> frozenset[int]:
    """What the pdf strategy can carry; the provider registered with
    :func:`evadex.core.representable.register_pdf_charset`."""
    return fonts().charset


def reset() -> None:
    """Forget the discovered fonts (tests; or after changing ``EVADEX_PDF_FONTS``)."""
    global _cached
    _cached = None
