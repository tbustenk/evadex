"""Synthetic generators for capital-markets identifiers.

Covers: CUSIP, CINS, SEDOL, ISIN, FIGI, LEI, ticker symbols, Reuters RIC,
VALOR (Swiss), WKN (German), MT103 sender reference, and MiFID II transaction IDs.

All structured formats implement their published checksum algorithms so
generated values are structurally valid — they pass pattern + check-digit
tests that a DLP scanner would apply.
"""
from __future__ import annotations

import random
import string
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic
from evadex.synthetic.validators import luhn_check_digit


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _char_value(ch: str) -> int:
    """Map a CUSIP/SEDOL/ISIN character to its numeric value."""
    ch = ch.upper()
    if ch.isdigit():
        return int(ch)
    if ch.isalpha():
        return ord(ch) - ord("A") + 10
    return {"*": 36, "@": 37, "#": 38}.get(ch, 0)


# ── CUSIP check digit (ANSI X9.6) ─────────────────────────────────────────────

def _cusip_check(chars: str) -> str:
    """Return the CUSIP check digit for an 8-character issuer+issue string.

    Algorithm: for each character at an odd 1-indexed position (even 0-indexed)
    keep its value; for even 1-indexed (odd 0-indexed) double it then sum the
    two decimal digits. Sum all values and take (10 - total%10) % 10.
    """
    total = 0
    for i, ch in enumerate(chars[:8]):
        v = _char_value(ch)
        if i % 2 == 1:          # even position (1-indexed) → double
            v *= 2
        total += v // 10 + v % 10
    return str((10 - total % 10) % 10)


# Well-known issuer codes (first 6 chars of CUSIP) for common equity.
_CUSIP_ISSUERS = [
    "037833",   # Apple Inc
    "46625H",   # JPMorgan Chase
    "78008T",   # Royal Bank of Canada
    "38141G",   # Goldman Sachs
    "17275R",   # Citigroup
    "742718",   # Procter & Gamble
    "023135",   # Amazon
    "594918",   # Microsoft
]


def _gen_cusip(rng: random.Random) -> str:
    issuer = rng.choice(_CUSIP_ISSUERS)
    # Two-char issue code: common equity is "10", preferred "20", etc.
    issue = rng.choice(["10", "20", "30", "40"])
    base = issuer + issue
    return base + _cusip_check(base)


# ── CINS (CUSIP International Numbering System) ────────────────────────────────

# CINS first character is a letter indicating the country/region of the issuer.
# Common prefixes: F=France, G=UK, H=Switzerland, L=Luxembourg, N=Netherlands.
_CINS_PREFIXES = list("FGHLNQSXY")  # subset of real CINS country prefixes


def _gen_cins(rng: random.Random) -> str:
    prefix = rng.choice(_CINS_PREFIXES)
    # Remaining 5 chars of issuer (digits)
    issuer_tail = "".join(str(rng.randint(0, 9)) for _ in range(5))
    issue = rng.choice(["10", "20"])
    base = prefix + issuer_tail + issue
    return base + _cusip_check(base)


# ── SEDOL check digit (London Stock Exchange) ──────────────────────────────────

_SEDOL_WEIGHTS = [1, 3, 1, 7, 3, 9]
# SEDOL uses digits + consonants only (no vowels A,E,I,O,U).
_SEDOL_CHARS = string.digits + "BCDFGHJKLMNPQRSTVWXYZ"


def _sedol_check(chars: str) -> str:
    """Return the SEDOL check digit for a 6-character string."""
    total = sum(_char_value(c) * w for c, w in zip(chars[:6], _SEDOL_WEIGHTS))
    return str((10 - total % 10) % 10)


def _gen_sedol(rng: random.Random) -> str:
    # Modern international SEDOLs start with B-Z (letter), older UK ones are
    # numeric.  Mix both.
    if rng.random() < 0.5:
        # Older numeric SEDOL (6 digits)
        base = "".join(str(rng.randint(0, 9)) for _ in range(6))
    else:
        # International SEDOL: starts with a consonant
        first = rng.choice(list("BCDFGHJKLMNPQRSTVWXYZ"))
        rest = "".join(rng.choice(_SEDOL_CHARS) for _ in range(5))
        base = first + rest
    return base + _sedol_check(base)


# ── ISIN check digit (ISO 6166 / Luhn) ────────────────────────────────────────

# Country codes used in synthetic ISINs: major capital markets.
_ISIN_COUNTRIES = ["US", "GB", "CA", "DE", "FR", "JP", "AU", "CH", "NL", "SE"]


def _isin_check(prefix_11: str) -> str:
    """Return the ISIN check digit for the 11-character country+NSIN prefix.

    Converts each character to its decimal representation (A→10 … Z→35),
    concatenates them, then applies the Luhn algorithm.
    """
    digits = "".join(
        str(_char_value(ch)) if ch.isalpha() else ch
        for ch in prefix_11.upper()
    )
    return str(luhn_check_digit([int(d) for d in digits]))


def _gen_isin(rng: random.Random) -> str:
    country = rng.choice(_ISIN_COUNTRIES)
    # 9-char NSIN: mix of digits (for US/CA/AU equity CUSIPs) and alphanumeric
    nsin = "".join(rng.choice(string.digits + "ABCDEFGHJKLMNPQRSTVWXYZ")
                   for _ in range(9))
    prefix = country + nsin
    return prefix + _isin_check(prefix)


# ── FIGI check digit (Bloomberg / OMG) ────────────────────────────────────────

# FIGI format: BB + G + 8 random chars (no vowels, no OI) + 1 check digit.
# The check digit uses the same Luhn algorithm as ISIN (char→value → digit string).
_FIGI_BODY_CHARS = "BCDFGHJKLMNPQRSTVWXYZ0123456789"


def _figi_check(body_11: str) -> str:
    """Return the FIGI check digit for the 11-character BBG+body prefix."""
    digits = "".join(
        str(_char_value(ch)) if ch.isalpha() else ch
        for ch in body_11.upper()
    )
    return str(luhn_check_digit([int(d) for d in digits]))


def _gen_figi(rng: random.Random) -> str:
    # First 3 chars are always "BBG"; next 8 are random from allowed set.
    body = "".join(rng.choice(_FIGI_BODY_CHARS) for _ in range(8))
    prefix = "BBG" + body
    return prefix + _figi_check(prefix)


# ── LEI check digits (ISO 17442 / mod-97) ─────────────────────────────────────

# LEI = 4-char LOU + "00" (reserved) + 12-char entity code + 2 check digits.
# Check digit uses the same mod-97 algorithm as IBANs.
_LEI_ALPHANUMERIC = string.digits + string.ascii_uppercase


def _lei_check(base18: str) -> str:
    """Compute the two-char mod-97 check digits for an 18-char LEI base."""
    numeric = "".join(
        str(ord(ch) - ord("A") + 10) if ch.isalpha() else ch
        for ch in (base18 + "00").upper()
    )
    remainder = int(numeric) % 97
    return f"{98 - remainder:02d}"


def _gen_lei(rng: random.Random) -> str:
    # Use a fixed-length 4-char LOU code; real LOUs are registered with GLEIF.
    lou = "".join(rng.choice(_LEI_ALPHANUMERIC) for _ in range(4))
    reserved = "00"
    entity = "".join(rng.choice(_LEI_ALPHANUMERIC) for _ in range(12))
    base = lou + reserved + entity
    return base + _lei_check(base)


# ── Ticker symbols ─────────────────────────────────────────────────────────────

# Common equity tickers across major exchanges.  Dollar-prefixed form is used
# in social/messaging contexts; bare form appears in structured data.
_TICKER_SEEDS = [
    "$AAPL", "$MSFT", "$AMZN", "$GOOGL", "$META", "$NVDA", "$TSLA",
    "$JPM", "$BAC", "$WFC", "$GS", "$MS", "$C",
    "$BRK.A", "$BRK.B",
    "AAPL", "MSFT", "JPM", "AMZN", "RY.TO", "TD.TO", "BNS.TO",
    "BP.L", "HSBA.L", "LLOY.L", "VOD.L",
]


def _gen_ticker(rng: random.Random) -> str:
    return rng.choice(_TICKER_SEEDS)


# ── Reuters RIC (Refinitiv Instrument Code) ────────────────────────────────────

# RIC = ticker + "." + exchange suffix.
_RIC_MAP = [
    ("AAPL", "O"),   # Nasdaq
    ("MSFT", "O"),
    ("AMZN", "O"),
    ("NVDA", "O"),
    ("TSLA", "O"),
    ("JPM",  "N"),   # NYSE
    ("BAC",  "N"),
    ("GS",   "N"),
    ("MS",   "N"),
    ("C",    "N"),
    ("RY",   "TO"),  # Toronto
    ("TD",   "TO"),
    ("BNS",  "TO"),
    ("BP",   "L"),   # London
    ("HSBA", "L"),
    ("VOD",  "L"),
    ("ADS",  "DE"),  # Frankfurt Xetra
    ("BMW",  "DE"),
    ("SAN",  "MC"),  # Madrid
    ("BNP",  "PA"),  # Paris
]


def _gen_ric(rng: random.Random) -> str:
    ticker, suffix = rng.choice(_RIC_MAP)
    return f"{ticker}.{suffix}"


# ── Swiss VALOR number ─────────────────────────────────────────────────────────

# VALOR is a 6-to-9 digit integer assigned by SIX Group.
# No checksum — purely sequential.  Range: ~1M to ~60M for active securities.


def _gen_valor(rng: random.Random) -> str:
    return str(rng.randint(1_000_000, 59_999_999))


# ── German WKN (Wertpapierkennnummer) ─────────────────────────────────────────

# WKN is exactly 6 alphanumeric characters (uppercase letters + digits).
# No checksum — assigned sequentially by Bundesbank/WM Datenservice.
_WKN_CHARS = string.digits + string.ascii_uppercase


def _gen_wkn(rng: random.Random) -> str:
    return "".join(rng.choice(_WKN_CHARS) for _ in range(6))


# ── SWIFT MT103 sender reference (field 20) ───────────────────────────────────

# Field 20 is up to 16 uppercase alphanumeric characters (no spaces/special).
_MT103_CHARS = string.ascii_uppercase + string.digits


def _gen_mt103(rng: random.Random) -> str:
    length = rng.randint(12, 16)
    return "".join(rng.choice(_MT103_CHARS) for _ in range(length))


# ── MiFID II Transaction Reference Number ─────────────────────────────────────

# MiFID II TRN: up to 52 uppercase alphanumeric characters, assigned by the
# reporting firm.  Common patterns: firm LEI prefix + date + sequence.
_MIFID_CHARS = string.ascii_uppercase + string.digits


def _gen_mifid(rng: random.Random) -> str:
    # Realistic structure: 20-char LEI-like prefix + 8-char date + 24-char seq
    length = rng.randint(30, 52)
    return "".join(rng.choice(_MIFID_CHARS) for _ in range(length))


# ── Synthetic generator classes ────────────────────────────────────────────────

@register_synthetic(PayloadCategory.CUSIP_NUM)
class CUSIPSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally valid 9-character CUSIP numbers with check digit."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_cusip(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.CINS_NUM)
class CINSSyntheticGenerator(BaseSyntheticGenerator):
    """Generates CUSIP International Numbering System values (non-US CUSIP variant)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_cins(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.SEDOL_NUM)
class SEDOLSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally valid 7-character SEDOL codes with check digit."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_sedol(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.ISIN)
class ISINSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally valid 12-character ISINs with Luhn check digit."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_isin(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.FIGI_NUM)
class FIGISyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally valid 12-character Bloomberg FIGIs with check digit."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_figi(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.LEI_NUM)
class LEISyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally valid 20-character LEIs with ISO 17442 check digits."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_lei(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.TICKER_SYMBOL)
class TickerSyntheticGenerator(BaseSyntheticGenerator):
    """Generates equity ticker symbols from major exchanges."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_ticker(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.REUTERS_RIC)
class ReutersRICSyntheticGenerator(BaseSyntheticGenerator):
    """Generates Reuters Instrument Codes (ticker.exchange suffix)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_ric(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.VALOR_NUM)
class ValorSyntheticGenerator(BaseSyntheticGenerator):
    """Generates Swiss Valorennummer (6–9 digit sequential number)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_valor(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.WKN_NUM)
class WKNSyntheticGenerator(BaseSyntheticGenerator):
    """Generates German WKN (Wertpapierkennnummer) — 6 alphanumeric chars."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_wkn(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.MT103_REF)
class MT103RefSyntheticGenerator(BaseSyntheticGenerator):
    """Generates SWIFT MT103 sender references (field 20, up to 16 chars)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_mt103(rng) for _ in range(count)]


@register_synthetic(PayloadCategory.MIFID_TX_ID)
class MiFIDTxIDSyntheticGenerator(BaseSyntheticGenerator):
    """Generates MiFID II Transaction Reference Numbers (up to 52 alphanumeric)."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_gen_mifid(rng) for _ in range(count)]
