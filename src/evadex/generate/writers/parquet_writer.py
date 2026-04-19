"""Parquet writer for evadex generate.

Targets Siphon's ``extract_parquet`` (``src/extractors.rs``), which
reads the first 10,000 rows as tab-separated text for DLP scanning.
Column layout is a flat "customer table" shape — the minimum surface
that exercises Siphon's row+header extraction path.

Layout
------
Columns are arranged so every sensitive category in evadex's built-in
payload set lands in a semantically realistic column. Non-sensitive
columns are filled with realistic fake data (names, addresses, dates,
amounts) via :mod:`evadex.generate.writers._data_filler`.

Row groups
----------
Written with a 1,000-row row group so files >1k rows give Siphon's
reader multiple groups to walk — closer to a real production Parquet
footprint than a single mega-group.

Optional dependency
-------------------
Gated behind ``pip install evadex[data-formats]``. A clear RuntimeError
with the install hint is raised when pyarrow is unavailable.
"""
from __future__ import annotations

import os
import random
from collections import defaultdict
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers._data_filler import (
    fake_address,
    fake_amount,
    fake_date,
    fake_name,
    fake_uuid,
    normalize_language,
)


PARQUET_DEPS_HINT = (
    "Parquet generation requires optional dependencies. "
    "Install with: pip install evadex[data-formats]"
)


# Column layouts — one per language. Keys map evadex PayloadCategory values
# to the column name they should populate; categories not in the map get
# stuffed into a generic "notes" column. Column order matters because
# Siphon emits headers in schema order.
_EN_COLUMNS = [
    "customer_id", "name", "email", "phone", "date_of_birth", "address",
    "sin", "card_number", "iban", "swift_bic", "aba_routing",
    "aws_key", "jwt", "notes",
]
_EN_CATEGORY_MAP = {
    PayloadCategory.EMAIL: "email",
    PayloadCategory.PHONE: "phone",
    PayloadCategory.SIN: "sin",
    PayloadCategory.SSN: "sin",  # no separate ssn column — collapse into sin
    PayloadCategory.CREDIT_CARD: "card_number",
    PayloadCategory.IBAN: "iban",
    PayloadCategory.SWIFT_BIC: "swift_bic",
    PayloadCategory.ABA_ROUTING: "aba_routing",
    PayloadCategory.AWS_KEY: "aws_key",
    PayloadCategory.JWT: "jwt",
}

_FR_COLUMNS = [
    "id_client", "nom", "courriel", "telephone", "date_de_naissance",
    "adresse", "numero_assurance_sociale", "numero_carte", "iban",
    "code_swift", "routage_aba", "cle_aws", "jeton_jwt", "notes",
]
# Mapping mirrors _EN_CATEGORY_MAP but with French column names.
_FR_CATEGORY_MAP = {
    PayloadCategory.EMAIL: "courriel",
    PayloadCategory.PHONE: "telephone",
    PayloadCategory.SIN: "numero_assurance_sociale",
    PayloadCategory.SSN: "numero_assurance_sociale",
    PayloadCategory.CREDIT_CARD: "numero_carte",
    PayloadCategory.IBAN: "iban",
    PayloadCategory.SWIFT_BIC: "code_swift",
    PayloadCategory.ABA_ROUTING: "routage_aba",
    PayloadCategory.AWS_KEY: "cle_aws",
    PayloadCategory.JWT: "jeton_jwt",
}


def write_parquet(entries: list[GeneratedEntry], path: str) -> None:
    """Render *entries* to ``path`` as a Parquet file.

    One row per entry, with the sensitive value placed in the category-
    appropriate column and every other column filled with realistic fake
    data. Unknown/unmapped categories land in ``notes``.
    """
    pa = _require_pyarrow()
    pq = _require_parquet()

    from evadex.generate.writers import _active_seed
    seed = _active_seed
    rng = random.Random(seed if seed is not None else 0)
    language = normalize_language(_active_language())

    columns = _FR_COLUMNS if language == "fr-CA" else _EN_COLUMNS
    category_map = _FR_CATEGORY_MAP if language == "fr-CA" else _EN_CATEGORY_MAP

    rows: dict[str, list] = {c: [] for c in columns}
    id_col = columns[0]  # customer_id / id_client
    name_col = columns[1]
    address_col = columns[5]
    dob_col = columns[4]
    notes_col = columns[-1]

    for i, entry in enumerate(entries, start=1):
        rows[id_col].append(i)
        rows[name_col].append(fake_name(rng, language))
        rows[dob_col].append(fake_date(rng))
        rows[address_col].append(fake_address(rng, language))

        target_col = category_map.get(entry.category)
        # Fill every non-target column with a plausible fake, then drop the
        # entry's value into the target column.
        for col in columns:
            if col in (id_col, name_col, dob_col, address_col, notes_col):
                continue
            if col == target_col:
                rows[col].append(entry.variant_value)
            else:
                rows[col].append(_fake_for_column(col, rng))
        # Notes column: include the category + technique so scan output
        # carries the evasion metadata back to evadex.
        technique = entry.technique or "plain"
        rows[notes_col].append(
            f"category={entry.category.value} technique={technique}"
        )

    table = pa.table(rows)
    _ensure_dir(path)
    # 1,000-row groups so large files exercise Siphon's multi-group reader.
    pq.write_table(table, path, row_group_size=1000, compression="snappy")


def _fake_for_column(col: str, rng: random.Random) -> str:
    """Return a plausible fake value for a sensitive column.

    These appear in every row except the one where the column holds a real
    evadex payload. We use recognisable but clearly-fake shapes so a
    scanner that flags them is over-triggering on format alone.
    """
    # Bank-like but Luhn-invalid shapes — safe to embed.
    if col in ("card_number", "numero_carte"):
        return "".join(str(rng.randint(0, 9)) for _ in range(16))
    if col in ("sin", "numero_assurance_sociale"):
        return f"{rng.randint(100, 999)} {rng.randint(100, 999)} {rng.randint(100, 999)}"
    if col == "iban":
        return f"GB{rng.randint(10, 99)}TEST{rng.randint(10**18, 10**19 - 1)}"
    if col in ("swift_bic", "code_swift"):
        return f"TEST{rng.choice('ABCDEFGH')}{rng.choice('ABCDEFGH')}"
    if col in ("aba_routing", "routage_aba"):
        return f"{rng.randint(10**8, 10**9 - 1)}"
    if col in ("email", "courriel"):
        return f"user{rng.randint(1000, 9999)}@example.com"
    if col in ("phone", "telephone"):
        return f"+1-555-{rng.randint(100, 999)}-{rng.randint(1000, 9999)}"
    if col in ("aws_key", "cle_aws"):
        return "AKIA" + "".join(rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
    if col in ("jwt", "jeton_jwt"):
        return "eyJhbGciOiJIUzI1NiJ9.TEST.TEST"
    return "—"


def _active_language() -> str:
    try:
        from evadex.generate.writers import _active_language as lang
        return lang
    except Exception:
        return "en"


def _require_pyarrow():
    try:
        import pyarrow  # type: ignore
        return pyarrow
    except ImportError as exc:
        raise RuntimeError(PARQUET_DEPS_HINT) from exc


def _require_parquet():
    try:
        import pyarrow.parquet as pq  # type: ignore
        return pq
    except ImportError as exc:
        raise RuntimeError(PARQUET_DEPS_HINT) from exc


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
