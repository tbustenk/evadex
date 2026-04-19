"""SQLite writer for evadex generate.

Targets Siphon's ``extract_sqlite`` (``src/extractors.rs``), which opens
the file READ_ONLY, enumerates all non-``sqlite_%`` tables, and reads
up to 5,000 rows per table. We emit a realistic three-table banking
schema so Siphon's per-table extraction gets a full workout.

Schema
------
customers     (id, name, email, phone, sin, date_of_birth, address)
transactions  (id, customer_id, card_number, amount, timestamp, notes)
accounts      (id, customer_id, iban, swift_bic, balance, opened_on)

Entries are routed to the table whose columns best match their
payload category. Categories that don't fit any specific column land
in ``customers.notes`` (when present) or transactions notes.

French language
---------------
``--language fr-CA`` renames both tables and columns:

clients       (id, nom, courriel, telephone, numero_assurance_sociale,
               date_de_naissance, adresse)
transactions  (id, id_client, numero_carte, montant, horodatage, notes)
comptes       (id, id_client, iban, code_swift, solde, date_ouverture)

Uses Python's stdlib ``sqlite3`` module — no extra install required.
"""
from __future__ import annotations

import os
import random
import sqlite3

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers._data_filler import (
    fake_address,
    fake_amount,
    fake_date,
    fake_name,
    fake_timestamp,
    normalize_language,
)


# ── English schema ──────────────────────────────────────────────────────────

_EN_SCHEMA = {
    "customers": (
        "CREATE TABLE customers ("
        " id INTEGER PRIMARY KEY,"
        " name TEXT,"
        " email TEXT,"
        " phone TEXT,"
        " sin TEXT,"
        " date_of_birth TEXT,"
        " address TEXT,"
        " notes TEXT"
        ")"
    ),
    "transactions": (
        "CREATE TABLE transactions ("
        " id INTEGER PRIMARY KEY,"
        " customer_id INTEGER,"
        " card_number TEXT,"
        " amount REAL,"
        " timestamp TEXT,"
        " notes TEXT"
        ")"
    ),
    "accounts": (
        "CREATE TABLE accounts ("
        " id INTEGER PRIMARY KEY,"
        " customer_id INTEGER,"
        " iban TEXT,"
        " swift_bic TEXT,"
        " balance REAL,"
        " opened_on TEXT"
        ")"
    ),
}

_EN_TABLE_MAP = {
    # (table, column) for each category — matches schema above
    PayloadCategory.EMAIL:        ("customers", "email"),
    PayloadCategory.PHONE:        ("customers", "phone"),
    PayloadCategory.SIN:          ("customers", "sin"),
    PayloadCategory.SSN:          ("customers", "sin"),
    PayloadCategory.CREDIT_CARD:  ("transactions", "card_number"),
    PayloadCategory.IBAN:         ("accounts", "iban"),
    PayloadCategory.SWIFT_BIC:    ("accounts", "swift_bic"),
    # Everything else → customers.notes so it's still on-disk and scannable.
}

# ── French schema ───────────────────────────────────────────────────────────

_FR_SCHEMA = {
    "clients": (
        "CREATE TABLE clients ("
        " id INTEGER PRIMARY KEY,"
        " nom TEXT,"
        " courriel TEXT,"
        " telephone TEXT,"
        " numero_assurance_sociale TEXT,"
        " date_de_naissance TEXT,"
        " adresse TEXT,"
        " notes TEXT"
        ")"
    ),
    "transactions": (
        "CREATE TABLE transactions ("
        " id INTEGER PRIMARY KEY,"
        " id_client INTEGER,"
        " numero_carte TEXT,"
        " montant REAL,"
        " horodatage TEXT,"
        " notes TEXT"
        ")"
    ),
    "comptes": (
        "CREATE TABLE comptes ("
        " id INTEGER PRIMARY KEY,"
        " id_client INTEGER,"
        " iban TEXT,"
        " code_swift TEXT,"
        " solde REAL,"
        " date_ouverture TEXT"
        ")"
    ),
}

_FR_TABLE_MAP = {
    PayloadCategory.EMAIL:        ("clients", "courriel"),
    PayloadCategory.PHONE:        ("clients", "telephone"),
    PayloadCategory.SIN:          ("clients", "numero_assurance_sociale"),
    PayloadCategory.SSN:          ("clients", "numero_assurance_sociale"),
    PayloadCategory.CREDIT_CARD:  ("transactions", "numero_carte"),
    PayloadCategory.IBAN:         ("comptes", "iban"),
    PayloadCategory.SWIFT_BIC:    ("comptes", "code_swift"),
}


# ── Writer ─────────────────────────────────────────────────────────────────

def write_sqlite(entries: list[GeneratedEntry], path: str) -> None:
    from evadex.generate.writers import _active_seed
    seed = _active_seed
    rng = random.Random(seed if seed is not None else 0)
    language = normalize_language(_active_language())

    schema = _FR_SCHEMA if language == "fr-CA" else _EN_SCHEMA
    table_map = _FR_TABLE_MAP if language == "fr-CA" else _EN_TABLE_MAP

    _ensure_dir(path)
    # Remove any prior file so repeated runs produce a clean DB (writing
    # into an existing SQLite file would otherwise duplicate schemas).
    if os.path.exists(path):
        os.unlink(path)

    conn = sqlite3.connect(path)
    try:
        cur = conn.cursor()
        for ddl in schema.values():
            cur.execute(ddl)

        # Pre-allocate customer rows so each entry has a valid customer_id
        # to foreign-key from (non-enforced, but the shape is realistic).
        n = max(1, len(entries))
        customer_ids = list(range(1, n + 1))
        customers_table = "clients" if language == "fr-CA" else "customers"
        _insert_customers(cur, customers_table, customer_ids, rng, language)

        txn_id = 1
        acct_id = 1
        for i, entry in enumerate(entries, start=1):
            target = table_map.get(entry.category)
            if target is None:
                # Route unmapped categories to customers.notes so nothing is dropped.
                _update_notes(
                    cur, customers_table, i, entry, language,
                )
                continue
            table, column = target
            if table == customers_table:
                _update_customer_column(cur, customers_table, i, column, entry.variant_value)
            elif table == "transactions":
                _insert_transaction(cur, txn_id, i, column, entry, rng, language)
                txn_id += 1
            elif table in ("accounts", "comptes"):
                _insert_account(cur, table, acct_id, i, column, entry, rng, language)
                acct_id += 1

        conn.commit()
    finally:
        conn.close()


def _insert_customers(
    cur: sqlite3.Cursor,
    table: str,
    ids: list[int],
    rng: random.Random,
    language: str,
) -> None:
    if table == "clients":
        sql = (
            "INSERT INTO clients (id, nom, courriel, telephone, "
            "numero_assurance_sociale, date_de_naissance, adresse, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
    else:
        sql = (
            "INSERT INTO customers (id, name, email, phone, sin, "
            "date_of_birth, address, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
    rows = []
    for cid in ids:
        rows.append((
            cid,
            fake_name(rng, language),
            f"user{cid}@example.com",
            f"+1-555-{rng.randint(100, 999):03d}-{rng.randint(1000, 9999):04d}",
            f"{rng.randint(100, 999):03d} {rng.randint(100, 999):03d} {rng.randint(100, 999):03d}",
            fake_date(rng),
            fake_address(rng, language),
            "",
        ))
    cur.executemany(sql, rows)


def _update_customer_column(
    cur: sqlite3.Cursor, table: str, cid: int, column: str, value: str
) -> None:
    cur.execute(
        f"UPDATE {table} SET {column} = ? WHERE id = ?",
        (value, cid),
    )


def _update_notes(
    cur: sqlite3.Cursor, table: str, cid: int, entry: GeneratedEntry, language: str
) -> None:
    note = f"{entry.category.value}:{entry.variant_value}"
    cur.execute(
        f"UPDATE {table} SET notes = ? WHERE id = ?",
        (note, cid),
    )


def _insert_transaction(
    cur: sqlite3.Cursor, txn_id: int, customer_id: int, column: str,
    entry: GeneratedEntry, rng: random.Random, language: str,
) -> None:
    # Only `card_number` / `numero_carte` is a sensitive column here; the
    # remaining columns get fake amounts + timestamps.
    if language == "fr-CA":
        sql = (
            "INSERT INTO transactions (id, id_client, numero_carte, montant, "
            "horodatage, notes) VALUES (?, ?, ?, ?, ?, ?)"
        )
    else:
        sql = (
            "INSERT INTO transactions (id, customer_id, card_number, amount, "
            "timestamp, notes) VALUES (?, ?, ?, ?, ?, ?)"
        )
    card_val = entry.variant_value if column in ("card_number", "numero_carte") else ""
    technique = entry.technique or "plain"
    cur.execute(sql, (
        txn_id, customer_id, card_val, fake_amount(rng),
        fake_timestamp(rng),
        f"category={entry.category.value} technique={technique}",
    ))


def _insert_account(
    cur: sqlite3.Cursor, table: str, acct_id: int, customer_id: int, column: str,
    entry: GeneratedEntry, rng: random.Random, language: str,
) -> None:
    if table == "comptes":
        sql = (
            "INSERT INTO comptes (id, id_client, iban, code_swift, solde, "
            "date_ouverture) VALUES (?, ?, ?, ?, ?, ?)"
        )
        iban_col, swift_col = "iban", "code_swift"
    else:
        sql = (
            "INSERT INTO accounts (id, customer_id, iban, swift_bic, balance, "
            "opened_on) VALUES (?, ?, ?, ?, ?, ?)"
        )
        iban_col, swift_col = "iban", "swift_bic"
    iban_val = entry.variant_value if column == iban_col else ""
    swift_val = entry.variant_value if column == swift_col else "TESTCAXX"
    cur.execute(sql, (
        acct_id, customer_id, iban_val, swift_val,
        round(rng.uniform(0, 100000), 2), fake_date(rng, 2018, 2026),
    ))


def _active_language() -> str:
    try:
        from evadex.generate.writers import _active_language as lang
        return lang
    except Exception:
        return "en"


def _ensure_dir(path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d:
        os.makedirs(d, exist_ok=True)
