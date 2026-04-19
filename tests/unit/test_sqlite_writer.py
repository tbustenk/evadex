"""Tests for the SQLite writer.

SQLite uses Python's stdlib so these tests run everywhere — no
conditional skip needed.
"""
from __future__ import annotations

import sqlite3

import pytest

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.writers import set_writer_config
from evadex.generate.writers.sqlite_writer import write_sqlite


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
        embedded_text=value,
    )


@pytest.fixture(autouse=True)
def _reset_writer_config():
    set_writer_config(seed=42, language="en")
    yield
    set_writer_config(seed=None, language="en")


def _tables(path: str) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
    finally:
        conn.close()
    return [r[0] for r in rows]


def _columns(path: str, table: str) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
    return [r[1] for r in rows]


# ── Schema ──────────────────────────────────────────────────────────────────

def test_sqlite_has_three_tables(tmp_path):
    out = tmp_path / "out.db"
    write_sqlite(
        [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")],
        str(out),
    )
    assert _tables(str(out)) == ["accounts", "customers", "transactions"]


def test_sqlite_customers_columns(tmp_path):
    out = tmp_path / "out.db"
    write_sqlite(
        [_entry(PayloadCategory.EMAIL, "alice@example.com")],
        str(out),
    )
    cols = _columns(str(out), "customers")
    assert set(cols) == {
        "id", "name", "email", "phone", "sin", "date_of_birth", "address", "notes"
    }


def test_sqlite_transactions_hold_card_numbers(tmp_path):
    out = tmp_path / "out.db"
    entries = [
        _entry(PayloadCategory.CREDIT_CARD, f"453201511283036{i}")
        for i in range(3)
    ]
    write_sqlite(entries, str(out))
    conn = sqlite3.connect(str(out))
    try:
        rows = conn.execute(
            "SELECT card_number FROM transactions ORDER BY id"
        ).fetchall()
    finally:
        conn.close()
    values = [r[0] for r in rows]
    assert len(values) == 3
    assert all(v.startswith("453201511283036") for v in values)


def test_sqlite_accounts_hold_ibans(tmp_path):
    out = tmp_path / "out.db"
    write_sqlite(
        [_entry(PayloadCategory.IBAN, "GB82WEST12345698765432")],
        str(out),
    )
    conn = sqlite3.connect(str(out))
    try:
        (iban,) = conn.execute("SELECT iban FROM accounts LIMIT 1").fetchone()
    finally:
        conn.close()
    assert iban == "GB82WEST12345698765432"


# ── French ──────────────────────────────────────────────────────────────────

def test_sqlite_fr_ca_tables(tmp_path):
    set_writer_config(seed=42, language="fr-CA")
    out = tmp_path / "out_fr.db"
    write_sqlite(
        [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")],
        str(out),
    )
    assert _tables(str(out)) == ["clients", "comptes", "transactions"]


def test_sqlite_fr_ca_columns_are_french(tmp_path):
    set_writer_config(seed=42, language="fr-CA")
    out = tmp_path / "out_fr.db"
    write_sqlite(
        [_entry(PayloadCategory.EMAIL, "alice@example.com")],
        str(out),
    )
    cols = set(_columns(str(out), "clients"))
    assert "courriel" in cols
    assert "nom" in cols
    assert "numero_assurance_sociale" in cols
    assert "email" not in cols


def test_sqlite_fr_ca_transactions_use_french_columns(tmp_path):
    set_writer_config(seed=42, language="fr-CA")
    out = tmp_path / "out_fr.db"
    write_sqlite(
        [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")],
        str(out),
    )
    cols = set(_columns(str(out), "transactions"))
    assert "numero_carte" in cols
    assert "montant" in cols
    assert "id_client" in cols


# ── Evasion rate pass-through ───────────────────────────────────────────────

def test_sqlite_preserves_technique_in_notes(tmp_path):
    out = tmp_path / "out.db"
    write_sqlite([
        _entry(PayloadCategory.CREDIT_CARD, "4532015112830366",
               technique="unicode_en_space"),
    ], str(out))
    conn = sqlite3.connect(str(out))
    try:
        (note,) = conn.execute("SELECT notes FROM transactions LIMIT 1").fetchone()
    finally:
        conn.close()
    assert "technique=unicode_en_space" in note


# ── Single row / empty ──────────────────────────────────────────────────────

def test_sqlite_single_row(tmp_path):
    out = tmp_path / "single.db"
    write_sqlite(
        [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")],
        str(out),
    )
    conn = sqlite3.connect(str(out))
    try:
        (n_cust,) = conn.execute("SELECT COUNT(*) FROM customers").fetchone()
        (n_txn,) = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()
    finally:
        conn.close()
    assert n_cust == 1
    assert n_txn == 1


def test_sqlite_overwrites_existing_file(tmp_path):
    """Repeated runs to the same path should not duplicate the schema."""
    out = tmp_path / "db.sqlite"
    write_sqlite([_entry(PayloadCategory.EMAIL, "a@x.com")], str(out))
    write_sqlite([_entry(PayloadCategory.EMAIL, "b@x.com")], str(out))
    # Still exactly three tables — no duplicate creates.
    assert _tables(str(out)) == ["accounts", "customers", "transactions"]
    conn = sqlite3.connect(str(out))
    try:
        (n,) = conn.execute("SELECT COUNT(*) FROM customers").fetchone()
    finally:
        conn.close()
    assert n == 1


# ── Excluded system tables ──────────────────────────────────────────────────

def test_sqlite_no_internal_tables_visible(tmp_path):
    """Siphon skips sqlite_% tables — our writer must not create any."""
    out = tmp_path / "out.db"
    write_sqlite([_entry(PayloadCategory.EMAIL, "a@x.com")], str(out))
    assert not any(t.startswith("sqlite_") for t in _tables(str(out)))
