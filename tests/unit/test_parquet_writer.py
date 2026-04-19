"""Tests for the Parquet writer.

Skipped entirely when the ``data-formats`` extra is not installed —
``pyarrow`` is optional and core CI should stay lean.
"""
from __future__ import annotations

import pytest

pa = pytest.importorskip("pyarrow", reason="data-formats extra not installed")
pq = pytest.importorskip("pyarrow.parquet", reason="data-formats extra not installed")


from evadex.core.result import PayloadCategory  # noqa: E402
from evadex.generate.generator import GeneratedEntry  # noqa: E402
from evadex.generate.writers import set_writer_config  # noqa: E402
from evadex.generate.writers.parquet_writer import (  # noqa: E402
    _EN_COLUMNS,
    _FR_COLUMNS,
    write_parquet,
)


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


# ── Schema ──────────────────────────────────────────────────────────────────

def test_parquet_valid_and_has_expected_columns(tmp_path):
    out = tmp_path / "out.parquet"
    entries = [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")]
    write_parquet(entries, str(out))
    assert out.exists()
    table = pq.read_table(out)
    assert table.num_rows == 1
    assert set(_EN_COLUMNS).issubset(set(table.column_names))
    assert "card_number" in table.column_names


def test_parquet_places_value_in_category_column(tmp_path):
    out = tmp_path / "out.parquet"
    entries = [
        _entry(PayloadCategory.EMAIL, "alice@example.com"),
        _entry(PayloadCategory.PHONE, "+1-555-867-5309"),
        _entry(PayloadCategory.CREDIT_CARD, "4532015112830366"),
    ]
    write_parquet(entries, str(out))
    df = pq.read_table(out).to_pandas()
    # Each value lands in its own row's appropriate column
    assert df.loc[0, "email"] == "alice@example.com"
    assert df.loc[1, "phone"] == "+1-555-867-5309"
    assert df.loc[2, "card_number"] == "4532015112830366"


def test_parquet_notes_column_records_category_and_technique(tmp_path):
    out = tmp_path / "out.parquet"
    entries = [
        _entry(PayloadCategory.CREDIT_CARD, "4532015112830366",
               technique="unicode_en_space"),
    ]
    write_parquet(entries, str(out))
    df = pq.read_table(out).to_pandas()
    notes = df.loc[0, "notes"]
    assert "category=credit_card" in notes
    assert "technique=unicode_en_space" in notes


# ── French columns ──────────────────────────────────────────────────────────

def test_parquet_fr_ca_uses_french_column_names(tmp_path):
    set_writer_config(seed=42, language="fr-CA")
    out = tmp_path / "out_fr.parquet"
    entries = [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")]
    write_parquet(entries, str(out))
    table = pq.read_table(out)
    assert "numero_carte" in table.column_names
    assert "courriel" in table.column_names
    assert "nom" in table.column_names
    # English names must NOT appear
    assert "card_number" not in table.column_names
    assert "email" not in table.column_names
    df = table.to_pandas()
    assert df.loc[0, "numero_carte"] == "4532015112830366"


# ── Row groups ──────────────────────────────────────────────────────────────

def test_parquet_multiple_row_groups_for_large_inputs(tmp_path):
    """>1k rows should produce multiple row groups (1k-row group size)."""
    out = tmp_path / "big.parquet"
    entries = [
        _entry(PayloadCategory.CREDIT_CARD, f"45320151128303{i:02d}")
        for i in range(2500)
    ]
    write_parquet(entries, str(out))
    f = pq.ParquetFile(out)
    assert f.num_row_groups >= 2  # 1000-row groups on 2500 entries
    assert pq.read_table(out).num_rows == 2500


# ── Single row ──────────────────────────────────────────────────────────────

def test_parquet_single_row_file(tmp_path):
    out = tmp_path / "single.parquet"
    write_parquet(
        [_entry(PayloadCategory.CREDIT_CARD, "4532015112830366")],
        str(out),
    )
    assert pq.read_table(out).num_rows == 1


# ── Missing pyarrow path ────────────────────────────────────────────────────

def test_parquet_deps_hint_mentions_extras(monkeypatch, tmp_path):
    from evadex.generate.writers import parquet_writer

    def _fake_require():
        raise RuntimeError(parquet_writer.PARQUET_DEPS_HINT)

    monkeypatch.setattr(parquet_writer, "_require_pyarrow", _fake_require)
    with pytest.raises(RuntimeError) as exc:
        write_parquet(
            [_entry(PayloadCategory.CREDIT_CARD, "x")],
            str(tmp_path / "out.parquet"),
        )
    assert "evadex[data-formats]" in str(exc.value)
