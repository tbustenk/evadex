"""Tests for v3.19.0 template work.

Covers:
  * Bilingual (``en`` / ``fr-CA``) output from the six expanded templates.
  * ``banking-statement`` alias resolving to the same formatter as
    ``statement``.
  * ``apply_template`` accepting ``language`` and falling back gracefully
    when a formatter predates the kwarg.
  * The ``lsh_corpus`` CLI path — manifest shape, variant count, and
    files-per-base arithmetic.
"""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry
from evadex.generate.templates import (
    apply_template,
    _FORMATTERS,
)


def _sample_entries(n: int = 6) -> list[GeneratedEntry]:
    """Handful of entries with a mix of banking / Canadian / healthcare
    categories so the templates always have something to place in their
    sensitive-field sections."""
    cats = [
        PayloadCategory.CREDIT_CARD,
        PayloadCategory.SIN,
        PayloadCategory.CA_RAMQ,
        PayloadCategory.IBAN,
        PayloadCategory.EMAIL,
        PayloadCategory.AWS_KEY,
    ]
    out = []
    for i in range(n):
        cat = cats[i % len(cats)]
        val = f"VALUE{i:03d}"
        out.append(GeneratedEntry(
            category=cat,
            plain_value=val,
            variant_value=val,
            technique=None,
            generator_name=None,
            transform_name=None,
            has_keywords=True,
            embedded_text=f"{cat.value}: {val}",
        ))
    return out


# ── Bilingual rendering ────────────────────────────────────────────────

class TestBilingualTemplates:
    """Each of the expanded templates should have obviously different
    output when ``language='fr-CA'`` vs the English default."""

    def _en_fr_differ(self, template: str) -> tuple[str, str]:
        entries = _sample_entries(6)
        en = "\n".join(apply_template(
            template, entries, seed=42, language="en",
        ))
        fr = "\n".join(apply_template(
            template, entries, seed=42, language="fr-CA",
        ))
        assert en != fr, f"{template}: en and fr-CA output identical"
        return en, fr

    def test_statement_bilingual(self):
        en, fr = self._en_fr_differ("statement")
        # Canadian banks mentioned in both locales — different copy.
        assert ("Royal Bank" in en) or ("TD Canada" in en) or ("Scotiabank" in en) \
               or ("Bank of Montreal" in en) or ("CIBC" in en.upper())
        assert ("Desjardins" in fr) or ("Banque Nationale" in fr) \
               or ("Banque Royale" in fr)
        # Balance labels reflect the locale.
        assert "CLOSING BALANCE" in en.upper()
        assert "SOLDE DE CLÔTURE" in fr

    def test_invoice_bilingual(self):
        en, fr = self._en_fr_differ("invoice")
        assert "INVOICE" in en.upper()
        assert "FACTURE" in fr.upper()
        # Tax labels differ by locale.
        assert "HST" in en.upper()
        assert "TPS" in fr.upper() and "TVQ" in fr.upper()

    def test_hr_record_bilingual(self):
        en, fr = self._en_fr_differ("hr_record")
        assert ("EMPLOYEE" in en.upper()) and ("HIRE DATE" in en.upper())
        assert ("EMPLOYÉ" in fr.upper()) and ("EMBAUCHE" in fr.upper())

    def test_medical_record_bilingual(self):
        en, fr = self._en_fr_differ("medical_record")
        assert "PHIPA" in en.upper() or "PIPEDA" in en.upper()
        # French mode references Quebec-specific privacy law.
        assert "LOI 25" in fr.upper()

    def test_source_code_bilingual(self):
        en, fr = self._en_fr_differ("source_code")
        # Code structure is identical but comments differ — the French
        # variant must include a French comment line.
        assert "DO NOT COMMIT" in en
        assert "NE PAS COMMITTER" in fr

    def test_config_file_bilingual(self):
        en, fr = self._en_fr_differ("config_file")
        assert "CONFIDENTIAL" in en.upper()
        assert "CONFIDENTIEL" in fr.upper()


# ── banking-statement alias ────────────────────────────────────────────

class TestBankingStatementAlias:
    def test_banking_statement_routes_to_statement_formatter(self):
        assert _FORMATTERS["banking-statement"] is _FORMATTERS["statement"]
        assert _FORMATTERS["banking_statement"] is _FORMATTERS["statement"]

    def test_banking_statement_end_to_end_renders(self):
        entries = _sample_entries(4)
        out = apply_template(
            "banking-statement", entries, seed=11, language="en",
        )
        text = "\n".join(out)
        # Sentinel strings that only the statement formatter emits.
        assert "STATEMENT" in text.upper() or "Statement" in text
        assert "CLOSING BALANCE" in text.upper()


# ── apply_template language fallback ───────────────────────────────────

class TestApplyTemplateFallback:
    def test_formatter_without_language_kwarg_still_renders(self):
        """Older formatters registered directly should still work when
        ``apply_template`` passes ``language``. The public helper catches
        TypeError and retries without the kwarg."""
        from evadex.generate.templates import _FORMATTERS

        def _legacy(entries, rng, noise_level="medium", density="medium"):
            return ["legacy line"]

        _FORMATTERS["__legacy_test__"] = _legacy
        try:
            out = apply_template("__legacy_test__", _sample_entries(1),
                                  seed=1, language="fr-CA")
            assert out == ["legacy line"]
        finally:
            _FORMATTERS.pop("__legacy_test__", None)

    def test_unknown_template_falls_back_to_generic(self):
        out = apply_template("__not_registered__", _sample_entries(2), seed=0)
        # Generic template emits category headers.
        assert any("===" in line or "=" * 5 in line for line in out)


# ── lsh_corpus CLI integration ─────────────────────────────────────────

class TestLshCorpusCommand:
    """End-to-end test of ``evadex generate --template lsh_corpus ...``.

    Renders to TXT so we don't need any of the heavy writers (docx,
    pdf, parquet) installed in the minimal test environment.
    """

    def _run(self, tmp_path: Path, *extra: str):
        from evadex.cli.commands.generate import generate as generate_cmd
        out_dir = tmp_path / "lsh_corpus"
        runner = CliRunner()
        args = [
            "--format", "txt",
            "--template", "lsh_corpus",
            "--tier", "banking",
            "--count", "2",
            "--lsh-variants", "3",
            "--seed", "42",
            "--output", str(out_dir),
        ] + list(extra)
        result = runner.invoke(generate_cmd, args, catch_exceptions=False)
        return result, out_dir

    def test_produces_manifest_with_expected_counts(self, tmp_path: Path):
        result, out_dir = self._run(tmp_path)
        assert result.exit_code == 0, result.output
        manifest_path = out_dir / "manifest.json"
        assert manifest_path.is_file()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest["variants"] == 3
        # count=2, lsh-variants=3, formats=1 → 6 entries.
        assert len(manifest["entries"]) == 6
        # Files land on disk.
        for entry in manifest["entries"]:
            assert (out_dir / entry["file"]).is_file()
            assert 0.0 <= entry["jaccard"] <= 1.0
            assert 0.0 <= entry["distortion"] <= 1.0

    def test_jaccard_decreases_with_distortion(self, tmp_path: Path):
        """The manifest's jaccard should generally trend downward as
        distortion climbs — it's the whole point of the corpus."""
        result, out_dir = self._run(tmp_path)
        assert result.exit_code == 0, result.output
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        # Pick the first base's variants in order.
        base0 = [e for e in manifest["entries"] if e["base_index"] == 0]
        base0.sort(key=lambda e: e["variant"])
        jaccards = [e["jaccard"] for e in base0]
        # Zero-distortion or lowest-distortion variant should be the
        # most similar; highest distortion the least.
        assert jaccards[0] >= jaccards[-1]

    def test_explicit_distortions_flag_overrides_default(self, tmp_path: Path):
        result, out_dir = self._run(
            tmp_path,
            "--lsh-distortions", "0.01,0.2,0.45",
        )
        assert result.exit_code == 0, result.output
        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["distortions"] == [0.01, 0.2, 0.45]
        assert manifest["variants"] == 3

    def test_rejects_out_of_range_distortion(self, tmp_path: Path):
        from evadex.cli.commands.generate import generate as generate_cmd
        runner = CliRunner()
        result = runner.invoke(generate_cmd, [
            "--format", "txt", "--template", "lsh_corpus",
            "--tier", "banking", "--count", "1",
            "--lsh-distortions", "0.1,1.5",
            "--output", str(tmp_path / "bad"),
        ])
        assert result.exit_code != 0
