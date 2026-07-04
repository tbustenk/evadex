"""Unit tests for the capital_markets variant generator (v3.32.0)."""

from __future__ import annotations

import pytest
from evadex.core.registry import load_builtins, get_generator
from evadex.core.result import PayloadCategory


@pytest.fixture(autouse=True, scope="module")
def _load():
    load_builtins()


class TestCapitalMarketsRegistered:
    def test_generator_registered(self):
        gen = get_generator("capital_markets")
        assert gen is not None
        assert gen.name == "capital_markets"

    def test_applicable_categories_includes_isin(self):
        gen = get_generator("capital_markets")
        assert PayloadCategory.ISIN in gen.applicable_categories

    def test_applicable_categories_includes_cusip(self):
        gen = get_generator("capital_markets")
        assert PayloadCategory.CUSIP_NUM in gen.applicable_categories

    def test_applicable_categories_includes_sedol(self):
        gen = get_generator("capital_markets")
        assert PayloadCategory.SEDOL_NUM in gen.applicable_categories

    def test_applicable_categories_includes_lei(self):
        gen = get_generator("capital_markets")
        assert PayloadCategory.LEI_NUM in gen.applicable_categories


class TestCapitalMarketsVariants:
    @pytest.fixture
    def generator(self):
        return get_generator("capital_markets")

    def test_isin_produces_variants(self, generator):
        isin = "US0378331005"
        variants = list(generator.generate(isin))
        assert len(variants) > 0

    def test_cusip_produces_variants(self, generator):
        cusip = "037833100"
        variants = list(generator.generate(cusip))
        assert len(variants) > 0

    def test_slash_before_check_variant(self, generator):
        cusip = "037833100"
        variants = list(generator.generate(cusip))
        techniques = {v.technique for v in variants}
        assert "slash_before_check" in techniques

    def test_space_after_prefix_variant(self, generator):
        isin = "US0378331005"
        variants = list(generator.generate(isin))
        techniques = {v.technique for v in variants}
        assert "space_after_prefix" in techniques

    def test_lowercase_variant(self, generator):
        sedol = "B0SWJX3"
        variants = list(generator.generate(sedol))
        techniques = {v.technique for v in variants}
        assert "lowercase_all" in techniques
        lower_vars = [v for v in variants if v.technique == "lowercase_all"]
        assert lower_vars[0].value == "b0swjx3"

    def test_zwsp_mid_variant(self, generator):
        lei = "HWUPKR0MPOU8FGXBT394"
        variants = list(generator.generate(lei))
        techniques = {v.technique for v in variants}
        assert "zwsp_mid" in techniques

    def test_zero_width_char_present_in_zwsp_mid(self, generator):
        lei = "HWUPKR0MPOU8FGXBT394"
        variants = list(generator.generate(lei))
        zwsp_var = next(v for v in variants if v.technique == "zwsp_mid")
        zwsp = "​"
        assert zwsp in zwsp_var.value

    def test_reversed_variant(self, generator):
        isin = "US0378331005"
        variants = list(generator.generate(isin))
        techniques = {v.technique for v in variants}
        assert "reversed" in techniques
        rev_var = next(v for v in variants if v.technique == "reversed")
        assert rev_var.value == isin[::-1]

    def test_grouped_spaces_3_variant(self, generator):
        cusip = "037833100"
        variants = list(generator.generate(cusip))
        grouped = next(v for v in variants if v.technique == "grouped_spaces_3")
        assert grouped.value == "037 833 100"

    def test_country_prefix_noise_variant(self, generator):
        isin = "US0378331005"
        variants = list(generator.generate(isin))
        noise = next(v for v in variants if v.technique == "country_prefix_noise")
        assert noise.value == "[US] US0378331005"

    def test_country_prefix_noise_skipped_for_numeric_cusip(self, generator):
        # CUSIP has no alpha country prefix — technique should not fire.
        variants = list(generator.generate("037833100"))
        techniques = {v.technique for v in variants}
        assert "country_prefix_noise" not in techniques

    def test_bloomberg_suffix_variant(self, generator):
        ticker = "AAPL"
        variants = list(generator.generate(ticker))
        bbg = next(v for v in variants if v.technique == "bloomberg_suffix")
        assert bbg.value == "AAPL US Equity"

    def test_all_variants_have_technique(self, generator):
        for v in generator.generate("US0378331005"):
            assert v.technique, f"Variant missing technique: {v}"

    def test_all_variants_have_value(self, generator):
        for v in generator.generate("037833100"):
            assert v.value, f"Variant has empty value: {v}"
