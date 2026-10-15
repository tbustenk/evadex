"""The keyword sentence drawn under wrap_context is reproducible from a seed.

Most Siphon rules are context-gated, so the template drawn around a variant
decides detection as much as the evasion does. Before v3.41.0 each submission
drew from a fresh unseeded RNG, so no run could be repeated.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from evadex.core.registry import get_adapter
from evadex.core.result import Payload, PayloadCategory, Variant
from evadex.generate.filler import sentence_rng

CAT = PayloadCategory.CREDIT_CARD
PAYLOAD = Payload("4532015112830366", CAT, "Visa")


def _variant(value: str) -> Variant:
    return Variant(value, "structural", "uppercase", "Uppercased")


# ── sentence_rng ────────────────────────────────────────────────────────────


def test_same_seed_same_draw():
    a = sentence_rng(7, CAT, "v").random()
    b = sentence_rng(7, CAT, "v").random()
    assert a == b


def test_different_seeds_differ_somewhere():
    draws = [
        (sentence_rng(1, CAT, f"v{i}").random(), sentence_rng(2, CAT, f"v{i}").random())
        for i in range(20)
    ]
    assert any(x != y for x, y in draws)


def test_different_values_get_independent_draws():
    picks = {sentence_rng(5, CAT, f"v{i}").randrange(1_000_000) for i in range(50)}
    assert len(picks) > 1


def test_category_is_part_of_the_key():
    a = sentence_rng(5, PayloadCategory.CREDIT_CARD, "v").random()
    b = sentence_rng(5, PayloadCategory.SSN, "v").random()
    assert a != b


def test_no_seed_still_returns_an_rng():
    assert sentence_rng(None, CAT, "v").random() < 1.0


# ── through the adapters ────────────────────────────────────────────────────


async def _siphon_sentence(seed, value):
    adapter = get_adapter(
        "siphon-cli", {"executable": "siphon", "wrap_context": True, "seed": seed}
    )
    adapter._client.scan_text = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant(value))
    return adapter._client.scan_text.call_args.args[0]


async def _dlpscan_sentence(seed, value):
    adapter = get_adapter(
        "dlpscan-cli", {"executable": "dlpscan", "wrap_context": True, "seed": seed}
    )
    adapter._scan_text_async = AsyncMock(return_value=[])
    await adapter.submit(PAYLOAD, _variant(value))
    return adapter._scan_text_async.call_args.args[0]


@pytest.mark.parametrize("sentence_for", [_siphon_sentence, _dlpscan_sentence])
async def test_same_seed_same_sentence_across_adapter_instances(sentence_for):
    first = await sentence_for(42, "4532015112830366")
    second = await sentence_for(42, "4532015112830366")
    assert first == second
    assert "4532015112830366" in first


async def test_both_cli_adapters_draw_the_same_sentence_for_the_same_seed():
    assert await _siphon_sentence(42, "x") == await _dlpscan_sentence(42, "x")


async def test_different_seeds_change_at_least_one_sentence():
    values = [f"453201511283036{i}" for i in range(10)]
    a = [await _siphon_sentence(1, v) for v in values]
    b = [await _siphon_sentence(2, v) for v in values]
    assert a != b


async def test_seed_from_string_config_is_accepted():
    assert await _siphon_sentence("42", "x") == await _siphon_sentence(42, "x")


async def test_no_seed_still_wraps():
    assert "4532015112830366" in await _siphon_sentence(None, "4532015112830366")
