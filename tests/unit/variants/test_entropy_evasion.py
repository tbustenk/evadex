"""Unit tests for the entropy_evasion variant generator.

Three invariants we care about:
1. For each applicable payload the generator emits every technique.
2. The techniques actually reduce the per-character Shannon entropy of
   the longest run, or break it below Siphon's 16-char floor — otherwise
   they wouldn't evade entropy detection.
3. The core high-entropy token in every seed payload sits above the
   Siphon threshold of 4.5 bits/char so evasion is meaningful.
"""
import math
from collections import Counter

import pytest

from evadex.variants.entropy_evasion import EntropyEvasionGenerator, _extract_token


SIPHON_ENTROPY_THRESHOLD = 4.5
SIPHON_MIN_TOKEN_LEN = 16
SIPHON_DELIMITERS = set(" \t\n,;'\"()[]{}=:")


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _longest_nondelim_run(text: str) -> str:
    best = ""
    cur = []
    for ch in text:
        if ch in SIPHON_DELIMITERS:
            if len("".join(cur)) > len(best):
                best = "".join(cur)
            cur = []
        else:
            cur.append(ch)
    if len("".join(cur)) > len(best):
        best = "".join(cur)
    return best


SEED = "xK9mP2nL4qR7vT1wY6uI0oE3sA5dF8hJ"  # 32-char, matches RANDOM_API_KEY payload


@pytest.fixture
def gen():
    return EntropyEvasionGenerator()


def test_extract_token_finds_longest_run():
    assert _extract_token(SEED) == SEED
    # For assignment (KEY=value), the longest non-delimiter run should be the value.
    # Note `_` is alphanumeric-adjacent in the helper, so `KEY_NAME=VALUE` keeps the
    # prefix attached — but it should still find the longest alphanumeric run.
    assignment_extract = _extract_token(f"DB_PASSWORD={SEED}")
    assert SEED in assignment_extract or assignment_extract == SEED
    # Colon-separated: space breaks the run cleanly.
    assert _extract_token(f"api_key: {SEED}") == SEED


def test_generator_emits_all_six_techniques(gen):
    techniques = [v.technique for v in gen.generate(SEED)]
    # Expect at least 6 distinct techniques (encode can be skipped on pathological input)
    assert set(techniques) >= {
        "entropy_split",
        "entropy_comment",
        "entropy_concat",
        "entropy_low_mix",
        "entropy_space",
    }
    assert "entropy_encode" in techniques


def test_seed_core_is_actually_high_entropy():
    """Sanity: the bare payload needs entropy > Siphon's 4.5 threshold."""
    assert shannon(SEED) > SIPHON_ENTROPY_THRESHOLD


def test_split_produces_sub_min_length_runs(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    run = _longest_nondelim_run(variants["entropy_split"].value)
    assert len(run) < SIPHON_MIN_TOKEN_LEN, (
        f"entropy_split longest non-delimiter run ({len(run)}) "
        f"must be under Siphon's min token length {SIPHON_MIN_TOKEN_LEN}"
    )


def test_space_produces_sub_min_length_runs(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    run = _longest_nondelim_run(variants["entropy_space"].value)
    assert len(run) < SIPHON_MIN_TOKEN_LEN


def test_comment_breaks_longest_run(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    # The / and * delimiters chop the token. Whatever run is left must be shorter
    # than the original value.
    run = _longest_nondelim_run(variants["entropy_comment"].value)
    assert len(run) < len(SEED)


def test_concat_breaks_longest_run(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    run = _longest_nondelim_run(variants["entropy_concat"].value)
    assert len(run) < len(SEED)


def test_low_mix_reduces_per_char_entropy(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    run = _longest_nondelim_run(variants["entropy_low_mix"].value)
    # The padded run of 'a's should drop entropy below the threshold
    assert shannon(run) < SIPHON_ENTROPY_THRESHOLD


def test_encode_produces_non_empty_output(gen):
    variants = {v.technique: v for v in gen.generate(SEED)}
    encoded = variants["entropy_encode"].value
    assert encoded
    assert encoded != SEED


def test_generator_skips_too_short_values(gen):
    # Value under 4 chars should produce nothing.
    assert list(gen.generate("abc")) == []


def test_generator_preserves_assignment_prefix(gen):
    """Evasion should transform the secret, not the KEY= prefix."""
    prefix = "SECRET_TOKEN="
    variants = list(gen.generate(f"{prefix}{SEED}"))
    assert variants, "expected at least one variant"
    for v in variants:
        # Concat/comment variants rewrite the structure, so we only check the
        # ones that leave the value in-place.
        if v.technique in ("entropy_split", "entropy_low_mix", "entropy_space"):
            assert v.value.startswith(prefix), (
                f"{v.technique} should preserve the '{prefix}' key: {v.value!r}"
            )
