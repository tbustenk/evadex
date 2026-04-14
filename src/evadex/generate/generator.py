"""Core generation logic for evadex generate command."""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from evadex.core.registry import load_builtins, all_generators
from evadex.core.result import PayloadCategory
from evadex.payloads.builtins import get_payloads, HEURISTIC_CATEGORIES


# Visa, Mastercard, Amex, Discover, JCB — (prefix, total_length)
_CC_PREFIXES: list[tuple[str, int]] = [
    ("4", 16),
    ("51", 16), ("52", 16), ("53", 16), ("54", 16), ("55", 16),
    ("34", 15), ("37", 15),
    ("6011", 16),
    ("3528", 16), ("3589", 16),
]


@dataclass
class GeneratedEntry:
    category: PayloadCategory
    plain_value: str
    variant_value: str       # equals plain_value when no evasion applied
    technique: Optional[str]       # None when no evasion
    generator_name: Optional[str]  # None when no evasion
    transform_name: Optional[str]  # None when no evasion
    has_keywords: bool
    embedded_text: str       # final sentence/paragraph for the document


@dataclass
class GenerateConfig:
    fmt: str
    categories: Optional[list[PayloadCategory]] = None
    count: int = 100
    evasion_rate: float = 0.5
    keyword_rate: float = 0.5
    techniques: Optional[list[str]] = None   # None = all techniques allowed
    random_mode: bool = False
    seed: Optional[int] = None
    output: str = "output"
    include_heuristic: bool = False
    language: str = "en"   # "en" or "fr-CA"


# ── Luhn-valid credit card generation ─────────────────────────────────────────

def _luhn_check_digit(digits: list[int]) -> int:
    """Return Luhn check digit for a digit list (without the check digit)."""
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - (total % 10)) % 10


def _generate_cc(rng: random.Random, prefix: str, length: int) -> str:
    body_len = length - len(prefix) - 1
    body = [rng.randint(0, 9) for _ in range(body_len)]
    all_digits = [int(c) for c in prefix] + body
    check = _luhn_check_digit(all_digits)
    return prefix + "".join(str(d) for d in body) + str(check)


# ── Value pool helpers ─────────────────────────────────────────────────────────

def _pick_plain_value(
    rng: random.Random,
    cat: PayloadCategory,
    seeds: list[str],
    idx: int,
    synthetic_pools: Optional[dict] = None,
) -> str:
    if cat == PayloadCategory.CREDIT_CARD:
        prefix, length = rng.choice(_CC_PREFIXES)
        return _generate_cc(rng, prefix, length)
    # Use synthetic pool if available for this category
    if synthetic_pools and cat in synthetic_pools:
        pool = synthetic_pools[cat]
        if pool:
            return pool[idx % len(pool)]
    # Fallback: rotate through seed values
    return seeds[idx % len(seeds)]


def _pick_variant(
    rng: random.Random,
    plain: str,
    cat: PayloadCategory,
    generators: list,
    allowed_techniques: Optional[list[str]],
):
    """Return a random Variant for plain, or None if none applicable."""
    applicable = [
        g for g in generators
        if g.applicable_categories is None or cat in g.applicable_categories
    ]
    order = list(applicable)
    rng.shuffle(order)
    for gen in order:
        try:
            variants = list(gen.generate(plain))
        except Exception:
            continue
        if allowed_techniques:
            variants = [v for v in variants if v.technique in allowed_techniques]
        if variants:
            return rng.choice(variants)
    return None


def _random_categories(rng: random.Random, include_heuristic: bool) -> list[PayloadCategory]:
    pool = [
        c for c in PayloadCategory
        if c != PayloadCategory.UNKNOWN
        and (include_heuristic or c not in HEURISTIC_CATEGORIES)
    ]
    k = rng.randint(2, min(5, len(pool)))
    return rng.sample(pool, k)


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_entries(config: GenerateConfig) -> list[GeneratedEntry]:
    """
    Generate a list of GeneratedEntry objects based on config.

    Returns count entries *per resolved category*.
    """
    load_builtins()
    from evadex.synthetic.registry import load_synthetic_generators
    load_synthetic_generators()
    rng = random.Random(config.seed)

    if config.random_mode:
        cats = _random_categories(rng, config.include_heuristic)
        evasion_rate = rng.uniform(0.2, 0.8)
        keyword_rate = rng.uniform(0.2, 0.8)
        techniques = None
    else:
        cats = config.categories  # None = all structured (+ heuristic if flag set)
        evasion_rate = config.evasion_rate
        keyword_rate = config.keyword_rate
        techniques = config.techniques

    include_heuristic = config.include_heuristic or bool(
        cats and any(c in HEURISTIC_CATEGORIES for c in cats)
    )
    payloads = get_payloads(categories=cats, include_heuristic=include_heuristic)
    if not payloads:
        return []

    # Group seed values by category
    by_cat: dict[PayloadCategory, list[str]] = {}
    for p in payloads:
        by_cat.setdefault(p.category, []).append(p.value)

    gens = all_generators()

    from evadex.generate.filler import get_keyword_sentence
    from evadex.synthetic.registry import get_synthetic_generator

    # Build per-category synthetic value pools for categories that have generators
    _synthetic_pools: dict[PayloadCategory, list[str]] = {}

    entries: list[GeneratedEntry] = []
    for cat, seeds in sorted(by_cat.items(), key=lambda kv: kv[0].value):
        # Pre-generate a synthetic pool if a generator is registered for this category
        syn_gen = get_synthetic_generator(cat)
        if syn_gen is not None and config.count > len(seeds):
            seed_val = rng.randint(0, 2 ** 31)
            _synthetic_pools[cat] = syn_gen.generate(config.count, seed=seed_val)

        for i in range(config.count):
            plain = _pick_plain_value(rng, cat, seeds, i, _synthetic_pools)

            # Evasion decision
            do_evasion = rng.random() < evasion_rate
            technique: Optional[str] = None
            gen_name: Optional[str] = None
            transform: Optional[str] = None
            variant_value = plain

            if do_evasion:
                v = _pick_variant(rng, plain, cat, gens, techniques)
                if v is not None:
                    variant_value = v.value
                    technique = v.technique
                    gen_name = v.generator
                    transform = v.transform_name

            # Context-injection variants already supply realistic sentences;
            # skip keyword wrapping to avoid double-nesting.
            if gen_name == "context_injection":
                embedded = variant_value
                kw = True
            elif rng.random() < keyword_rate:
                embedded = get_keyword_sentence(rng, cat, variant_value, config.language)
                kw = True
            else:
                embedded = variant_value
                kw = False

            entries.append(GeneratedEntry(
                category=cat,
                plain_value=plain,
                variant_value=variant_value,
                technique=technique,
                generator_name=gen_name,
                transform_name=transform,
                has_keywords=kw,
                embedded_text=embedded,
            ))

    return entries
