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
    # Granular amount options
    count_per_category: Optional[dict[str, int]] = None   # category_name -> count
    total: Optional[int] = None                           # distribute N across categories
    density: str = "medium"                               # low, medium, high
    # Granular evasion options
    technique_group: Optional[list[str]] = None           # generator family names
    technique_mix: Optional[dict[str, float]] = None      # generator_name -> proportion
    evasion_per_category: Optional[dict[str, float]] = None  # category_name -> evasion rate
    # Template / noise options
    template: str = "generic"
    noise_level: str = "medium"                           # low, medium, high
    # Smart evasion selection (v3.13.0+)
    # "random" (default), "weighted", "adversarial", "exhaustive"
    evasion_mode: str = "random"
    # Optional {technique_name: scanner_pass_rate} from the audit log.
    # Required for "weighted" / "adversarial"; ignored for "random" /
    # "exhaustive". Cold-start (None or empty) silently falls back to
    # random mode — see evadex.cli.commands.scan for the warning UX.
    technique_history: Optional[dict[str, float]] = None


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
    technique_group: Optional[list[str]] = None,
    technique_mix: Optional[dict[str, float]] = None,
    evasion_mode: str = "random",
    technique_history: Optional[dict[str, float]] = None,
):
    """Return a Variant for plain, or None if none applicable.

    *evasion_mode* selects the technique strategy:

    * ``random``       — uniform random over applicable generators (default).
    * ``weighted``     — weight by ``1 - scanner_pass_rate`` from the audit
      history, so techniques that already evade well are picked more often.
      Falls back to random if no history is available.
    * ``adversarial``  — restrict the candidate pool to techniques whose
      historical scanner-detection rate is ≤ 50 %. Falls back to random
      if the filter leaves no candidates.
    * ``exhaustive``   — pick deterministically (the first applicable
      generator after the auto_applicable / technique_group filter).
      Useful when the caller is iterating to cover every technique.
    """
    # Sort by generator name so seeded shuffles are reproducible regardless of
    # the order in which generator modules were imported. Without this sort,
    # import order (for example, which variant test pytest collects first)
    # shifts the shuffle output and breaks deterministic tests that depend on
    # --seed alone.
    applicable = [
        g for g in generators
        if g.applicable_categories is None or cat in g.applicable_categories
    ]
    # Skip generators that opt out of random selection unless the user has
    # explicitly requested them via --technique-group / --technique-mix.
    explicit_names: set = set(technique_group or [])
    if technique_mix:
        explicit_names.update(technique_mix.keys())
    applicable = [
        g for g in applicable
        if getattr(g, "auto_applicable", True) or g.name in explicit_names
    ]
    applicable.sort(key=lambda g: g.name)

    # Filter by technique group (generator family name)
    if technique_group:
        applicable = [g for g in applicable if g.name in technique_group]

    # If technique_mix is set, pick a generator weighted by proportions
    if technique_mix and applicable:
        weighted = [(g, technique_mix.get(g.name, 0.0)) for g in applicable]
        weighted = [(g, w) for g, w in weighted if w > 0]
        if weighted:
            gens_list, weights = zip(*weighted)
            chosen_gen = rng.choices(list(gens_list), weights=list(weights), k=1)[0]
            try:
                variants = list(chosen_gen.generate(plain))
            except Exception:
                return None
            if allowed_techniques:
                variants = [v for v in variants if v.technique in allowed_techniques]
            return rng.choice(variants) if variants else None

    # ── Smart evasion-mode candidate ordering ─────────────────────────────
    # `applicable` at this point is the post-technique-group / auto-applicable
    # filter pool. Modes other than `random` reshape the order or filter the
    # pool further.
    #
    # Cold-start (no history) used to fall back to uniform random, which
    # defeated the point of `--evasion-mode weighted` on a fresh install.
    # v3.20.0: use the seed weights in `evadex.feedback.seed_weights` so
    # cold-start still biases toward techniques that bypass generic DLP.
    # Once audit history exists, blend 70 % history + 30 % seed so a
    # handful of early scans cannot push the bias off a cliff.
    from evadex.feedback.seed_weights import blend_with_history, SEED_WEIGHTS
    history = technique_history or {}
    if evasion_mode == "exhaustive":
        order = list(applicable)  # deterministic — first generator wins
    elif evasion_mode == "adversarial":
        # Keep only generators whose blended scanner-detection rate is
        # ≤ 0.5. Generators with no data on either side default to
        # 1 - SEED_WEIGHTS[name] (i.e. scanner pass rate implied by the
        # seed bypass probability), then 0.5 if no seed either.
        blended = blend_with_history(history or None,
                                     generators=(g.name for g in applicable))
        kept = [g for g in applicable if blended.get(g.name, 0.5) <= 0.5]
        if not kept:
            kept = list(applicable)  # fall back rather than emit nothing
        order = list(kept)
        rng.shuffle(order)
    elif evasion_mode == "weighted":
        # Weight = 1 - pass_rate. Without history we lean on the seed
        # bypass probabilities directly (= 1 - seed_pass in blend_with_history).
        blended = blend_with_history(history or None,
                                     generators=(g.name for g in applicable))
        weights = [1.0 - blended.get(g.name, 0.5) for g in applicable]
        # Avoid all-zero weights (a 100 %-detected generator would otherwise
        # be impossible to pick at all, which makes history brittle).
        weights = [max(w, 0.05) for w in weights]
        order = rng.choices(applicable, weights=weights, k=len(applicable))
    else:
        # `random` (the default) — uniform shuffle.
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

    # Resolve per-category counts
    cat_counts: dict[PayloadCategory, int] = {}
    cat_list = sorted(by_cat.keys(), key=lambda c: c.value)

    if config.total is not None:
        # Distribute --total evenly across categories
        n_cats = len(cat_list)
        base_count = config.total // n_cats
        remainder = config.total % n_cats
        for idx, cat in enumerate(cat_list):
            cat_counts[cat] = base_count + (1 if idx < remainder else 0)
    else:
        for cat in cat_list:
            if config.count_per_category and cat.value in config.count_per_category:
                cat_counts[cat] = config.count_per_category[cat.value]
            else:
                cat_counts[cat] = config.count

    entries: list[GeneratedEntry] = []
    for cat in cat_list:
        seeds = by_cat[cat]
        count_for_cat = cat_counts[cat]

        # Pre-generate a synthetic pool if a generator is registered for this category
        syn_gen = get_synthetic_generator(cat)
        if syn_gen is not None and count_for_cat > len(seeds):
            seed_val = rng.randint(0, 2 ** 31)
            _synthetic_pools[cat] = syn_gen.generate(count_for_cat, seed=seed_val)

        # Per-category evasion rate override
        cat_evasion_rate = evasion_rate
        if config.evasion_per_category and cat.value in config.evasion_per_category:
            cat_evasion_rate = config.evasion_per_category[cat.value]

        for i in range(count_for_cat):
            plain = _pick_plain_value(rng, cat, seeds, i, _synthetic_pools)

            # Evasion decision
            do_evasion = rng.random() < cat_evasion_rate
            technique: Optional[str] = None
            gen_name: Optional[str] = None
            transform: Optional[str] = None
            variant_value = plain

            if do_evasion:
                v = _pick_variant(
                    rng, plain, cat, gens, techniques,
                    technique_group=config.technique_group,
                    technique_mix=config.technique_mix,
                    evasion_mode=config.evasion_mode,
                    technique_history=config.technique_history,
                )
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
