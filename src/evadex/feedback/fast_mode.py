"""Fast-mode technique selection for ``evadex scan --fast``.

Full scans spawn one subprocess per variant on Windows (~50 ms each);
9,000 variants => 7–8 min wall-clock. Fast mode trims the variant pool
to the top-N techniques per generator family by historical bypass rate,
dropping techniques known to be ineffective.

Budget rationale
----------------

* 5 techniques per generator × 16 generators ≈ 80 techniques max —
  typically a 70–85 % reduction vs exhaustive mode.
* Any technique whose blended bypass weight < 0.10 is dropped
  regardless of rank — keeping a technique that evades 5 % of the time
  only wastes subprocess spawns.

Weight sources
--------------

* :mod:`evadex.feedback.seed_weights` provides static weights used as
  the cold-start source.
* :mod:`evadex.feedback.technique_history` surfaces empirical
  scanner-detection rates from ``audit.jsonl``. Detection rate → bypass
  rate is ``1 - detection``.

Improvements (v3.28.0)
-----------------------

* **Exponential decay**: more recent audit entries are weighted more
  heavily than older ones, with a configurable half-life. This means a
  recently-patched scanner technique degrades quickly in weight rather
  than dragging down the average for months.
* **Per-category technique selection**: different payload categories
  respond differently to evasion techniques (e.g. structured numeric IDs
  like SSN are more vulnerable to digit-script substitution than credit
  cards). When ``per_category=True``, technique weights are computed
  separately per category from the audit log.

The blend matches the documented behaviour of the ``weighted`` evasion
mode: 70 % history / 30 % seed when history is available, pure seed
otherwise.
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Iterable, Optional

from evadex.feedback.seed_weights import SEED_WEIGHTS, TECHNIQUE_SEED_WEIGHTS
from evadex.feedback.technique_history import has_history, load_technique_history

DEFAULT_TOP_PER_GENERATOR = 5
DEFAULT_MIN_BYPASS = 0.10

# Half-life for exponential decay: runs older than this many audit entries
# are down-weighted by half. Smaller values = favour recent data more.
DEFAULT_DECAY_HALF_LIFE = 5


def _sample_value() -> str:
    """Alphanumeric fixed sample so every generator branch fires."""
    return "4532015112830366"


def _decay_weight(position: int, total: int, half_life: int) -> float:
    """Return an exponential decay factor for an audit entry.

    *position* is 0-indexed from the **oldest** entry in the log; the
    *total* number of entries is used to compute how old the entry is
    relative to the most recent one.

    Entries are weighted by ``2^(-age / half_life)`` where *age* is
    ``total - 1 - position`` (so the newest entry has age 0 and weight 1.0).
    """
    age = total - 1 - position  # 0 for newest, total-1 for oldest
    return math.pow(2.0, -age / max(1, half_life))


def _load_history_bypass_with_decay(
    audit_log: Optional[str],
    half_life: int = DEFAULT_DECAY_HALF_LIFE,
) -> dict[str, float]:
    """Load technique bypass rates with exponential decay on older runs.

    Returns ``{technique: weighted_bypass_rate}`` using a decay-weighted
    average across all audit entries. Recent entries contribute more than
    older ones.
    """
    if not audit_log or not has_history(audit_log):
        return {}

    from evadex.feedback.technique_history import _iter_audit_entries

    entries = [
        e for e in _iter_audit_entries(audit_log) if e.get("technique_success_rates")
    ]
    if not entries:
        return {}

    total = len(entries)
    # Accumulate decay-weighted bypass rates per technique
    weighted_sum: dict[str, float] = defaultdict(float)
    weight_total: dict[str, float] = defaultdict(float)

    for pos, entry in enumerate(entries):
        w = _decay_weight(pos, total, half_life)
        rates = entry.get("technique_success_rates") or {}
        for tech, pass_rate in rates.items():
            try:
                bypass = max(0.0, min(1.0, 1.0 - float(pass_rate)))
            except (TypeError, ValueError):
                continue
            weighted_sum[tech] += w * bypass
            weight_total[tech] += w

    return {
        tech: weighted_sum[tech] / weight_total[tech]
        for tech in weighted_sum
        if weight_total[tech] > 0
    }


def _load_history_bypass_per_category(
    audit_log: Optional[str],
    half_life: int = DEFAULT_DECAY_HALF_LIFE,
) -> dict[str, dict[str, float]]:
    """Load per-category technique bypass rates with exponential decay.

    Returns ``{category: {technique: weighted_bypass_rate}}``.
    Audit entries that include ``category_technique_rates`` (a nested
    mapping) are used; entries without that field are skipped for
    per-category analysis.
    """
    if not audit_log or not has_history(audit_log):
        return {}

    from evadex.feedback.technique_history import _iter_audit_entries

    entries = [
        e
        for e in _iter_audit_entries(audit_log)
        if e.get("category_technique_rates")
    ]
    if not entries:
        return {}

    total = len(entries)
    # {category: {technique: (weighted_sum, weight_total)}}
    accum: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(lambda: [0.0, 0.0]))

    for pos, entry in enumerate(entries):
        w = _decay_weight(pos, total, half_life)
        cat_rates = entry.get("category_technique_rates") or {}
        for cat, tech_rates in cat_rates.items():
            for tech, pass_rate in tech_rates.items():
                try:
                    bypass = max(0.0, min(1.0, 1.0 - float(pass_rate)))
                except (TypeError, ValueError):
                    continue
                accum[cat][tech][0] += w * bypass
                accum[cat][tech][1] += w

    out: dict[str, dict[str, float]] = {}
    for cat, techs in accum.items():
        out[cat] = {
            tech: vals[0] / vals[1]
            for tech, vals in techs.items()
            if vals[1] > 0
        }
    return out


def _load_history_bypass(audit_log: Optional[str]) -> dict[str, float]:
    """Legacy flat bypass loader (no decay) for backwards compat."""
    if not audit_log or not has_history(audit_log):
        return {}
    stats = load_technique_history(audit_log)
    return {t: max(0.0, min(1.0, 1.0 - s.average_success)) for t, s in stats.items()}


def _technique_bypass_weight(
    technique: str,
    generator_name: str,
    history_bypass: dict[str, float],
) -> float:
    """Return a blended bypass probability for *technique*.

    * If audit history exists for *technique*, blend 70/30 with the seed.
    * Otherwise fall back to ``TECHNIQUE_SEED_WEIGHTS`` then the generator
      family seed.
    """
    seed = (
        TECHNIQUE_SEED_WEIGHTS.get(technique) or SEED_WEIGHTS.get(generator_name) or 0.5
    )
    hist = history_bypass.get(technique)
    if hist is None:
        return float(seed)
    return 0.7 * float(hist) + 0.3 * float(seed)


def pick_fast_techniques(
    generators: Iterable,
    audit_log: Optional[str] = None,
    top_per_generator: int = DEFAULT_TOP_PER_GENERATOR,
    min_bypass: float = DEFAULT_MIN_BYPASS,
    use_decay: bool = True,
    decay_half_life: int = DEFAULT_DECAY_HALF_LIFE,
    per_category: bool = False,
    verbose: bool = False,
) -> tuple[set[str], dict]:
    """Return the set of technique names fast mode should run.

    Parameters
    ----------
    generators
        Iterable of instantiated ``BaseVariantGenerator`` objects.
    audit_log
        Path to ``audit.jsonl`` (optional — cold-start falls back to seeds).
    top_per_generator
        Keep at most this many techniques per generator family.
    min_bypass
        Drop techniques whose blended bypass weight is below this value.
    use_decay
        If True (default), weight recent audit entries more heavily than
        older ones using exponential decay (v3.28.0).
    decay_half_life
        Number of audit entries after which a run's weight halves.
        Only used when ``use_decay=True``.
    per_category
        If True, compute per-category technique weights from the audit log
        and include category-level diagnostics in the returned diag dict.
    verbose
        If True, include per-generator technique weights in the diag dict
        for human-readable ``--verbose`` output.

    Returns
    -------
    (allowed_techniques, diag)
        ``allowed_techniques`` is a set of technique names — pass to
        :class:`evadex.core.engine.Engine` as ``technique_filter``.
        ``diag`` is a mapping with ``dropped``, ``total_enumerated``,
        ``per_generator`` for reporting.
    """
    if use_decay:
        history_bypass = _load_history_bypass_with_decay(audit_log, decay_half_life)
    else:
        history_bypass = _load_history_bypass(audit_log)

    per_cat_bypass: dict[str, dict[str, float]] = {}
    if per_category:
        per_cat_bypass = _load_history_bypass_per_category(audit_log, decay_half_life)

    sample = _sample_value()

    per_gen_ranked: dict[str, list[tuple[str, float]]] = {}
    total_enumerated = 0
    for gen in generators:
        seen: dict[str, float] = {}
        try:
            variants = list(gen.generate(sample))
        except Exception:
            continue
        for v in variants:
            if v.technique in seen:
                continue
            seen[v.technique] = _technique_bypass_weight(
                v.technique,
                gen.name,
                history_bypass,
            )
        total_enumerated += len(seen)
        ranked = sorted(seen.items(), key=lambda kv: -kv[1])
        per_gen_ranked[gen.name] = ranked

    allowed: set[str] = set()
    kept_per_gen: dict = defaultdict(list)
    dropped = 0
    for gen_name, ranked in per_gen_ranked.items():
        kept_count = 0
        for technique, weight in ranked:
            if kept_count >= top_per_generator:
                dropped += 1
                continue
            if weight < min_bypass:
                dropped += 1
                continue
            allowed.add(technique)
            kept_per_gen[gen_name].append((technique, round(weight, 3)))
            kept_count += 1

    diag: dict = {
        "total_enumerated": total_enumerated,
        "kept": len(allowed),
        "dropped": dropped,
        "per_generator": dict(kept_per_gen),
        "has_history": bool(history_bypass),
        "used_decay": use_decay,
        "decay_half_life": decay_half_life if use_decay else None,
    }

    if per_category and per_cat_bypass:
        diag["per_category"] = per_cat_bypass

    if verbose:
        diag["verbose_weights"] = {
            gen: [(t, round(w, 3)) for t, w in ranked]
            for gen, ranked in per_gen_ranked.items()
        }

    return allowed, diag
