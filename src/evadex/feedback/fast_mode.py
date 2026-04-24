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

The blend matches the documented behaviour of the ``weighted`` evasion
mode: 70 % history / 30 % seed when history is available, pure seed
otherwise.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Optional

from evadex.feedback.seed_weights import SEED_WEIGHTS, TECHNIQUE_SEED_WEIGHTS
from evadex.feedback.technique_history import has_history, load_technique_history

DEFAULT_TOP_PER_GENERATOR = 5
DEFAULT_MIN_BYPASS = 0.10


def _sample_value() -> str:
    """Alphanumeric fixed sample so every generator branch fires."""
    return "4532015112830366"


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
        TECHNIQUE_SEED_WEIGHTS.get(technique)
        or SEED_WEIGHTS.get(generator_name)
        or 0.5
    )
    hist = history_bypass.get(technique)
    if hist is None:
        return float(seed)
    return 0.7 * float(hist) + 0.3 * float(seed)


def _load_history_bypass(audit_log: Optional[str]) -> dict[str, float]:
    """Scanner detection rates → technique bypass rates."""
    if not audit_log or not has_history(audit_log):
        return {}
    stats = load_technique_history(audit_log)
    return {
        t: max(0.0, min(1.0, 1.0 - s.average_success))
        for t, s in stats.items()
    }


def pick_fast_techniques(
    generators: Iterable,
    audit_log: Optional[str] = None,
    top_per_generator: int = DEFAULT_TOP_PER_GENERATOR,
    min_bypass: float = DEFAULT_MIN_BYPASS,
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

    Returns
    -------
    (allowed_techniques, diag)
        ``allowed_techniques`` is a set of technique names — pass to
        :class:`evadex.core.engine.Engine` as ``technique_filter``.
        ``diag`` is a mapping with ``dropped``, ``total_enumerated``,
        ``per_generator`` for reporting.
    """
    history_bypass = _load_history_bypass(audit_log)
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
                v.technique, gen.name, history_bypass,
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

    diag = {
        "total_enumerated": total_enumerated,
        "kept":             len(allowed),
        "dropped":          dropped,
        "per_generator":    dict(kept_per_gen),
        "has_history":      bool(history_bypass),
    }
    return allowed, diag
