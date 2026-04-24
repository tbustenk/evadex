import json
from datetime import datetime, timezone
from collections import defaultdict
from evadex.reporters.base import BaseReporter
from evadex.core.result import ScanResult, SeverityLevel


_CONFIDENCE_BUCKETS = [
    ("0.9-1.0", 0.9, 1.01),
    ("0.7-0.9", 0.7, 0.9),
    ("0.5-0.7", 0.5, 0.7),
    ("0.3-0.5", 0.3, 0.5),
    ("0.0-0.3", 0.0, 0.3),
]


def _confidence_histogram(results: list[ScanResult]) -> dict:
    """Distribution of confidence scores across detected matches."""
    buckets: dict = {label: 0 for label, _lo, _hi in _CONFIDENCE_BUCKETS}
    total = 0
    for r in results:
        if not r.detected or r.confidence is None:
            continue
        try:
            c = float(r.confidence)
        except (TypeError, ValueError):
            continue
        total += 1
        for label, lo, hi in _CONFIDENCE_BUCKETS:
            if lo <= c < hi:
                buckets[label] += 1
                break
    return {"total": total, "buckets": buckets}


def _enrich_by_technique(
    counts_by_technique: dict,
    results: list[ScanResult],
) -> dict:
    """Add evasion_rate + example_evaded_value + example_detected_value."""
    first_evaded: dict = {}
    first_detected: dict = {}
    for r in results:
        tech = r.variant.technique or r.variant.generator
        if r.severity == SeverityLevel.FAIL and tech not in first_evaded:
            first_evaded[tech] = r.variant.value
        if r.severity == SeverityLevel.PASS and tech not in first_detected:
            first_detected[tech] = r.variant.value

    out: dict = {}
    for tech, counts in counts_by_technique.items():
        p, f, e = counts["pass"], counts["fail"], counts["error"]
        denom = p + f
        evasion_rate = round(f / denom * 100, 1) if denom else 0.0
        entry = {
            "pass": p, "fail": f, "error": e,
            "evasion_rate": evasion_rate,
        }
        if tech in first_evaded:
            entry["example_evaded_value"] = first_evaded[tech][:200]
        if tech in first_detected:
            entry["example_detected_value"] = first_detected[tech][:200]
        out[tech] = entry
    return out


def _enrich_by_category(
    counts_by_category: dict,
    results: list[ScanResult],
) -> dict:
    """Add evasion_rate + worst_technique + best_technique + sample_evaded."""
    per_cat_tech: dict = defaultdict(lambda: defaultdict(lambda: {"pass": 0, "fail": 0}))
    sample_evaded: dict = {}
    for r in results:
        cat = r.payload.category.value
        if r.severity == SeverityLevel.ERROR:
            continue
        tech = r.variant.technique or r.variant.generator
        per_cat_tech[cat][tech][r.severity.value] += 1
        if r.severity == SeverityLevel.FAIL and cat not in sample_evaded:
            sample_evaded[cat] = r.variant.value

    out: dict = {}
    for cat, counts in counts_by_category.items():
        p, f, e = counts["pass"], counts["fail"], counts["error"]
        denom = p + f
        evasion_rate = round(f / denom * 100, 1) if denom else 0.0
        entry = {
            "pass": p, "fail": f, "error": e,
            "evasion_rate": evasion_rate,
        }
        tech_map = per_cat_tech.get(cat, {})
        tech_rates = []
        for tech, tc in tech_map.items():
            td = tc["pass"] + tc["fail"]
            if td < 3:  # ignore tiny samples
                continue
            tech_rates.append((tech, round(tc["fail"] / td * 100, 1), td))
        if tech_rates:
            tech_rates.sort(key=lambda x: x[1])
            entry["best_technique"] = {"technique": tech_rates[0][0], "evasion_rate": tech_rates[0][1], "samples": tech_rates[0][2]}
            entry["worst_technique"] = {"technique": tech_rates[-1][0], "evasion_rate": tech_rates[-1][1], "samples": tech_rates[-1][2]}
        if cat in sample_evaded:
            entry["sample_evaded"] = sample_evaded[cat][:200]
        out[cat] = entry
    return out


class JsonReporter(BaseReporter):
    def __init__(self, scanner_label: str = ""):
        self.scanner_label = scanner_label

    def render(self, results: list[ScanResult]) -> str:
        total = len(results)
        passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
        fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
        errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)

        by_category: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
        by_generator: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
        by_technique: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
        for r in results:
            by_category[r.payload.category.value][r.severity.value] += 1
            by_generator[r.variant.generator][r.severity.value] += 1
            tech = r.variant.technique or r.variant.generator
            by_technique[tech][r.severity.value] += 1

        # v3.21.0: enrich with evasion_rate + examples so JSON consumers (HTML
        # report, feedback tooling, dashboards) can render actionable output
        # without re-walking the full results list.
        enriched_by_technique = _enrich_by_technique(dict(by_technique), results)
        enriched_by_category = _enrich_by_category(dict(by_category), results)
        confidence_dist = _confidence_histogram(results)

        meta = {
            "timestamp":            datetime.now(timezone.utc).isoformat(),
            "scanner":              self.scanner_label,
            "total":                total,
            "pass":                 passes,
            "fail":                 fails,
            "error":                errors,
            "pass_rate":            round(passes / total * 100, 1) if total else 0.0,
            "summary_by_category":  dict(sorted(enriched_by_category.items())),
            "summary_by_generator": dict(sorted(by_generator.items())),
            "summary_by_technique": dict(sorted(enriched_by_technique.items())),
            "confidence_distribution": confidence_dist,
        }

        output = {
            "meta": meta,
            "results": [r.to_dict() for r in results],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)
