"""Structured feedback report: techniques, fix suggestions, and regression test code."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone

from evadex.core.result import ScanResult, SeverityLevel
from evadex.feedback.regression_writer import generate_regression_code
from evadex.feedback.suggestions import get_suggestions


def generate_feedback_report(
    results: list[ScanResult],
    scanner_label: str = "",
) -> dict:
    """Build a JSON-serialisable feedback report dict."""
    total    = len(results)
    evasions = [r for r in results if r.severity == SeverityLevel.FAIL]

    # Aggregate per-technique: count + up to 3 example variant values
    tech_stats: dict[str, dict] = defaultdict(lambda: {
        "count": 0,
        "generator": "",
        "example_variants": [],
    })
    for r in evasions:
        tech = r.variant.technique
        stats = tech_stats[tech]
        stats["count"] += 1
        stats["generator"] = r.variant.generator
        if len(stats["example_variants"]) < 3:
            stats["example_variants"].append(r.variant.value)

    techniques = [
        {
            "technique": tech,
            "generator": stats["generator"],
            "count": stats["count"],
            "example_variants": stats["example_variants"],
        }
        for tech, stats in sorted(
            tech_stats.items(), key=lambda kv: kv[1]["count"], reverse=True
        )
    ]

    suggestions = get_suggestions(results)

    return {
        "meta": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanner": scanner_label,
            "total_tests": total,
            "total_evasions": len(evasions),
        },
        "techniques": techniques,
        "regression_test_code": generate_regression_code(results),
        "fix_suggestions": [
            {
                "technique": s.technique,
                "generator": s.generator,
                "description": s.description,
                "suggested_fix": s.suggested_fix,
            }
            for s in suggestions
        ],
    }


def write_feedback_report(
    results: list[ScanResult],
    path: str,
    scanner_label: str = "",
) -> None:
    """Write the feedback report as JSON to *path*."""
    report = generate_feedback_report(results, scanner_label=scanner_label)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
