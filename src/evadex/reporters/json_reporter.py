import json
from datetime import datetime, timezone
from collections import defaultdict
from evadex.reporters.base import BaseReporter
from evadex.core.result import ScanResult, SeverityLevel


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

        meta = {
            "timestamp":            datetime.now(timezone.utc).isoformat(),
            "scanner":              self.scanner_label,
            "total":                total,
            "pass":                 passes,
            "fail":                 fails,
            "error":                errors,
            "pass_rate":            round(passes / total * 100, 1) if total else 0.0,
            "summary_by_category":  dict(sorted(by_category.items())),
            "summary_by_generator": dict(sorted(by_generator.items())),
            "summary_by_technique": dict(sorted(by_technique.items())),
        }

        output = {
            "meta": meta,
            "results": [r.to_dict() for r in results],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)
