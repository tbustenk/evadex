import json
from datetime import datetime, timezone
from collections import defaultdict
from evadex.reporters.base import BaseReporter
from evadex.core.result import ScanResult, SeverityLevel


class JsonReporter(BaseReporter):
    def render(self, results: list[ScanResult]) -> str:
        total = len(results)
        passes = sum(1 for r in results if r.severity == SeverityLevel.PASS)
        fails  = sum(1 for r in results if r.severity == SeverityLevel.FAIL)
        errors = sum(1 for r in results if r.severity == SeverityLevel.ERROR)

        by_category: dict = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0})
        for r in results:
            cat = r.payload.category.value
            by_category[cat][r.severity.value] += 1

        output = {
            "meta": {
                "timestamp":           datetime.now(timezone.utc).isoformat(),
                "total":               total,
                "pass":                passes,
                "fail":                fails,
                "error":               errors,
                "pass_rate":           round(passes / total * 100, 1) if total else 0,
                "summary_by_category": dict(by_category),
            },
            "results": [r.to_dict() for r in results],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)
