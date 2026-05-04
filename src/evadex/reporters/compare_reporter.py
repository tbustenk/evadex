import json
from datetime import datetime, timezone
from evadex.reporters.base import BaseReporter


class CompareReporter(BaseReporter):
    """Renders a comparison dict as JSON."""

    def render(self, comparison: dict) -> str:  # type: ignore[override]
        out = {
            "meta": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "label_a":   comparison["label_a"],
                "label_b":   comparison["label_b"],
                "overall":   comparison["overall"],
            },
            "by_category":  comparison["by_category"],
            "by_technique": comparison["by_technique"],
            "diffs":        comparison["diffs"],
            "verdict":      comparison.get("verdict"),
        }
        return json.dumps(out, indent=2, ensure_ascii=False)
