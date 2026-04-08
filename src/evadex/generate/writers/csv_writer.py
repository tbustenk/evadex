"""CSV writer for evadex generate."""
from __future__ import annotations

import csv
from evadex.generate.generator import GeneratedEntry


_FIELDNAMES = [
    "category",
    "plain_value",
    "variant_value",
    "technique",
    "generator",
    "transform_name",
    "has_keywords",
    "embedded_text",
]


def write_csv(entries: list[GeneratedEntry], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES)
        writer.writeheader()
        for e in entries:
            writer.writerow({
                "category":       e.category.value,
                "plain_value":    e.plain_value,
                "variant_value":  e.variant_value,
                "technique":      e.technique or "",
                "generator":      e.generator_name or "",
                "transform_name": e.transform_name or "",
                "has_keywords":   str(e.has_keywords),
                "embedded_text":  e.embedded_text,
            })
