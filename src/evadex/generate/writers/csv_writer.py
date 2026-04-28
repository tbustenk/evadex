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
    from evadex.generate.writers import (
        _active_template, _active_noise_level, _active_density, _active_seed,
        _active_language,
    )

    # Certain templates produce CSV-format output natively (bloomberg_export).
    # For those, use apply_template and write the lines verbatim.
    if _active_template not in ("generic", "email_thread"):
        from evadex.generate.templates import apply_template
        lines = apply_template(
            _active_template, entries,
            seed=_active_seed,
            noise_level=_active_noise_level,
            density=_active_density,
            language=_active_language,
        )
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(lines))
        return

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
