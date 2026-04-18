"""Writer for Siphon EDM bulk-registration JSON.

The shape matches Siphon's ``/v1/edm/register`` request body:

    {
        "values": [
            {"value": "4532015112830366",
             "category": "credit_card",
             "label": "Visa test"},
            ...
        ]
    }

Consumers can split the list per category and POST each slice to
``/v1/edm/register`` (which accepts one category at a time). Keeping
the output flat makes that trivial and also lets the file double as
an evadex ``edm_corpus.json``.
"""
from __future__ import annotations

import json

from evadex.generate.generator import GeneratedEntry


def write_edm_json(entries: list[GeneratedEntry], path: str) -> None:
    body = {
        "values": [
            {
                "value": e.variant_value,
                "category": e.category.value,
                "label": e.plain_value,
            }
            for e in entries
        ]
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, ensure_ascii=False)
