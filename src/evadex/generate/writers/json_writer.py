"""JSON writer for evadex generate."""
from __future__ import annotations

import json
import random
from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory

_FILLER_FIELDS = [
    ("account_status", ["active", "suspended", "pending_review", "closed", "dormant"]),
    ("department", ["Finance", "Compliance", "HR", "IT", "Operations", "Legal", "Risk"]),
    ("branch", ["Toronto Main", "Vancouver West", "Montreal Centre", "Calgary South", "Ottawa East"]),
    ("risk_rating", ["low", "medium", "high", "critical"]),
    ("currency", ["CAD", "USD", "EUR", "GBP", "CHF"]),
    ("verification_status", ["verified", "pending", "failed", "expired"]),
]

_CATEGORY_FIELD_NAMES: dict[PayloadCategory, str] = {
    PayloadCategory.CREDIT_CARD: "card_number",
    PayloadCategory.SSN: "ssn",
    PayloadCategory.SIN: "sin",
    PayloadCategory.IBAN: "iban",
    PayloadCategory.SWIFT_BIC: "swift_bic",
    PayloadCategory.ABA_ROUTING: "routing_number",
    PayloadCategory.BITCOIN: "btc_address",
    PayloadCategory.ETHEREUM: "eth_address",
    PayloadCategory.EMAIL: "email",
    PayloadCategory.PHONE: "phone",
    PayloadCategory.US_PASSPORT: "passport_number",
}


def write_json(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)

    first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Michael",
                   "Jennifer", "James", "Lisa", "Wei", "Priya", "Ahmed", "Yuki"]
    last_names = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown", "Lee",
                  "Taylor", "Anderson", "Martinez", "Kumar", "Tanaka", "Hassan"]

    records: list[dict] = []
    for i, e in enumerate(entries, 1):
        field_name = _CATEGORY_FIELD_NAMES.get(e.category, e.category.value)

        first = rng.choice(first_names)
        last = rng.choice(last_names)

        record: dict = {
            "customer_id": f"CUST-{i:06d}",
            "name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}@example.com",
            field_name: e.variant_value,
        }

        # Add 2-3 random filler fields
        fillers = rng.sample(_FILLER_FIELDS, rng.randint(2, min(3, len(_FILLER_FIELDS))))
        for field, values in fillers:
            record[field] = rng.choice(values)

        if e.technique:
            record["_evasion_technique"] = e.technique
            record["_generator"] = e.generator_name

        records.append(record)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)
