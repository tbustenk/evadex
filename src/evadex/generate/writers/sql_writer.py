"""SQL writer for evadex generate — database dump format."""
from __future__ import annotations

import datetime
import random
from evadex.generate.generator import GeneratedEntry
from evadex.core.result import PayloadCategory

_CATEGORY_COLUMN: dict[PayloadCategory, str] = {
    PayloadCategory.CREDIT_CARD: "card_number",
    PayloadCategory.SSN: "ssn",
    PayloadCategory.SIN: "sin",
    PayloadCategory.IBAN: "iban",
    PayloadCategory.SWIFT_BIC: "swift_bic",
    PayloadCategory.ABA_ROUTING: "routing_number",
    PayloadCategory.BITCOIN: "btc_address",
    PayloadCategory.ETHEREUM: "eth_address",
    PayloadCategory.EMAIL: "email_address",
    PayloadCategory.PHONE: "phone_number",
    PayloadCategory.US_PASSPORT: "passport_number",
}


def _sql_escape(val: str) -> str:
    return val.replace("'", "''").replace("\\", "\\\\")


def write_sql(entries: list[GeneratedEntry], path: str) -> None:
    rng = random.Random(42)
    today = datetime.date.today().isoformat()

    first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Michael",
                   "Jennifer", "James", "Lisa", "Wei", "Priya", "Ahmed", "Yuki"]
    last_names = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown", "Lee",
                  "Taylor", "Anderson", "Martinez", "Kumar", "Tanaka", "Hassan"]
    departments = ["Finance", "Compliance", "HR", "IT", "Operations", "Legal", "Risk"]

    # The schema declares every category column up-front so each INSERT
    # can target the column matching its payload (card_number, sin, …)
    # rather than overloading a single ``sensitive_val`` field.
    # All payload columns are NULL-able since any one row only fills
    # the column that matches its category.
    lines: list[str] = [
        f"-- evadex DLP test data — generated {today}",
        "-- CONFIDENTIAL — For DLP Scanner Testing Only",
        "",
        "CREATE TABLE IF NOT EXISTS customers (",
        "    id              INT PRIMARY KEY AUTO_INCREMENT,",
        "    first_name      VARCHAR(100) NOT NULL,",
        "    last_name       VARCHAR(100) NOT NULL,",
        "    department      VARCHAR(50),",
        "    sensitive_val   VARCHAR(500),",
        "    card_number     VARCHAR(500),",
        "    ssn             VARCHAR(500),",
        "    sin             VARCHAR(500),",
        "    iban            VARCHAR(500),",
        "    swift_bic       VARCHAR(500),",
        "    routing_number  VARCHAR(500),",
        "    btc_address     VARCHAR(500),",
        "    eth_address     VARCHAR(500),",
        "    email_address   VARCHAR(500),",
        "    phone_number    VARCHAR(500),",
        "    passport_number VARCHAR(500),",
        "    category        VARCHAR(50) NOT NULL,",
        "    notes           TEXT,",
        "    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP",
        ");",
        "",
    ]

    for i, e in enumerate(entries, 1):
        first = rng.choice(first_names)
        last = rng.choice(last_names)
        dept = rng.choice(departments)
        col_name = _CATEGORY_COLUMN.get(e.category, "sensitive_val")
        # Context-injection variants embed value in a sentence — use plain
        # value for the structured column, sentence goes in notes.
        raw_val = e.plain_value if e.generator_name == "context_injection" else e.variant_value
        val = _sql_escape(raw_val)
        notes = _sql_escape(e.embedded_text)

        # Use category-specific column name in the INSERT
        lines.append(
            f"INSERT INTO customers (id, first_name, last_name, department, "
            f"{col_name}, category, notes) VALUES "
            f"({i}, '{_sql_escape(first)}', '{_sql_escape(last)}', '{dept}', "
            f"'{val}', '{e.category.value}', '{notes}');"
        )

        # Every 20 rows, add a comment separator
        if i % 20 == 0:
            lines.append(f"-- batch {i // 20} complete")

    lines.append("")
    lines.append(f"-- {len(entries)} rows inserted")
    lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
