from typing import Iterator
from evadex.core.registry import register_generator
from evadex.core.result import Variant
from evadex.variants.base import BaseVariantGenerator

# Realistic sentence templates that embed the sensitive value in surrounding text.
# Uses str.replace rather than str.format so values containing { or } are safe.
# Ordered from most to least realistic document context.
TEMPLATES = [
    (
        "Please charge card number {value} for the amount due.",
        "sentence_payment_request",
        "Value in payment request sentence",
    ),
    (
        "Reference: {value} — please keep confidential.",
        "sentence_reference",
        "Value in confidential reference sentence",
    ),
    (
        "Dear Customer,\n\nYour account identifier is {value}.\n\nRegards,\nSupport Team",
        "email_body",
        "Value embedded inside an email body",
    ),
    (
        "2026-04-03 09:15:22 INFO  Processed record {value} successfully",
        "log_line",
        "Value embedded in a log line",
    ),
    (
        "Name: John Smith\nData: {value}\nDate: 2026-04-03\nDepartment: Finance",
        "multiline_form",
        "Value in a multiline form-style block",
    ),
    (
        "Note to auditor: the sensitive value {value} appears in the Q1 report, page 14.",
        "audit_note",
        "Value referenced in an audit note",
    ),
    (
        "<record><id>REF-2026-001</id><data>{value}</data><status>pending</status></record>",
        "xml_record",
        "Value inside an XML-like record element",
    ),
    (
        '{"type": "transaction", "ref": "{value}", "amount": 1200, "currency": "USD"}',
        "json_record",
        "Value inside a JSON-like transaction record",
    ),
    (
        "From: billing@example.com\nTo: accounts@corp.com\nSubject: Invoice\n\nSee attached. Key ref: {value}.",
        "email_header_body",
        "Value in an email with headers and body",
    ),
    (
        "CONFIDENTIAL — Internal Use Only\n\nRecord ID: {value}\nClassification: PCI",
        "confidential_header",
        "Value under a confidential document header",
    ),
]


@register_generator("context_injection")
class ContextInjectionGenerator(BaseVariantGenerator):
    name = "context_injection"
    # Applies to all payload categories — context embedding is category-agnostic

    def generate(self, value: str) -> Iterator[Variant]:
        for template, technique, desc in TEMPLATES:
            yield self._make_variant(template.replace("{value}", value), technique, desc)
