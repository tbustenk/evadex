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
    # French Canadian context templates
    (
        "Veuillez débiter la carte numéro {value} pour le montant dû.",
        "fr_ca_sentence_payment_request",
        "Value in French Canadian payment request sentence",
    ),
    (
        "Référence : {value} — veuillez traiter ce document de façon confidentielle.",
        "fr_ca_sentence_reference",
        "Value in French Canadian confidential reference sentence",
    ),
    (
        "Bonjour,\n\nVotre identifiant de compte est {value}.\n\nCordialement,\nService à la clientèle",
        "fr_ca_email_body",
        "Value embedded inside a French Canadian email body",
    ),
    (
        "2026-04-03 09:15:22 INFO  Dossier {value} traité avec succès",
        "fr_ca_log_line",
        "Value embedded in a French Canadian log line",
    ),
    (
        "Nom : Jean Tremblay\nDonnée : {value}\nDate : 2026-04-03\nDépartement : Finances",
        "fr_ca_multiline_form",
        "Value in a French Canadian multiline form-style block",
    ),
    (
        "Note à l'auditeur : la valeur sensible {value} figure au rapport du T1, page 14.",
        "fr_ca_audit_note",
        "Value referenced in a French Canadian audit note",
    ),
    (
        "CONFIDENTIEL — Usage interne seulement\n\nNuméro de dossier : {value}\nClassification : PCI",
        "fr_ca_confidential_header",
        "Value under a French Canadian confidential document header",
    ),
    (
        '{"type": "transaction", "ref": "{value}", "montant": 1200, "devise": "CAD"}',
        "fr_ca_json_record",
        "Value inside a French Canadian JSON-like transaction record",
    ),
    (
        "De : facturation@exemple.ca\nÀ : comptes@corp.ca\nObjet : Facture\n\nVoir pièce jointe. Référence : {value}.",
        "fr_ca_email_header_body",
        "Value in a French Canadian email with headers and body",
    ),
    (
        "Renseignements personnels : {value} — données confidentielles protégées par la Loi sur la protection des renseignements personnels.",
        "fr_ca_pii_notice",
        "Value in a French Canadian personal information notice",
    ),
]


@register_generator("context_injection")
class ContextInjectionGenerator(BaseVariantGenerator):
    name = "context_injection"
    # Applies to all payload categories — context embedding is category-agnostic

    def generate(self, value: str) -> Iterator[Variant]:
        for template, technique, desc in TEMPLATES:
            yield self._make_variant(template.replace("{value}", value), technique, desc)
