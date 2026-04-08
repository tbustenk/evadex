"""Realistic business filler text for embedding sensitive values in test documents."""
from __future__ import annotations

import random
from evadex.core.result import PayloadCategory


_TEMPLATES: dict[PayloadCategory, list[str]] = {
    PayloadCategory.CREDIT_CARD: [
        "Please charge {v} for the annual subscription renewal.",
        "Card on file: {v} — authorised for recurring monthly billing.",
        "Payment processed successfully using card number {v}.",
        "Billing reference: card {v} charged $249.99 on 2024-03-14.",
        "Customer account updated with new credit card {v}.",
        "Recurring payment scheduled for card {v} on the 1st of each month.",
        "Fraud alert triggered: unusual activity detected on card {v}.",
        "Card {v} approved at POS terminal ID 7734 for $89.00.",
        "Refund of $150.00 issued to original payment method: {v}.",
        "Chargeback dispute filed for transaction on card {v}.",
        "PCI audit log entry: card {v} tokenised to ref TK-882910.",
        "3DS authentication completed for card {v}, txn ref 4421-B.",
    ],
    PayloadCategory.SSN: [
        "Employee SSN on file: {v}.",
        "Tax filing for SSN {v} submitted to IRS electronically.",
        "Background check completed for applicant with SSN {v}.",
        "Social security number {v} verified against USCIS records.",
        "W-2 form issued to taxpayer SSN {v} for tax year 2023.",
        "Benefits enrolment: SSN {v} added to health plan B.",
        "Identity verification passed: SSN {v} matched applicant record.",
        "Payroll record — SSN {v}: gross $5,200.00, net $3,890.00.",
        "Form 1099-NEC issued to contractor SSN {v}.",
        "FATCA filing: US person SSN {v} reported to IRS.",
    ],
    PayloadCategory.SIN: [
        "Canadian employee SIN on record: {v}.",
        "T4 slip issued for SIN {v}, tax year 2023.",
        "CRA file reference: SIN {v}, balance owing $1,234.00.",
        "Benefits claim filed under SIN {v} — EI application #88921.",
        "ROE issued for SIN {v}: insurable hours 1,820.",
        "RRSP contribution reported under SIN {v}: $14,500.",
    ],
    PayloadCategory.IBAN: [
        "Wire transfer destination: IBAN {v}.",
        "SEPA credit transfer: beneficiary IBAN {v}, amount EUR 12,500.00.",
        "Bank account details — IBAN {v}, BIC: DEUTDEDB.",
        "Transfer of EUR 8,750.00 to IBAN {v} completed — ref TXN-20240315.",
        "Invoice payment to IBAN {v}, invoice reference INV-20240312.",
        "Direct debit mandate: IBAN {v} authorised for standing order GBP 450/month.",
        "SWIFT MT103 message: beneficiary account {v}.",
        "Reconciliation: incoming SEPA from IBAN {v}, EUR 3,200.00.",
    ],
    PayloadCategory.SWIFT_BIC: [
        "SWIFT code for beneficiary bank: {v}.",
        "Correspondent bank BIC: {v} — route through Frankfurt.",
        "International wire instruction: BIC {v}, ref TXN-884421.",
        "SWIFT gpi tracker: payment via {v} cleared in 4 hours.",
        "Nostro account held at {v}, balance USD 2.1M.",
    ],
    PayloadCategory.ABA_ROUTING: [
        "ACH routing number: {v}.",
        "Direct deposit configured with routing number {v}.",
        "Bank routing {v}, account 000123456789 — payroll ACH.",
        "ACH return filed: routing {v}, reason code R02.",
        "Wire routing: ABA {v} — Wells Fargo San Francisco.",
    ],
    PayloadCategory.BITCOIN: [
        "Bitcoin payment address: {v}.",
        "Send 0.05 BTC to wallet address {v} — invoice #BTC-0042.",
        "On-chain transaction confirmed: recipient {v}.",
        "Cold storage address: {v} — 2-of-3 multisig vault.",
        "Crypto withdrawal to address {v} approved by compliance.",
    ],
    PayloadCategory.ETHEREUM: [
        "Ethereum contract deployed at: {v}.",
        "ETH transfer to {v} — amount 0.25 ETH, gas 21000.",
        "DeFi protocol interaction: contract {v}.",
        "Gas fee paid for transaction to {v}: 0.003 ETH.",
        "Gnosis Safe owner: {v}.",
    ],
    PayloadCategory.US_PASSPORT: [
        "US Passport number: {v} — expires 2029-08-14.",
        "Travel document scanned at border control: US Passport {v}.",
        "Visa application attached to passport {v}.",
        "KYC verification: US Passport {v}, issued 2019-08-14.",
    ],
    PayloadCategory.AU_TFN: [
        "Australian Tax File Number: {v}.",
        "TFN {v} registered with the Australian Taxation Office.",
        "PAYG withholding report: TFN {v}, gross $82,000.",
        "Superannuation rollover: TFN {v}, fund USI 12345678.",
    ],
    PayloadCategory.DE_TAX_ID: [
        "German Steuer-Identifikationsnummer: {v}.",
        "Tax identification number {v} — Finanzamt Berlin-Mitte.",
        "Einkommensteuererklärung 2023: IdNr {v}.",
        "ELSTER submission: Steuernummer {v}, VZ 2023.",
    ],
    PayloadCategory.FR_INSEE: [
        "Numéro de sécurité sociale (NIR): {v}.",
        "INSEE {v} enregistré à la CPAM de Paris.",
        "Formulaire CERFA: NIR assuré {v}.",
        "Déclaration DADS-U: NIR salarié {v}.",
    ],
    PayloadCategory.AWS_KEY: [
        "AWS_ACCESS_KEY_ID={v}",
        "IAM access key {v} used for S3 PutObject operation.",
        "Key {v} provisioned for CI/CD pipeline — rotate every 90 days.",
        "CloudTrail event: key {v} called sts:AssumeRole.",
    ],
    PayloadCategory.GITHUB_TOKEN: [
        "GITHUB_TOKEN={v}",
        "GitHub Actions secret: PAT {v} scoped to repo read.",
        "CI pipeline authenticated with token {v}.",
        "Token {v} used for GitHub Packages publish.",
    ],
    PayloadCategory.STRIPE_KEY: [
        "STRIPE_SECRET_KEY={v}",
        "Stripe API key configured: {v}.",
        "Payment gateway initialised with key {v} — test mode.",
        "Webhook signature validated using key {v}.",
    ],
    PayloadCategory.SLACK_TOKEN: [
        "SLACK_BOT_TOKEN={v}",
        "Slack bot authenticated with token {v}.",
        "Incoming webhook token: {v}.",
        "Slack app token {v} scoped to channels:read.",
    ],
    PayloadCategory.JWT: [
        "Authorization: Bearer {v}",
        "Session token issued: {v}",
        "API gateway forwarded JWT: {v}",
        "Refresh token exchanged for access token: {v}",
    ],
    PayloadCategory.CLASSIFICATION: [
        "Document classification: {v}.",
        "Security label: {v} — handle per information security policy.",
        "This document is marked {v} and must not be distributed externally.",
        "DLP policy triggered: content labelled {v} detected in outbound email.",
    ],
    PayloadCategory.EMAIL: [
        "Contact email: {v}.",
        "Password reset notification sent to {v}.",
        "User account registered with email {v}.",
        "Reply-To: {v}",
        "GDPR data subject request received from {v}.",
        "Two-factor authentication code emailed to {v}.",
    ],
    PayloadCategory.PHONE: [
        "Customer contact number: {v}.",
        "Two-factor auth SMS dispatched to {v}.",
        "Call {v} to verify account ownership.",
        "Outbound marketing call placed to {v} — DNC checked.",
        "Emergency contact on record: {v}.",
    ],
}

_FALLBACK_TEMPLATES = [
    "Reference value: {v}.",
    "Data field: {v}.",
    "Record: {v}.",
]


def get_keyword_sentence(rng: random.Random, cat: PayloadCategory, value: str) -> str:
    """Return a realistic business sentence with value embedded."""
    templates = _TEMPLATES.get(cat, _FALLBACK_TEMPLATES)
    return rng.choice(templates).format(v=value)
