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
        "Virtual card {v} issued to employee for travel expenses.",
        "Statement line: MERCHANT-XYZ, card ending {v}, USD 42.50.",
        "Card limit increase approved for cardholder with card number {v}.",
        "Cross-border transaction flagged: card {v} used in 3 countries in 24 hours.",
        "Visa card no {v} authorised for primary account holder.",
        "PAN {v} mapped to primary account number in tokenisation vault.",
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
        "Loan application submitted: applicant SSN {v}, credit score 742.",
        "Account ownership verified: SSN {v} matches KYC documentation.",
        "Mortgage underwriting file: borrower SSN {v}, DTI 36%.",
        "Social security no {v} — applicant verification pending.",
    ],
    PayloadCategory.SIN: [
        "Canadian employee SIN on record: {v}.",
        "T4 slip issued for SIN {v}, tax year 2023.",
        "CRA file reference: SIN {v}, balance owing $1,234.00.",
        "Benefits claim filed under SIN {v} — EI application #88921.",
        "ROE issued for SIN {v}: insurable hours 1,820.",
        "RRSP contribution reported under SIN {v}: $14,500.",
        "Social insurance number {v} verified against CRA database.",
        "Social insurance no {v} — employee payroll enrolment.",
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
        "Payee details updated: account IBAN {v}, reference PAYROLL-2024-04.",
        "IBAN validation passed: {v} — account open and eligible for credit.",
        "Settlement account: {v} — net EUR 145,000.00 due end of day.",
        "International bank account number {v} on file for the compte bancaire.",
    ],
    PayloadCategory.SWIFT_BIC: [
        "SWIFT code for beneficiary bank: {v}.",
        "Correspondent bank BIC: {v} — route through Frankfurt.",
        "International wire instruction: BIC {v}, ref TXN-884421.",
        "SWIFT gpi tracker: payment via {v} cleared in 4 hours.",
        "Nostro account held at {v}, balance USD 2.1M.",
        "Bank identifier code {v} verified for correspondent routing.",
    ],
    PayloadCategory.ABA_ROUTING: [
        "ACH routing number: {v}.",
        "Direct deposit configured with routing number {v}.",
        "Bank routing {v}, account 000123456789 — payroll ACH.",
        "ACH return filed: routing {v}, reason code R02.",
        "Wire routing: ABA {v} — Wells Fargo San Francisco.",
        "ABA routing {v} — transit routing for domestic wire.",
        "Routing no {v} confirmed for numéro de transit bancaire.",
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
        "Passport number {v} — no de passeport filed with CBSA.",
    ],
    PayloadCategory.AU_TFN: [
        "Australian Tax File Number: {v}.",
        "TFN {v} registered with the Australian Taxation Office.",
        "PAYG withholding report: TFN {v}, gross $82,000.",
        "Superannuation rollover: TFN {v}, fund USI 12345678.",
        "ATO tax file number {v} — lodged for assessment.",
    ],
    PayloadCategory.DE_TAX_ID: [
        "German Steuer-Identifikationsnummer: {v}.",
        "Tax identification number {v} — Finanzamt Berlin-Mitte.",
        "Einkommensteuererklärung 2023: IdNr {v}.",
        "ELSTER submission: Steuernummer {v}, VZ 2023.",
        "Steueridentifikationsnummer {v} — Steuer-ID filed with Finanzamt.",
    ],
    PayloadCategory.FR_INSEE: [
        "Numéro de sécurité sociale (NIR): {v}.",
        "INSEE {v} enregistré à la CPAM de Paris.",
        "Formulaire CERFA: NIR assuré {v}.",
        "Déclaration DADS-U: NIR salarié {v}.",
        "Numéro de sécurité sociale {v} — securite sociale file.",
    ],
    PayloadCategory.AWS_KEY: [
        "AWS_ACCESS_KEY_ID={v}",
        "IAM access key {v} used for S3 PutObject operation.",
        "Key {v} provisioned for CI/CD pipeline — rotate every 90 days.",
        "CloudTrail event: key {v} called sts:AssumeRole.",
        "AWS key {v} — access key rotated per security policy.",
    ],
    PayloadCategory.GITHUB_TOKEN: [
        "GITHUB_TOKEN={v}",
        "GitHub Actions secret: PAT {v} scoped to repo read.",
        "CI pipeline authenticated with token {v}.",
        "Token {v} used for GitHub Packages publish.",
        "GitHub personal access token {v} — fine-grained, expires 2025-12-31.",
    ],
    PayloadCategory.STRIPE_KEY: [
        "STRIPE_SECRET_KEY={v}",
        "Stripe API key configured: {v}.",
        "Payment gateway initialised with key {v} — test mode.",
        "Webhook signature validated using key {v}.",
        "Stripe secret key {v} — Stripe key for payment processing.",
    ],
    PayloadCategory.SLACK_TOKEN: [
        "SLACK_BOT_TOKEN={v}",
        "Slack bot token {v} authenticated successfully.",
        "Incoming webhook token: {v}.",
        "Slack app token {v} scoped to channels:read.",
    ],
    PayloadCategory.JWT: [
        "Authorization: Bearer {v}",
        "Session token issued: {v}",
        "API gateway forwarded JWT: {v}",
        "Refresh token exchanged for auth token: {v}",
        "JSON Web Token {v} — signed with RS256.",
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
        "Online banking login: username {v}, last login 2024-03-14 09:22 UTC.",
        "Wire transfer confirmation emailed to {v} — amount CAD 15,000.00.",
        "AML alert sent to compliance officer at {v}.",
        "E-mail address {v} registered as primary email address for account.",
    ],
    PayloadCategory.PHONE: [
        "Customer contact number: {v}.",
        "Two-factor auth SMS dispatched to {v}.",
        "Call {v} to verify account ownership.",
        "Outbound marketing call placed to {v} — DNC checked.",
        "Emergency contact on record: {v}.",
        "Telephone banking PIN reset confirmed: customer reached at {v}.",
        "Fraud callback initiated: outbound call to {v} at 14:32 EST.",
        "Mobile phone {v} registered for two-factor authentication.",
    ],
    # Canadian regional IDs
    PayloadCategory.CA_RAMQ: [
        "Numéro de carte d'assurance maladie du Québec (RAMQ): {v}.",
        "RAMQ health card on file: {v} — Quebec provincial coverage.",
        "Patient record: RAMQ {v}, registered with Régie de l'assurance maladie.",
        "Carte Soleil number {v} verified for provincial healthcare coverage.",
        "Quebec health card {v} — regie assurance maladie du Québec.",
    ],
    PayloadCategory.CA_ONTARIO_HEALTH: [
        "Ontario health card number: {v}.",
        "OHIP card on file: {v} — Ontario health insurance plan.",
        "Patient registration: Ontario health card {v}, version code on file.",
        "Health card {v} verified against OHIP registry.",
    ],
    PayloadCategory.CA_BC_CARECARD: [
        "BC CareCard number: {v}.",
        "British Columbia personal health number: {v}.",
        "BC Services Card PHN {v} registered with MSP.",
        "Patient record: BC CareCard {v}, active coverage confirmed.",
        "BC health card {v} — BC PHN enrolled in medical services plan (BC MSP).",
    ],
    PayloadCategory.CA_AB_HEALTH: [
        "Alberta health card number: {v}.",
        "AHCIP personal health number: {v}.",
        "Alberta personal health number {v} verified with Alberta Health.",
        "Patient record: Alberta PHN {v}, active provincial coverage.",
    ],
    PayloadCategory.CA_QC_DRIVERS: [
        "Quebec driver's licence number: {v}.",
        "Permis de conduire du Québec : {v}.",
        "Quebec SAAQ driver's licence {v} verified for identity check.",
        "Driver ID: Quebec licence {v}, class 5, expires 2027.",
    ],
    PayloadCategory.CA_ON_DRIVERS: [
        "Ontario driver's licence number: {v}.",
        "MTO driver's licence: {v} — Ontario resident.",
        "Ontario driver's licence {v} verified at border crossing.",
        "Driver ID: Ontario licence {v}, class G, expires 2028.",
    ],
    PayloadCategory.CA_BC_DRIVERS: [
        "British Columbia driver's licence number: {v}.",
        "BC ICBC driver's licence: {v}.",
        "BC driver's licence {v} verified for identity purposes.",
        "Driver ID: BC licence {v}, class 5, expires 2026.",
    ],
    PayloadCategory.CA_PASSPORT: [
        "Canadian passport number: {v}.",
        "Numéro de passeport canadien : {v}.",
        "Travel document: Canadian passport {v}, expires 2029.",
        "KYC verification: Canadian passport {v}, issued by IRCC.",
        "Border crossing record: Canada passport {v} scanned at CBSA.",
    ],
}

_TEMPLATES_FR_CA: dict[PayloadCategory, list[str]] = {
    PayloadCategory.CREDIT_CARD: [
        "Veuillez débiter la carte {v} pour le renouvellement de l'abonnement annuel.",
        "Carte bancaire en dossier : {v} — autorisée pour la facturation mensuelle récurrente.",
        "Paiement par carte traité avec succès, numéro de carte {v}.",
        "Référence de facturation : carte {v} débitée de 249,99 $ le 2024-03-14.",
        "Mon numéro de carte est le {v}, veuillez procéder au paiement.",
        "Numéro de carte bancaire : {v} — coordonnées de paiement confidentielles.",
        "Carte virtuelle {v} émise pour les frais de déplacement de l'employé.",
        "Relevé bancaire : transaction carte {v}, 42,50 $ USD.",
        "Contestation de transaction : carte {v}, litige soumis au département fraude.",
        "Carte de crédit {v} — no de carte associé au compte principal.",
        "Carte de credit {v} — paiement autorisé.",
    ],
    PayloadCategory.SSN: [
        "Numéro de sécurité sociale de l'employé : {v}.",
        "Déclaration fiscale pour le NAS {v} soumise électroniquement.",
        "Vérification d'identité réussie : numéro {v} confirmé.",
        "Dossier de paie — numéro {v} : brut 5 200 $, net 3 890 $.",
        "Demande de prêt : numéro d'assurance sociale du demandeur {v}.",
        "Vérification KYC : numéro {v} correspond aux documents d'identité.",
    ],
    PayloadCategory.SIN: [
        "Numéro d'assurance sociale de l'employé canadien : {v}.",
        "Feuillet T4 émis pour le NAS {v}, année d'imposition 2023.",
        "Référence ARC : NAS {v}, solde dû 1 234,00 $.",
        "Demande de prestations déposée sous le NAS {v} — dossier AE #88921.",
        "Mon NAS est le {v} — veuillez traiter ce formulaire.",
        "No d'assurance sociale {v} — registre de l'employeur.",
    ],
    PayloadCategory.IBAN: [
        "Numéro de compte bénéficiaire (IBAN) : {v}.",
        "Virement bancaire vers le compte {v}, montant 12 500,00 EUR.",
        "Coordonnées bancaires — IBAN {v}, BIC : DEUTDEDB.",
        "Relevé bancaire : virement entrant de {v}, 3 200,00 EUR.",
        "Numéro de compte pour le virement SEPA : {v}.",
        "Numéro de compte bancaire international {v} — IBAN vérifié.",
    ],
    PayloadCategory.SWIFT_BIC: [
        "Code SWIFT de la banque bénéficiaire : {v}.",
        "Instruction de virement international : BIC {v}, réf TXN-884421.",
        "Virement via correspondant bancaire {v}.",
        "Code d'identification bancaire {v} — correspondant vérifié.",
    ],
    PayloadCategory.ABA_ROUTING: [
        "Numéro de routage ACH : {v}.",
        "Dépôt direct configuré avec le numéro de routage {v}.",
        "Routage bancaire {v}, compte 000123456789 — paie ACH.",
        "Numero de transit {v} — routage configuré.",
    ],
    PayloadCategory.BITCOIN: [
        "Adresse de paiement Bitcoin : {v}.",
        "Envoyer 0,05 BTC à l'adresse {v} — facture #BTC-0042.",
        "Transaction confirmée en chaîne : destinataire {v}.",
    ],
    PayloadCategory.ETHEREUM: [
        "Contrat Ethereum déployé à : {v}.",
        "Transfert ETH vers {v} — montant 0,25 ETH, gaz 21000.",
        "Interaction avec le protocole DeFi : contrat {v}.",
    ],
    PayloadCategory.US_PASSPORT: [
        "Numéro de passeport américain : {v} — expire le 2029-08-14.",
        "Document de voyage scanné à la frontière : passeport américain {v}.",
    ],
    PayloadCategory.AU_TFN: [
        "Numéro de dossier fiscal australien (TFN) : {v}.",
        "TFN {v} enregistré auprès de l'Administration fiscale australienne.",
    ],
    PayloadCategory.DE_TAX_ID: [
        "Numéro d'identification fiscale allemand (IdNr) : {v}.",
        "Déclaration de revenus 2023 : IdNr {v}.",
    ],
    PayloadCategory.FR_INSEE: [
        "Numéro de sécurité sociale (NIR) : {v}.",
        "INSEE {v} enregistré à la CPAM de Paris.",
        "Formulaire CERFA : NIR assuré {v}.",
        "Numero de securite sociale {v} — dossier CPAM.",
    ],
    PayloadCategory.AWS_KEY: [
        "Clé d'accès AWS : {v}.",
        "AWS_ACCESS_KEY_ID={v}",
    ],
    PayloadCategory.GITHUB_TOKEN: [
        "Jeton GitHub Actions : {v}.",
        "GITHUB_TOKEN={v}",
    ],
    PayloadCategory.STRIPE_KEY: [
        "Clé secrète Stripe : {v}.",
        "STRIPE_SECRET_KEY={v}",
    ],
    PayloadCategory.SLACK_TOKEN: [
        "Jeton du bot Slack : {v}.",
        "SLACK_BOT_TOKEN={v}",
    ],
    PayloadCategory.JWT: [
        "Autorisation : Bearer {v}",
        "Jeton de session émis : {v}",
    ],
    PayloadCategory.CLASSIFICATION: [
        "Classification du document : {v}.",
        "Ce document est classifié {v} et ne doit pas être distribué à l'externe.",
        "Politique de protection des données : contenu étiqueté {v} détecté.",
    ],
    PayloadCategory.EMAIL: [
        "Courriel de contact : {v}.",
        "Réinitialisation du mot de passe envoyée à l'adresse courriel {v}.",
        "Mon courriel est {v} — veuillez me contacter.",
        "Adresse courriel enregistrée : {v}.",
        "Demande de droits LPRPDE reçue de {v}.",
    ],
    PayloadCategory.PHONE: [
        "Numéro de téléphone du client : {v}.",
        "Code d'authentification à deux facteurs envoyé par SMS au {v}.",
        "Composez le {v} pour vérifier la propriété du compte.",
        "Cellulaire enregistré : {v}.",
        "Téléphone de contact : {v}.",
    ],
    PayloadCategory.CA_RAMQ: [
        "Numéro de carte d'assurance maladie (RAMQ) : {v}.",
        "Carte Soleil numéro {v} vérifiée pour la couverture provinciale.",
        "Dossier patient : RAMQ {v}, inscrit à la Régie de l'assurance maladie du Québec.",
        "Renseignements personnels — numéro RAMQ : {v}.",
    ],
    PayloadCategory.CA_ONTARIO_HEALTH: [
        "Numéro de carte Santé de l'Ontario : {v}.",
        "Carte OHIP en dossier : {v} — assurance maladie de l'Ontario.",
        "Vérification de la carte santé {v} auprès du registre OHIP.",
    ],
    PayloadCategory.CA_BC_CARECARD: [
        "Numéro de CareCard de la Colombie-Britannique : {v}.",
        "Numéro de santé personnel de la C.-B. : {v}.",
        "Dossier patient : CareCard C.-B. {v}, couverture MSP confirmée.",
    ],
    PayloadCategory.CA_AB_HEALTH: [
        "Numéro de carte santé de l'Alberta : {v}.",
        "Numéro de santé personnel AHCIP : {v}.",
        "Dossier patient : PHN Alberta {v}, couverture provinciale active.",
    ],
    PayloadCategory.CA_QC_DRIVERS: [
        "Numéro de permis de conduire du Québec : {v}.",
        "Permis de conduire délivré par la SAAQ : {v}.",
        "Vérification d'identité — permis québécois {v}, classe 5.",
        "Informations personnelles : permis de conduire Québec {v}.",
    ],
    PayloadCategory.CA_ON_DRIVERS: [
        "Numéro de permis de conduire de l'Ontario : {v}.",
        "Permis MTO de l'Ontario : {v} — résident ontarien.",
        "Vérification du permis de conduire {v} à la frontière.",
    ],
    PayloadCategory.CA_BC_DRIVERS: [
        "Numéro de permis de conduire de la Colombie-Britannique : {v}.",
        "Permis ICBC de la C.-B. : {v}.",
        "Vérification d'identité — permis C.-B. {v}, classe 5.",
    ],
    PayloadCategory.CA_PASSPORT: [
        "Numéro de passeport canadien : {v}.",
        "Document de voyage : passeport canadien {v}, expire en 2029.",
        "Vérification KYC : passeport canadien {v}, émis par IRCC.",
        "Vie privée — renseignements personnels : passeport {v}.",
    ],
}

_FALLBACK_TEMPLATES = [
    "Reference value: {v}.",
    "Data field: {v}.",
    "Record: {v}.",
]

_FALLBACK_TEMPLATES_FR_CA = [
    "Valeur de référence : {v}.",
    "Données confidentielles : {v}.",
    "Renseignements personnels : {v}.",
]


def get_keyword_sentence(
    rng: random.Random,
    cat: PayloadCategory,
    value: str,
    language: str = "en",
) -> str:
    """Return a realistic business sentence with value embedded.

    Args:
        rng:      Random number generator for template selection.
        cat:      Payload category to select appropriate templates.
        value:    Sensitive value to embed in the sentence.
        language: Language code — ``"en"`` (default) or ``"fr-CA"`` for
                  Canadian French templates.
    """
    if language == "fr-CA":
        templates = _TEMPLATES_FR_CA.get(cat, _FALLBACK_TEMPLATES_FR_CA)
    else:
        templates = _TEMPLATES.get(cat, _FALLBACK_TEMPLATES)
    return rng.choice(templates).format(v=value)
