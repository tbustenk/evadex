"""Document templates for evadex generate — control structure and tone of output.

Each formatter accepts a ``language`` argument (default ``"en"``). Passing
``"fr-CA"`` switches labels, noise copy, and sample business details to
Canadian-French — used for bilingual-scanner evaluation at Canadian banks.
"""
from __future__ import annotations

import datetime
import random
from collections import defaultdict
from typing import Optional

from evadex.core.result import PayloadCategory
from evadex.generate.generator import GeneratedEntry


# Supported display languages. Anything unknown falls through to ``"en"``.
SUPPORTED_LANGUAGES: tuple[str, ...] = ("en", "fr-CA")


def _lang_key(language: Optional[str]) -> str:
    """Normalise the CLI's language flag to a key the L10N tables share."""
    if not language:
        return "en"
    if language in SUPPORTED_LANGUAGES:
        return language
    return "en"


def _t(key: str, language: Optional[str], table: dict[str, dict[str, str]]) -> str:
    """Look up a label from a bilingual dict. Falls back to ``en`` on
    missing locale, then to the raw key itself if the table is missing
    the entry entirely."""
    lang = _lang_key(language)
    entry = table.get(key) or {}
    return entry.get(lang) or entry.get("en") or key


# ── Noise / filler text ──────────────────────────────────────────────────────

_BUSINESS_FILLER = {
    "en": [
        "As per our internal compliance procedures, all data must be handled in accordance with applicable privacy legislation.",
        "The following records have been extracted from the production database for review purposes only.",
        "This report is generated as part of our ongoing data quality assurance initiative.",
        "All information contained herein is subject to our data retention policy (DRP-2024-Rev3).",
        "Access to this document is restricted to authorized personnel with appropriate security clearance.",
        "Please ensure all sensitive data is redacted before distribution to external parties.",
        "The compliance team has reviewed and approved the release of this data for internal testing.",
        "This information is classified as INTERNAL USE ONLY and must not be shared outside the organization.",
        "Records marked with an asterisk (*) require additional verification before processing.",
        "The data controller has been notified of this extraction per PIPEDA requirements.",
        "Quarterly reconciliation is required for all accounts listed in Section B below.",
        "The risk assessment for this data set was completed on {date} with an overall rating of LOW.",
        "Business continuity planning requires maintaining offline copies of critical customer records.",
        "The audit trail for all modifications to these records is maintained in the central logging system.",
        "Retention period for the records in this document: 7 years from date of last transaction.",
    ],
    "fr-CA": [
        "Conformément à nos procédures internes de conformité, toutes les données doivent être traitées selon la législation applicable en matière de protection de la vie privée.",
        "Les dossiers suivants ont été extraits de la base de données de production à des fins d'examen uniquement.",
        "Ce rapport est produit dans le cadre de notre initiative continue d'assurance qualité des données.",
        "Toute information ci-incluse est assujettie à notre politique de conservation des données (PCD-2024-Rév3).",
        "L'accès à ce document est restreint au personnel autorisé détenant une habilitation de sécurité appropriée.",
        "Veuillez vous assurer que toutes les données sensibles sont caviardées avant toute distribution externe.",
        "L'équipe de conformité a examiné et approuvé la divulgation de ces données aux fins d'essais internes.",
        "Cette information est classifiée USAGE INTERNE SEULEMENT et ne doit pas être partagée hors de l'organisation.",
        "Les dossiers marqués d'un astérisque (*) exigent une vérification additionnelle avant traitement.",
        "Le responsable du traitement a été avisé de cette extraction conformément à la Loi 25 et à la LPRPDE.",
        "Un rapprochement trimestriel est requis pour tous les comptes énumérés à la Section B ci-dessous.",
        "L'évaluation des risques pour ce jeu de données a été complétée le {date} avec une cote globale de FAIBLE.",
        "La planification de la continuité des affaires requiert le maintien de copies hors ligne des dossiers critiques.",
        "La piste d'audit de toutes les modifications à ces dossiers est conservée dans le journal central.",
        "Période de conservation : 7 ans à compter de la date de la dernière transaction.",
    ],
}


def _noise_lines(rng: random.Random, noise_level: str, count: int,
                  language: str = "en") -> list[str]:
    """Return filler text lines appropriate for the noise level + locale."""
    today = datetime.date.today().isoformat()
    if noise_level == "low":
        n = max(1, count // 10)
    elif noise_level == "high":
        n = max(3, count // 2)
    else:  # medium
        n = max(2, count // 5)
    pool = _BUSINESS_FILLER.get(_lang_key(language), _BUSINESS_FILLER["en"])
    chosen = rng.choices(pool, k=n)
    return [line.format(date=today) for line in chosen]


# ── Template formatters ──────────────────────────────────────────────────────
# Each returns a list of text lines ready for writing.

def format_generic(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Default mixed prose and table format (existing behaviour)."""
    lines: list[str] = []
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(noise)
        lines.append("")

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        title = cat.value.replace("_", " ").title()
        lines.append(f"=== {title} ===")
        lines.append("")
        for i, e in enumerate(cat_entries, 1):
            lines.append(f"  {i}. {e.embedded_text}")
        lines.append("")
    return lines


def format_invoice(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Accounts-payable invoice with vendor, PO, line items, and payment
    wire details. Sensitive values land naturally as PO numbers,
    invoice references, or wire-payment metadata."""
    lang = _lang_key(language)
    today = datetime.date.today()
    inv_no = f"INV-{rng.randint(100000, 999999)}"
    po_no  = f"PO-{rng.randint(1000, 9999)}-{rng.randint(100, 999)}"

    if lang == "fr-CA":
        hdr = [
            "=" * 70,
            "                    FACTURE / INVOICE",
            "=" * 70,
            f"  No de facture   / Invoice #:   {inv_no}",
            f"  No de BC        / PO #:        {po_no}",
            f"  Date d'émission / Issue date:  {today.isoformat()}",
            f"  Date d'échéance / Due date:    {(today + datetime.timedelta(days=30)).isoformat()}",
            "  Conditions de paiement / Payment terms:  Net 30",
            "",
            "  Fournisseur / Vendor:               Destinataire / Bill To:",
            "  Groupe Transbec inc.                Banque Laurentienne du Canada",
            "  1275 boul. René-Lévesque O.        1360 boul. René-Lévesque O.",
            "  Montréal, QC H3G 2B3                Montréal, QC H3G 0E5",
            "  NEQ: 1166789432                    No fournisseur: V-48291",
            "",
            "  Virement / Wire payment details:",
            "  Bénéficiaire: Groupe Transbec inc.",
            "  IBAN:   CA12 1234 5678 9012 3456 78",
            "  SWIFT:  BNDCCAMMINT",
            "  RAMQ (contact): Q-48291 (aucune pièce de santé associée)",
            "",
        ]
    else:
        hdr = [
            "=" * 70,
            "                         INVOICE / FACTURE",
            "=" * 70,
            f"  Invoice #:           {inv_no}",
            f"  Purchase Order #:    {po_no}",
            f"  Issue Date:          {today.isoformat()}",
            f"  Due Date:            {(today + datetime.timedelta(days=30)).isoformat()}",
            "  Payment Terms:       Net 30",
            "",
            "  Vendor:                                Bill To:",
            "  Transbec Group Inc.                    Laurentian Bank of Canada",
            "  1275 René-Lévesque Blvd W.             1360 René-Lévesque Blvd W.",
            "  Montreal, QC H3G 2B3                   Montreal, QC H3G 0E5",
            "  Business #: 116678943 BC0001           Vendor ID: V-48291",
            "",
            "  Wire payment details:",
            "  Beneficiary:  Transbec Group Inc.",
            "  IBAN:         CA12 1234 5678 9012 3456 78",
            "  SWIFT/BIC:    BNDCCAMMINT",
            "  Remittance email: ap-remit@transbec-grp.ca",
            "",
        ]
    lines = list(hdr)

    for noise in _noise_lines(rng, noise_level, len(entries), language=lang):
        lines.append(f"  {noise}")
    lines.append("")

    # Line-items table
    lines.append("  " + "-" * 66)
    if lang == "fr-CA":
        lines.append(f"  {'#':>4}  {'Description':<30} {'Quantité':>9}  {'Prix':>8}  {'Référence'}")
    else:
        lines.append(f"  {'#':>4}  {'Description':<30} {'Qty':>9}  {'Price':>8}  {'Reference'}")
    lines.append("  " + "-" * 66)

    running_total = 0.0
    for i, e in enumerate(entries, 1):
        qty = rng.randint(1, 20)
        unit = rng.uniform(50, 1500)
        line_total = qty * unit
        running_total += line_total
        # Wording varies by entry category to keep the invoice readable.
        desc = e.embedded_text if len(e.embedded_text) <= 30 else e.embedded_text[:27] + "…"
        ref = e.variant_value if len(e.variant_value) <= 18 else e.variant_value[:18]
        lines.append(f"  {i:>4}  {desc:<30} {qty:>9}  {unit:>8.2f}  {ref}")

    lines.append("  " + "-" * 66)
    tax_rate, tax_label = (0.14975, "TPS+TVQ 14.975%") if lang == "fr-CA" else (0.13, "HST 13%")
    lines.append(f"  {'':>4}  {('Sous-total' if lang == 'fr-CA' else 'SUBTOTAL'):<30} {running_total:>18.2f}")
    lines.append(f"  {'':>4}  {tax_label:<30} {running_total * tax_rate:>18.2f}")
    lines.append(f"  {'':>4}  {('TOTAL DÛ' if lang == 'fr-CA' else 'TOTAL DUE'):<30} {running_total * (1 + tax_rate):>18.2f}")
    lines.append("  " + "-" * 66)
    lines.append("")
    if lang == "fr-CA":
        lines.append("  Modes de paiement: virement bancaire (IBAN/SWIFT ci-dessus), chèque, carte de crédit.")
        lines.append("  Questions: comptes-fournisseurs@transbec-grp.ca · 514-555-0199")
    else:
        lines.append("  Payment methods: wire transfer (IBAN/SWIFT above), cheque, or corporate credit card.")
        lines.append("  Questions: accounts-payable@transbec-grp.ca · 514-555-0199")
    lines.append("")
    return lines


def format_statement(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Canadian bank-statement layout (RBC / TD / BMO / Desjardins-style)
    with account metadata, transit/institution numbers, a transaction
    table with running balance, and realistic fee/deposit copy.
    Sensitive values are embedded as transaction descriptions or
    reference columns so they fall into plausible surrounding context.
    """
    lang = _lang_key(language)
    today = datetime.date.today()
    stmt_start = today.replace(day=1)
    stmt_end = today

    # Bank identity rotates between Canada's big five + Desjardins so
    # the corpus doesn't look templated across runs.
    if lang == "fr-CA":
        bank_choices = [
            ("Mouvement Desjardins",      "Caisse populaire Saint-Laurent",  "815",  "30001"),
            ("Banque Nationale du Canada","Succursale Centre-ville Montréal","12345","00006"),
            ("Banque Royale du Canada",   "Succursale McGill College",        "00003","00346"),
        ]
    else:
        bank_choices = [
            ("Royal Bank of Canada",        "Bay & King Branch",            "00003", "00006"),
            ("TD Canada Trust",             "Union Station Branch",         "19201", "00004"),
            ("Bank of Montreal",            "First Canadian Place Branch",  "00011", "00001"),
            ("Scotiabank",                  "Scotia Plaza Branch",          "02256", "00002"),
            ("Canadian Imperial Bank (CIBC)","Commerce Court Branch",       "00005", "00010"),
        ]
    bank, branch, transit, institution = rng.choice(bank_choices)

    acct_last4 = rng.randint(1000, 9999)
    acct_masked = f"****-****-****-{acct_last4}"
    opening = rng.uniform(1_500, 45_000)
    balance = opening

    if lang == "fr-CA":
        months_fr = ["janvier", "février", "mars", "avril", "mai", "juin",
                     "juillet", "août", "septembre", "octobre", "novembre", "décembre"]
        stmt_label = f"{months_fr[today.month - 1]} {today.year}"
        hdr = [
            "=" * 78,
            f"  {bank}",
            f"  {branch}  ·  Transit {transit}  ·  Institution {institution}",
            "=" * 78,
            "",
            "  RELEVÉ DE COMPTE PERSONNEL",
            f"  Période de relevé:       {stmt_start.isoformat()} au {stmt_end.isoformat()}",
            f"  Compte chèques:          {acct_masked}  (institution-transit-compte)",
            f"  Mois de référence:       {stmt_label}",
            f"  Solde d'ouverture:       {opening:>14,.2f} $ CAD",
            "",
            "  Personne-ressource succursale:",
            "  ↳ Marie-Josée Tremblay, directrice des services personnels",
            "  ↳ Tél. (succursale): 514-555-0142   ·   Télécopieur: 514-555-0143",
            "",
        ]
    else:
        stmt_label = today.strftime('%B %Y')
        hdr = [
            "=" * 78,
            f"  {bank}",
            f"  {branch}  ·  Transit {transit}  ·  Institution {institution}",
            "=" * 78,
            "",
            "  PERSONAL CHEQUING ACCOUNT STATEMENT",
            f"  Statement period:        {stmt_start.isoformat()} through {stmt_end.isoformat()}",
            f"  Chequing account:        {acct_masked}  (institution-transit-account)",
            f"  Reporting month:         {stmt_label}",
            f"  Opening balance:         CAD {opening:>14,.2f}",
            "",
            "  Branch contact:",
            "  ↳ Patricia Li, Senior Personal Banking Advisor",
            "  ↳ Branch phone: 416-555-0142   ·   Fax: 416-555-0143",
            "",
        ]
    lines = list(hdr)

    # Mixed compliance/business copy just below the header.
    for noise in _noise_lines(rng, noise_level, len(entries), language=lang)[:3]:
        lines.append(f"  {noise}")
    lines.append("")

    # Transaction table header.
    if lang == "fr-CA":
        lines.append(f"  {'Date':<12} {'Description':<40} {'Débit':>10} {'Crédit':>10} {'Solde':>12}")
    else:
        lines.append(f"  {'Date':<12} {'Description':<40} {'Debit':>10} {'Credit':>10} {'Balance':>12}")
    lines.append("  " + "-" * 88)

    # Plausible transaction descriptions — English / French variants
    # salted with the entry's embedded sensitive value so it reads like
    # a memo that happens to contain a SIN or credit-card reference.
    if lang == "fr-CA":
        descriptions = [
            "DÉPÔT SALAIRE — paie bi-hebdo — employeur {v}",
            "VIREMENT INTERAC — REF {v}",
            "RETRAIT GAB — succ. {t} — conf. {v}",
            "PAIEMENT HYPOTHÉCAIRE — compte-prêt {v}",
            "FRAIS MENSUELS — forfait Chèques Plus",
            "PAIEMENT DE FACTURE — Hydro-Québec — REF {v}",
            "ACHAT CARTE DÉBIT — IGA Montréal — term. {v}",
            "INTÉRÊT CRÉDITÉ",
            "TRANSFERT AUTOMATIQUE — épargne — {v}",
            "CHÈQUE ENCAISSÉ — no {v}",
            "DÉPÔT MOBILE — chèque image — {v}",
            "PAIEMENT PRÉAUTORISÉ — Bell Canada — {v}",
        ]
    else:
        descriptions = [
            "PAYROLL DEPOSIT — biweekly — employer ref {v}",
            "E-TRANSFER RECEIVED — REF {v}",
            "ATM WITHDRAWAL — branch {t} — confirmation {v}",
            "MORTGAGE PAYMENT — loan account {v}",
            "MONTHLY SERVICE FEE — Premium Chequing",
            "BILL PAYMENT — Enbridge Gas — REF {v}",
            "DEBIT PURCHASE — Loblaws Toronto — terminal {v}",
            "INTEREST PAID",
            "AUTO TRANSFER — to savings — {v}",
            "CHEQUE CLEARED — no. {v}",
            "MOBILE DEPOSIT — cheque image — {v}",
            "PREAUTHORIZED PAYMENT — Bell Canada — {v}",
        ]

    for i, e in enumerate(entries):
        dt = stmt_start + datetime.timedelta(
            days=min((stmt_end - stmt_start).days,
                     int(i * max(1, (stmt_end - stmt_start).days) / max(1, len(entries))))
        )
        is_debit = rng.random() < 0.62
        amount = round(rng.uniform(15, 2_800), 2)
        desc_tpl = rng.choice(descriptions)
        desc = desc_tpl.format(v=e.variant_value[:18], t=transit)
        if len(desc) > 40:
            desc = desc[:37] + "…"
        if is_debit:
            balance -= amount
            lines.append(
                f"  {dt.isoformat():<12} {desc:<40} {amount:>10,.2f} "
                f"{'':>10} {balance:>12,.2f}"
            )
        else:
            balance += amount
            lines.append(
                f"  {dt.isoformat():<12} {desc:<40} {'':>10} "
                f"{amount:>10,.2f} {balance:>12,.2f}"
            )

    lines.append("  " + "-" * 88)
    if lang == "fr-CA":
        lines.append(f"  SOLDE DE CLÔTURE: {balance:>14,.2f} $ CAD")
        lines.append("")
        lines.append("  CONDITIONS DU COMPTE")
        lines.append("  ↳ Les dépôts faits après 18 h peuvent ne pas apparaître sur le prochain relevé.")
        lines.append("  ↳ Les questions doivent être soumises dans les 30 jours (Loi sur les banques, art. 452).")
        lines.append("  ↳ Un avis de cotisation fiscale (feuillet T5) vous sera envoyé au plus tard le 28 février.")
    else:
        lines.append(f"  CLOSING BALANCE: CAD {balance:>14,.2f}")
        lines.append("")
        lines.append("  ACCOUNT TERMS")
        lines.append("  ↳ Deposits made after 6:00 PM may not appear on your next statement.")
        lines.append("  ↳ Queries must be submitted within 30 days (Bank Act s. 452).")
        lines.append("  ↳ A T5 tax slip will be mailed by February 28 for interest earned year-to-date.")
    lines.append("")
    return lines


def format_hr_record(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """HR employee-file layout with full personnel block (SIN, DOB,
    address, emergency contact, compensation, manager) before the
    sensitive-field dump. Mirrors the structure used by Canadian
    bank HRIS exports (Workday / SAP SuccessFactors)."""
    lang = _lang_key(language)
    today = datetime.date.today()

    if lang == "fr-CA":
        first_names = ["Jean-François", "Marie-Ève", "Philippe", "Catherine",
                       "Étienne", "Geneviève", "Maxime", "Valérie", "Luc",
                       "Sophie-Anne", "Yannick", "Marie-Claude"]
        last_names  = ["Tremblay", "Gagnon", "Roy", "Côté", "Bouchard",
                       "Gauthier", "Morin", "Lavoie", "Fortin", "Girard",
                       "Bélanger", "Pelletier"]
        depts = ["Finances", "Conformité", "Ressources humaines",
                 "Technologies de l'information", "Exploitation",
                 "Affaires juridiques", "Gestion des risques", "Trésorerie"]
        managers = ["Isabelle Laporte", "Marc-André Girard", "Sylvie Bergeron",
                    "Jean-Sébastien Parent"]
        status_pool = ["Actif · temps plein", "Actif · temps partiel",
                       "Congé parental", "Actif · télétravail"]
        addresses = [
            "1250 rue University, Montréal, QC  H3B 4W8",
            "2500 boul. Daniel-Johnson, Laval, QC  H7T 2P6",
            "800 rue Saint-Jacques, Montréal, QC  H3C 1E9",
            "1010 rue de la Gauchetière O., Montréal, QC  H3B 2N2",
        ]
    else:
        first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily",
                       "Michael", "Jennifer", "Priya", "Wei", "Amit", "Fatima"]
        last_names  = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown",
                       "Lee", "Taylor", "Patel", "Singh", "Nguyen", "O'Brien"]
        depts = ["Finance", "Compliance", "Human Resources", "Information Technology",
                 "Operations", "Legal", "Risk Management", "Treasury"]
        managers = ["Patricia Lin", "Marcus Webb", "Sandra Kowalski",
                    "David Abramowitz"]
        status_pool = ["Active · Full-time", "Active · Part-time",
                       "Active · Remote", "Parental Leave"]
        addresses = [
            "200 Bay Street, Toronto, ON  M5J 2J2",
            "1 First Canadian Place, Toronto, ON  M5X 1A4",
            "100 King Street West, Toronto, ON  M5X 1E2",
            "66 Wellington Street West, Toronto, ON  M5K 1E7",
        ]

    if lang == "fr-CA":
        lines = [
            "=" * 72,
            "  DOSSIER EMPLOYÉ — FICHE PERSONNELLE",
            "  Système SIRH — Banque Nationale du Canada",
            "=" * 72,
            f"  Extraction générée:   {today.isoformat()}",
            "  Classification:        CONFIDENTIEL — USAGE RH UNIQUEMENT",
            "  Conservation:          7 ans après cessation d'emploi (Loi 25)",
            "",
        ]
    else:
        lines = [
            "=" * 72,
            "  EMPLOYEE PERSONNEL FILE — MASTER RECORD",
            "  HRIS export · Royal Bank of Canada",
            "=" * 72,
            f"  Extract generated:     {today.isoformat()}",
            "  Classification:        CONFIDENTIAL — HR USE ONLY",
            "  Retention:             7 years post-termination (PIPEDA + PCI-DSS 9.4)",
            "",
        ]

    for noise in _noise_lines(rng, noise_level, len(entries), language=lang)[:3]:
        lines.append(f"  {noise}")
    lines.append("")

    emp_counter = rng.randint(10_000, 99_000)

    for i, e in enumerate(entries):
        if i % 5 == 0:
            emp_counter += 1
            first = rng.choice(first_names)
            last = rng.choice(last_names)
            dept = rng.choice(depts)
            manager = rng.choice(managers)
            status = rng.choice(status_pool)
            start_days_ago = rng.randint(180, 4_000)
            start = today - datetime.timedelta(days=start_days_ago)
            dob = today.replace(year=today.year - rng.randint(24, 62))
            salary = rng.choice([65_000, 78_000, 92_500, 110_000,
                                  128_000, 155_000, 182_000, 210_000])

            lines.append("-" * 72)
            if lang == "fr-CA":
                lines.append(f"  Numéro d'employé:         EMP-{emp_counter}")
                lines.append(f"  Nom légal:                 {first} {last}")
                lines.append(f"  Préféré:                  {first}")
                lines.append(f"  Date de naissance:        {dob.isoformat()}")
                lines.append(f"  Sexe (déclaré):            {rng.choice(['F', 'H', 'X', 'non divulgué'])}")
                lines.append(f"  Adresse domicile:          {rng.choice(addresses)}")
                lines.append(f"  Courriel personnel:        {first.lower().replace('-', '').replace(' ', '')}.{last.lower()}@gmail.com")
                lines.append(f"  Téléphone mobile:          514-555-{rng.randint(1000, 9999)}")
                lines.append(f"  Contact d'urgence:         {rng.choice(first_names)} {last} (conjoint·e)")
                lines.append(f"  Tél. urgence:             438-555-{rng.randint(1000, 9999)}")
                lines.append(f"  Département:              {dept}")
                lines.append(f"  Gestionnaire:             {manager}")
                lines.append(f"  Date d'embauche:          {start.isoformat()}  ({start_days_ago // 365} ans, {(start_days_ago % 365) // 30} mois)")
                lines.append(f"  Statut:                   {status}")
                lines.append(f"  Rémunération annuelle:    {salary:,} $ CAD")
                lines.append("  Dépôt direct — banque:    Institution 006 · Transit 12345")
                lines.append(f"  Dépôt direct — compte:    ****{rng.randint(1000, 9999)}")
                lines.append("  Champs sensibles extraits ci-dessous:")
            else:
                lines.append(f"  Employee ID:              EMP-{emp_counter}")
                lines.append(f"  Legal name:               {first} {last}")
                lines.append(f"  Preferred name:           {first}")
                lines.append(f"  Date of birth:            {dob.isoformat()}")
                lines.append(f"  Self-ID gender:           {rng.choice(['F', 'M', 'X', 'not disclosed'])}")
                lines.append(f"  Home address:             {rng.choice(addresses)}")
                lines.append(f"  Personal email:           {first.lower().replace(chr(39), '')}.{last.lower().replace(chr(39), '')}@gmail.com")
                lines.append(f"  Mobile phone:             416-555-{rng.randint(1000, 9999)}")
                lines.append(f"  Emergency contact:        {rng.choice(first_names)} {last} (spouse)")
                lines.append(f"  Emergency phone:          647-555-{rng.randint(1000, 9999)}")
                lines.append(f"  Department:               {dept}")
                lines.append(f"  Reports to (manager):     {manager}")
                lines.append(f"  Hire date:                {start.isoformat()}  ({start_days_ago // 365}y {(start_days_ago % 365) // 30}m tenure)")
                lines.append(f"  Employment status:        {status}")
                lines.append(f"  Base salary:              CAD ${salary:,.2f} / year")
                lines.append("  Direct deposit institution: 003 · Transit: 00006")
                lines.append(f"  Direct deposit account:   ****{rng.randint(1000, 9999)}")
                lines.append("  Sensitive fields extracted below:")

        field = e.category.value.replace("_", " ").title()
        if lang == "fr-CA":
            lines.append(f"    ↳ {field + ':':<24}{e.embedded_text}")
        else:
            lines.append(f"    ↳ {field + ':':<24}{e.embedded_text}")

    lines.append("-" * 72)
    if lang == "fr-CA":
        lines.append("  ** FIN DU DOSSIER **")
    else:
        lines.append("  ** END OF FILE **")
    lines.append("")
    return lines


def format_audit_report(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Internal audit report with findings and recommendations."""
    today = datetime.date.today()
    audit_no = f"AUD-{today.year}-{rng.randint(100, 999)}"
    lines = [
        "=" * 70,
        "            INTERNAL AUDIT REPORT",
        "=" * 70,
        f"  Audit Reference:   {audit_no}",
        f"  Report Date:       {today.isoformat()}",
        "  Auditor:           Compliance & Risk Management Division",
        "  Scope:             PCI-DSS Data Handling Compliance Review",
        "  Classification:    CONFIDENTIAL",
        "",
        "  1. EXECUTIVE SUMMARY",
        "  " + "-" * 50,
        "  This audit examined data handling practices for sensitive",
        "  financial and personal information across production systems.",
        "  The following findings document instances of sensitive data",
        "  discovered during the review period.",
        "",
    ]

    for noise in _noise_lines(rng, noise_level, len(entries)):
        lines.append(f"  {noise}")
    lines.append("")

    lines.append("  2. DETAILED FINDINGS")
    lines.append("  " + "-" * 50)

    severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_weights = [0.1, 0.3, 0.4, 0.2]

    for i, e in enumerate(entries, 1):
        sev = rng.choices(severity, weights=severity_weights, k=1)[0]
        lines.append(f"  Finding {i:>3}: [{sev}]")
        lines.append(f"    Category:    {e.category.value}")
        lines.append(f"    Evidence:    {e.embedded_text}")
        if e.technique:
            lines.append(f"    Evasion:     {e.technique} ({e.generator_name})")
        lines.append(f"    Action:      Remediate within {'24h' if sev == 'CRITICAL' else '72h' if sev == 'HIGH' else '2 weeks'}")
        lines.append("")

    lines.append("  3. RECOMMENDATIONS")
    lines.append("  " + "-" * 50)
    lines.append("  - Implement automated DLP scanning for all outbound channels")
    lines.append("  - Review evasion technique coverage in current scanner configuration")
    lines.append("  - Schedule follow-up audit within 90 days")
    lines.append("")
    return lines


def format_source_code(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Mixed Python+JavaScript config file with realistic surrounding
    code — imports, logger, DB connection, retry decorator — so the
    hardcoded credentials / API keys sit in plausible context. French
    mode swaps comments and variable prose to Canadian-French."""
    lang = _lang_key(language)

    def C(text_en: str, text_fr: str) -> str:
        return text_fr if lang == "fr-CA" else text_en

    lines = [
        "#!/usr/bin/env python3",
        '"""' + C(
            "Application configuration and database setup — DO NOT COMMIT.",
            "Configuration applicative et connexion base de données — NE PAS COMMITTER.",
        ) + '"""',
        "",
        "from __future__ import annotations",
        "",
        "import os",
        "import json",
        "import logging",
        "from functools import wraps",
        "from typing import Any",
        "",
        "import psycopg2",
        "import requests",
        "",
        "logger = logging.getLogger(__name__)",
        "",
        "# " + C(
            "Environment secrets — populated from vault in prod, inline for dev.",
            "Secrets d'environnement — provenant du coffre-fort en prod, intégrés pour le dev.",
        ),
        'DB_HOST = os.environ.get("DB_HOST", "db.prod.bnc-secure.ca")',
        'DB_PORT = int(os.environ.get("DB_PORT", "5432"))',
        'DB_NAME = os.environ.get("DB_NAME", "retail_banking")',
        'DB_USER = os.environ.get("DB_USER", "svc_retail_ro")',
        'DB_PASSWORD = os.environ.get("DB_PASSWORD", "Correct-Horse-Battery-Staple-91!")  '
            + C("# TODO: pull from HashiCorp Vault",
                "# TODO: extraire du coffre HashiCorp Vault"),
        "",
        'AWS_REGION = "ca-central-1"',
        'S3_BUCKET  = "retail-statements-2026-prod"',
        'AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"',
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "",
        'STRIPE_SECRET_KEY = "sk_test_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME"',
        'SENDGRID_API_KEY  = "SG.EVADEX_PLACEHOLDER.replace_with_test_key_at_runtime"',
        "",
        "# " + C(
            "Database connection — all retail-banking reads flow through here.",
            "Connexion à la base de données — toutes les lectures des opérations de détail passent par ici.",
        ),
        "def connect_db() -> psycopg2.extensions.connection:",
        "    return psycopg2.connect(",
        "        host=DB_HOST, port=DB_PORT,",
        "        dbname=DB_NAME, user=DB_USER,",
        "        password=DB_PASSWORD, connect_timeout=5,",
        "    )",
        "",
        "def retry_on_429(fn):",
        "    @wraps(fn)",
        "    def _inner(*a, **kw):",
        "        for attempt in range(3):",
        "            r = fn(*a, **kw)",
        "            if getattr(r, 'status_code', 0) != 429:",
        "                return r",
        "        return r",
        "    return _inner",
        "",
    ]

    if noise_level != "low":
        lines += [
            "# " + C(
                "Feature flags — safe to hardcode, read at startup only.",
                "Indicateurs de fonctionnalités — sûrs à coder en dur, lus au démarrage seulement.",
            ),
            "MAX_RETRIES = 3",
            "TIMEOUT_SECONDS = 30",
            'LOG_LEVEL = "INFO"',
            "ENABLE_TRACE = False",
            "",
        ]

    # Payload section — Python + JS mixed so the scanner sees both syntax shapes.
    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    emit_langs = ["python", "javascript", "generic"]
    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        var_base = cat.value.upper()
        emit_lang = rng.choice(emit_langs)

        lines.append(f"# --- {cat.value.replace('_', ' ').title()} "
                     + C("Data ---", "données ---"))

        if emit_lang == "python":
            for i, e in enumerate(cat_entries):
                var_name = f"{var_base}_{i}" if i > 0 else var_base
                ev = f"  # evasion: {e.technique}" if e.technique else ""
                roll = rng.random()
                if roll < 0.25:
                    lines.append(f'{var_name} = "{e.variant_value}"{ev}  '
                                 + C("# FIXME: hardcoded, rotate quarterly",
                                     "# À CORRIGER: codé en dur, à renouveler trimestriellement"))
                elif roll < 0.55:
                    lines.append(f'os.environ["{var_name}"] = "{e.variant_value}"{ev}')
                else:
                    lines.append(f'{var_name} = "{e.variant_value}"{ev}')
                if noise_level == "high" and rng.random() < 0.35:
                    lines.append(f'logger.debug("loaded %s (len=%d)", "{var_name}", '
                                 f'len({var_name}))')

        elif emit_lang == "javascript":
            lines.append("")
            lines.append("// " + C(
                "Front-end helpers — compiled with webpack",
                "Assistants front-end — compilés avec webpack",
            ))
            for i, e in enumerate(cat_entries):
                var_name = cat.value.lower() + (f"_{i}" if i > 0 else "")
                ev = f"  // evasion: {e.technique}" if e.technique else ""
                roll = rng.random()
                if roll < 0.3:
                    lines.append(f'const {var_name} = "{e.variant_value}";{ev}  '
                                 + C("// FIXME: remove before commit",
                                     "// À CORRIGER: retirer avant commit"))
                elif roll < 0.6:
                    lines.append(f'process.env.{var_name.upper()} = "{e.variant_value}";{ev}')
                else:
                    lines.append(f'let {var_name} = "{e.variant_value}";{ev}')
        else:  # generic
            for i, e in enumerate(cat_entries):
                lines.append(f'# {cat.value}[{i}] = {e.variant_value}')
        lines.append("")

    lines += [
        "# " + C(
            "Example connection strings (kept here for the operations runbook):",
            "Chaînes de connexion d'exemple (conservées pour le guide d'opérations):",
        ),
        'PG_DSN = "postgresql://svc_retail_ro:Correct-Horse-Battery-Staple-91!@'
            'db.prod.bnc-secure.ca:5432/retail_banking?sslmode=require"',
        'MONGO_URI = "mongodb+srv://admin:s3cr3t@cluster0.mongodb.net/?retryWrites=true&w=majority"',
        "",
        "# --- " + C("End of configuration ---", "Fin de la configuration ---"),
        'if __name__ == "__main__":',
        '    print(' + C('"Config loaded successfully"', '"Configuration chargée avec succès"') + ')',
        "",
    ]
    return lines


def format_config_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Realistic ``.env`` / ``application.yaml`` / ``app.ini`` with a
    mix of obvious hardcoded secrets, plausible build/feature flags,
    and evasion-variant values. Chosen format rotates so a corpus
    covers all three syntaxes."""
    lang = _lang_key(language)
    fmt = rng.choice(["env", "ini", "yaml"])
    today = datetime.date.today()

    def C(en: str, fr: str) -> str:
        return fr if lang == "fr-CA" else en

    lines: list[str] = []

    if fmt == "env":
        lines += [
            "# " + C(
                "Application Configuration — CONFIDENTIAL",
                "Configuration applicative — CONFIDENTIEL",
            ),
            "# " + C(f"Generated: {today.isoformat()}",
                    f"Généré le: {today.isoformat()}"),
            "# " + C(
                "Loaded by boot.sh via `set -o allexport && . .env`",
                "Chargée par boot.sh via `set -o allexport && . .env`",
            ),
            "",
            "# " + C("Database", "Base de données"),
            "DB_HOST=db-prod.bnc-secure.ca",
            "DB_PORT=5432",
            "DB_NAME=retail_banking",
            "DB_USER=svc_retail_ro",
            "DB_PASSWORD=Correct-Horse-Battery-Staple-91!",
            "",
            "# " + C(
                "Object storage — customer statements bucket",
                "Stockage objet — seau de relevés clients",
            ),
            "AWS_REGION=ca-central-1",
            "AWS_S3_BUCKET=retail-statements-2026-prod",
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "",
            "# " + C("Third-party APIs", "API tierces"),
            "STRIPE_SECRET_KEY=sk_test_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "SENDGRID_API_KEY=SG.EVADEX_PLACEHOLDER.replace_with_test_key_at_runtime",
            "TWILIO_AUTH_TOKEN=EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "",
            "# " + C("Feature flags", "Indicateurs fonctionnels"),
            "FEATURE_FX_WIRE_V2=true",
            "FEATURE_OPEN_BANKING_BETA=false",
            "MAX_DB_CONNECTIONS=200",
            "",
            "# " + C("Evasion-variant sensitive values (for DLP testing)",
                    "Valeurs sensibles (variantes d'évasion) pour tests DLP"),
        ]
        for e in entries:
            key = e.category.value.upper()
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"{key}={e.variant_value}{comment}")
            if noise_level == "high":
                lines.append("# " + C(
                    f"Last rotated: {today.isoformat()}",
                    f"Dernière rotation: {today.isoformat()}",
                ))

    elif fmt == "ini":
        lines += [
            "; " + C("Application Configuration — CONFIDENTIAL",
                    "Configuration applicative — CONFIDENTIEL"),
            "; " + C(f"Generated: {today.isoformat()}",
                    f"Généré le: {today.isoformat()}"),
            "",
            "[database]",
            "host = db-prod.bnc-secure.ca",
            "port = 5432",
            "name = retail_banking",
            "user = svc_retail_ro",
            "password = Correct-Horse-Battery-Staple-91!",
            "sslmode = require",
            "",
            "[aws]",
            "region = ca-central-1",
            "bucket = retail-statements-2026-prod",
            "access_key_id = AKIAIOSFODNN7EXAMPLE",
            "secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "",
            "[stripe]",
            "secret_key = sk_test_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "webhook_secret = whsec_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "",
            "[credentials]",
        ]
        for e in entries:
            key = e.category.value.lower()
            lines.append(f"{key} = {e.variant_value}")

    else:  # yaml — `application.yaml` style (Spring Boot / Micronaut)
        lines += [
            "# " + C("Application Configuration — CONFIDENTIAL",
                    "Configuration applicative — CONFIDENTIEL"),
            "# " + C(f"Generated: {today.isoformat()}",
                    f"Généré le: {today.isoformat()}"),
            "",
            "spring:",
            "  application:",
            "    name: retail-banking-api",
            "  datasource:",
            "    url: jdbc:postgresql://db-prod.bnc-secure.ca:5432/retail_banking",
            "    username: svc_retail_ro",
            "    password: 'Correct-Horse-Battery-Staple-91!'",
            "    hikari:",
            "      maximum-pool-size: 50",
            "",
            "aws:",
            "  region: ca-central-1",
            "  s3:",
            "    bucket: retail-statements-2026-prod",
            "  credentials:",
            "    access-key: AKIAIOSFODNN7EXAMPLE",
            "    secret-key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "",
            "stripe:",
            "  api-key: sk_test_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "  webhook-secret: whsec_EVADEX_PLACEHOLDER_REPLACE_AT_RUNTIME",
            "",
            "credentials:",
        ]
        for e in entries:
            key = e.category.value.lower()
            lines.append(f"  {key}: \"{e.variant_value}\"")

    lines.append("")
    return lines


def format_chat_log(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Messaging/chat export with sensitive values shared between participants."""
    names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Michael", "Jennifer", "Alex", "Wei"]
    participants = rng.sample(names, min(4, len(names)))

    base_dt = datetime.datetime(2026, 4, 17, 9, 0, 0)

    lines = [
        f"Chat Export — {datetime.date.today().isoformat()}",
        "Channel: #compliance-sensitive-data",
        f"Participants: {', '.join(participants)}",
        "=" * 50,
        "",
    ]

    filler_msgs = [
        "let me check on that",
        "one sec",
        "ok here's what I found",
        "can you verify this?",
        "sending it now",
        "thanks, got it",
        "I'll update the ticket",
        "sure, see below",
        "hold on, pulling it up",
        "confirmed",
    ]

    for i, e in enumerate(entries):
        ts = base_dt + datetime.timedelta(minutes=i * rng.randint(1, 5))
        ts_str = ts.strftime("%H:%M")
        sender = rng.choice(participants)

        # Occasionally add filler messages for noise
        if noise_level != "low" and rng.random() < (0.5 if noise_level == "high" else 0.25):
            filler_ts = ts - datetime.timedelta(seconds=rng.randint(10, 50))
            filler_sender = rng.choice([p for p in participants if p != sender] or participants)
            lines.append(f"[{filler_ts.strftime('%H:%M')}] {filler_sender}: {rng.choice(filler_msgs)}")

        cat_label = e.category.value.replace("_", " ")
        prompts = [
            f"here's the {cat_label}: {e.variant_value}",
            f"the {cat_label} is {e.variant_value}",
            f"{e.embedded_text}",
            f"found it — {e.variant_value}",
            f"can you process this? {e.variant_value}",
        ]
        lines.append(f"[{ts_str}] {sender}: {rng.choice(prompts)}")

    lines.append("")
    lines.append("--- End of chat export ---")
    lines.append("")
    return lines


def format_medical_record(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Clinical referral / discharge-summary layout — patient block,
    history of presenting illness, assessment, medications, plan.
    Health-card numbers, DOB, referring MD and insurance policy IDs
    are all woven into their natural fields."""
    lang = _lang_key(language)
    today = datetime.date.today()

    if lang == "fr-CA":
        first_names = ["Jean", "Marie-Hélène", "Alexandre", "Mélanie",
                       "Pierre-Olivier", "Catherine", "Louis", "Rosalie"]
        last_names  = ["Tremblay", "Gagnon", "Roy", "Côté", "Bouchard",
                       "Gauthier", "Morin", "Lavoie"]
        conditions = [
            "Diabète de type 2 avec neuropathie périphérique",
            "Hypertension essentielle, stade 2",
            "Trouble dépressif majeur, épisode récurrent",
            "Dorso-lombalgie chronique mécanique",
            "Trouble d'anxiété généralisée",
            "Hyperlipidémie mixte",
            "Arthrose bilatérale des genoux",
            "Fibrillation auriculaire paroxystique",
        ]
        medications = [
            "Metformine 500 mg BID", "Lisinopril 10 mg die", "Sertraline 50 mg die",
            "Naproxen 500 mg PRN", "Atorvastatine 20 mg HS", "Métoprolol 25 mg BID",
            "Gabapentine 300 mg TID", "Acétaminophène 500 mg PRN",
        ]
        physicians = [
            "Dre Marie-Josée Tremblay, MD CCFP",
            "Dr Jean-Sébastien Girard, MD FRCPC",
            "Dre Geneviève Bouchard, MD CCMF",
        ]
        facilities = [
            "CIUSSS du Centre-Sud-de-l'Île-de-Montréal — Hôpital Notre-Dame",
            "CHU de Québec — Hôpital Saint-François d'Assise",
            "CISSS de Laval — Hôpital de la Cité-de-la-Santé",
        ]
    else:
        first_names = ["John", "Sarah", "David", "Maria", "Robert", "Emily", "Priya", "Wei"]
        last_names  = ["Smith", "Chen", "Wilson", "Garcia", "Johnson", "Brown",
                       "Patel", "Nguyen"]
        conditions = [
            "Type 2 Diabetes Mellitus with peripheral neuropathy",
            "Essential Hypertension, Stage 2",
            "Major Depressive Disorder, recurrent episode",
            "Chronic mechanical lower back pain",
            "Generalized Anxiety Disorder",
            "Mixed Hyperlipidemia",
            "Osteoarthritis, bilateral knees, moderate",
            "Paroxysmal Atrial Fibrillation",
        ]
        medications = [
            "Metformin 500mg BID", "Lisinopril 10mg daily", "Sertraline 50mg daily",
            "Naproxen 500mg PRN", "Atorvastatin 20mg HS", "Metoprolol 25mg BID",
            "Gabapentin 300mg TID", "Acetaminophen 500mg PRN",
        ]
        physicians = [
            "Dr. Patricia Lin, MD FRCPC — Internal Medicine",
            "Dr. Marcus Webb, MD CCFP — Family Medicine",
            "Dr. Sandra Kowalski, MD — Cardiology",
        ]
        facilities = [
            "University Health Network — Toronto General Hospital",
            "Sunnybrook Health Sciences Centre",
            "St. Michael's Hospital — Unity Health Toronto",
        ]

    facility = rng.choice(facilities)
    attending = rng.choice(physicians)

    if lang == "fr-CA":
        lines = [
            "=" * 74,
            f"  {facility}",
            "  RÉSUMÉ DE CONGÉ / NOTE DE CONSULTATION",
            "=" * 74,
            f"  Date du rapport:      {today.isoformat()}",
            f"  Médecin traitant:     {attending}",
            f"  No de dictée:         D-{today.year}-{rng.randint(100000, 999999)}",
            "  ** RENSEIGNEMENTS PERSONNELS DE SANTÉ — LSSSS · Loi 25 **",
            "",
        ]
    else:
        lines = [
            "=" * 74,
            f"  {facility}",
            "  DISCHARGE SUMMARY / CONSULTATION NOTE",
            "=" * 74,
            f"  Report date:          {today.isoformat()}",
            f"  Attending:            {attending}",
            f"  Dictation #:          D-{today.year}-{rng.randint(100000, 999999)}",
            "  ** PROTECTED HEALTH INFORMATION — PHIPA / PIPEDA **",
            "",
        ]

    for noise in _noise_lines(rng, noise_level, len(entries), language=lang)[:2]:
        lines.append(f"  {noise}")
    lines.append("")

    patient_id = rng.randint(100_000, 999_999)
    for i, e in enumerate(entries):
        if i % 4 == 0:
            patient_id += 1
            first = rng.choice(first_names)
            last = rng.choice(last_names)
            birth_year = rng.randint(1940, 2005)
            dob = f"{birth_year}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
            age = today.year - birth_year
            condition = rng.choice(conditions)
            med = rng.choice(medications)
            admit = today - datetime.timedelta(days=rng.randint(1, 14))

            lines.append("-" * 74)
            if lang == "fr-CA":
                lines.append(f"  Patient·e:           {first} {last}")
                lines.append(f"  Dossier (MRN):       DOSS-{patient_id}")
                lines.append(f"  Date de naissance:   {dob}  (âge {age} ans)")
                lines.append(f"  Sexe:                {rng.choice(['F', 'H', 'X'])}")
                lines.append(f"  Date d'admission:    {admit.isoformat()}")
                lines.append(f"  Durée de séjour:     {(today - admit).days} jours")
                lines.append(f"  Médecin référent:    {rng.choice(physicians)}")
                lines.append("")
                lines.append(f"  Diagnostic principal: {condition}")
                lines.append(f"  Médication au congé:  {med}")
                lines.append("")
                lines.append("  Histoire de la maladie actuelle:")
                lines.append(f"  Le·la patient·e, connu·e pour {condition.lower()}, se présente pour un")
                lines.append("  suivi post-hospitalisation. Les signes vitaux sont stables. Aucune")
                lines.append("  plainte aiguë rapportée lors de l'examen d'aujourd'hui.")
                lines.append("")
                lines.append("  Identifiants administratifs associés au dossier:")
            else:
                lines.append(f"  Patient:             {first} {last}")
                lines.append(f"  MRN:                 MRN-{patient_id}")
                lines.append(f"  DOB:                 {dob}  (age {age})")
                lines.append(f"  Sex:                 {rng.choice(['F', 'M', 'X'])}")
                lines.append(f"  Admission date:      {admit.isoformat()}")
                lines.append(f"  Length of stay:      {(today - admit).days} days")
                lines.append(f"  Referring physician: {rng.choice(physicians)}")
                lines.append("")
                lines.append(f"  Primary Dx:          {condition}")
                lines.append(f"  Discharge meds:      {med}")
                lines.append("")
                lines.append("  History of Present Illness:")
                lines.append(f"  The patient, known for {condition.lower()}, presents for")
                lines.append("  post-hospitalization follow-up. Vital signs are stable. No")
                lines.append("  acute complaints reported on today's examination.")
                lines.append("")
                lines.append("  Administrative identifiers associated with this record:")

        field = e.category.value.replace("_", " ").title()
        lines.append(f"    ↳ {field + ':':<24} {e.embedded_text}")

    lines.append("-" * 74)
    if lang == "fr-CA":
        lines.append("  Signature électronique: [Dictée et vérifiée]")
        lines.append(f"  {attending}")
        lines.append("  ** FIN DU DOSSIER **")
    else:
        lines.append("  Electronically signed: [Dictated & verified]")
        lines.append(f"  {attending}")
        lines.append("  ** END OF RECORD **")
    lines.append("")
    return lines


# ── Public API ───────────────────────────────────────────────────────────────

def format_env_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """``.env``-style file where every entry becomes a KEY=VALUE line.

    Targets Siphon's ``EntropyMode::Assignment`` detection: the assignment
    regex matches ``KEY=`` before each value so every high-entropy payload
    is in assignment context.
    """
    lines = [
        "# Environment configuration for evadex test corpus",
        "# Generated for DLP scanner entropy-mode evaluation",
        "",
        "NODE_ENV=production",
        "LOG_LEVEL=info",
        "PORT=8080",
        "",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        for i, e in enumerate(by_cat[cat]):
            var_name = cat.value.upper() + (f"_{i}" if i > 0 else "")
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"{var_name}={e.variant_value}{comment}")

    if noise_level != "low":
        lines += [
            "",
            "# Feature flags",
            "FEATURE_FLAG_BETA=true",
            "FEATURE_FLAG_CACHING=true",
            "MAX_CONNECTIONS=100",
            "",
        ]

    return lines


def format_secrets_file(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """YAML-style secrets file mixing a keyword header with high-entropy values.

    Targets Siphon's ``EntropyMode::Gated`` mode: every value sits under a
    keyword like ``api_key:`` or ``secret:`` so the 80-char gating window
    catches it.
    """
    keywords = [
        "api_key", "secret_key", "access_token", "private_key",
        "password", "bearer_token", "signing_key", "encryption_key",
    ]

    lines = [
        "# Secrets manifest — for scanner evaluation only",
        "version: 1",
        "secrets:",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        for i, e in enumerate(by_cat[cat]):
            kw = rng.choice(keywords)
            name = f"{cat.value}_{i}" if i > 0 else cat.value
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f"  - name: {name}")
            lines.append(f"    {kw}: {e.variant_value}{comment}")
            lines.append("    environment: production")

    return lines


def format_code_with_secrets(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Source code with high-entropy values hardcoded bare — no keyword, no assignment.

    Values are emitted as positional arguments to function calls so that
    only ``EntropyMode::All`` (flag everything high-entropy) catches them.
    Complements ``source_code`` which puts them in assignment context.
    """
    lines = [
        "#!/usr/bin/env python3",
        '"""Entropy-focused bare-value placement — exercises EntropyMode::All."""',
        "",
        "import hashlib",
        "",
        "def _verify(token, nonce, signature):",
        "    return hashlib.sha256(token.encode()).hexdigest() == signature",
        "",
    ]

    by_cat: dict[PayloadCategory, list[GeneratedEntry]] = defaultdict(list)
    for e in entries:
        by_cat[e.category].append(e)

    for cat in sorted(by_cat.keys(), key=lambda c: c.value):
        cat_entries = by_cat[cat]
        lines.append(f"# {cat.value.replace('_', ' ').title()}")
        for e in cat_entries:
            # Bare value — no assignment, no keyword nearby. Function call
            # hides the value as a positional literal so only EntropyMode::All
            # (or a keyword Siphon happens to treat as context) catches it.
            comment = f"  # evasion: {e.technique}" if e.technique else ""
            lines.append(f'_verify("{e.variant_value}", "nonce_abc", "sig_xyz"){comment}')
        lines.append("")

    return lines


def format_lsh_variants(
    entries: list[GeneratedEntry],
    rng: random.Random,
    noise_level: str = "medium",
    density: str = "medium",
) -> list[str]:
    """Render a document containing N near-duplicate sections of a base
    text — one section per entry. Each section restates the same base
    paragraph with a different distortion rate, reporting the empirical
    Jaccard similarity to the base in the section header.

    Use this template to produce fixtures for testing a DLP scanner's
    LSH document-similarity engine. The single output file contains
    multiple variants stitched together; split on the
    ``--- VARIANT N ---`` separator to get individual documents to
    feed into ``siphon lsh query``.
    """
    from evadex.lsh import BASE_DOCUMENTS, distorted_variant, jaccard_similarity

    base_id = "loan_decision"
    base = BASE_DOCUMENTS[base_id]

    n = max(1, len(entries))
    if n == 1:
        rates = [0.0]
    else:
        # Smoothly span from no distortion to heavy distortion.
        rates = [round(i / (n - 1) * 0.5, 4) for i in range(n)]

    lines: list[str] = [
        "=" * 70,
        f"  LSH NEAR-DUPLICATE VARIANTS — base document: {base_id}",
        f"  {n} variants spanning distortion rates 0%–{int(rates[-1] * 100)}%",
        "=" * 70,
        "",
    ]

    for idx, (rate, entry) in enumerate(zip(rates, entries)):
        variant = distorted_variant(base, rate, rng) if rate > 0 else base
        # Splice the entry's sensitive value into the variant so each
        # near-duplicate carries a distinct PII payload — exactly the
        # property an LSH scan should preserve across variants.
        variant = f"{variant} Reference identifier: {entry.variant_value}."
        empirical = jaccard_similarity(base, variant)
        lines.append(f"--- VARIANT {idx} ---")
        lines.append(f"Distortion rate: {rate:.0%}  "
                     f"Empirical Jaccard vs base: {empirical:.0%}  "
                     f"Embedded category: {entry.category.value}")
        lines.append("")
        lines.append(variant)
        lines.append("")

    return lines


_FORMATTERS = {
    "generic": format_generic,
    "invoice": format_invoice,
    "statement": format_statement,
    # Alias — matches the name used by the siphon-c2 UI and the CLI
    # docs. Points at the same formatter as ``statement`` so the two
    # stay in sync.
    "banking-statement": format_statement,
    "banking_statement": format_statement,
    "hr_record": format_hr_record,
    "audit_report": format_audit_report,
    "source_code": format_source_code,
    "config_file": format_config_file,
    "chat_log": format_chat_log,
    "medical_record": format_medical_record,
    "env_file": format_env_file,
    "secrets_file": format_secrets_file,
    "code_with_secrets": format_code_with_secrets,
    "lsh_variants": format_lsh_variants,
    # ``lsh_corpus`` is the multi-document variant; generator.py
    # treats it specially because it writes N files instead of one.
    # The formatter here is a no-op placeholder so unknown-template
    # fallbacks never route back to generic for lsh_corpus.
    "lsh_corpus": format_lsh_variants,
}


def apply_template(
    template: str,
    entries: list[GeneratedEntry],
    seed: Optional[int] = None,
    noise_level: str = "medium",
    density: str = "medium",
    language: str = "en",
) -> list[str]:
    """Apply a named template to entries, returning formatted text lines.

    ``language`` is an ISO tag — currently ``"en"`` (default) or
    ``"fr-CA"``. Formatters that know about locales will switch labels,
    noise copy, and sample business details; older formatters still
    accepting the ``(entries, rng, noise_level, density)`` signature
    are called without the kw and fall back to English implicitly.
    """
    formatter = _FORMATTERS.get(template, format_generic)
    rng = random.Random(seed)
    try:
        return formatter(
            entries, rng,
            noise_level=noise_level, density=density, language=language,
        )
    except TypeError:
        # Formatter predates the language kwarg — call without it.
        return formatter(entries, rng, noise_level=noise_level, density=density)
