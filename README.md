# evadex

A scanner-agnostic DLP evasion test suite. evadex generates hundreds of obfuscated variants of known-sensitive values and submits them to your DLP scanner to find what slips through — including through file extraction pipelines (DOCX, PDF, XLSX), not just plain-text API calls.

Built and tested with [dlpscan](https://github.com/oxide11/dlpscan); works with any scanner via its adapter interface. Detection rates vary by scanner, configuration, and ruleset — run evadex against your own deployment to see your results.

---

## What it does

evadex takes a sensitive value (a credit card number, SSN, AWS key, etc.), runs it through every evasion technique it knows — unicode tricks, delimiter manipulation, encoding variants, regional digit scripts, homoglyphs, and more — and records which variants your scanner catches and which it misses.

**Evasion categories:**

| Generator | Techniques |
|---|---|
| `unicode_encoding` | Zero-width chars, fullwidth digits, homoglyphs, NFD/NFC/NFKC/NFKD normalization, HTML entities (decimal + hex), URL encoding (full, digits-only, mixed) |
| `delimiter` | Space, hyphen, dot, slash, tab, newline, mixed, doubled, none |
| `splitting` | Mid-value line break, HTML/CSS comment injection, prefix/suffix noise, JSON field split, whitespace padding, XML wrapping |
| `leetspeak` | Minimal, moderate, and aggressive substitution tiers |
| `regional_digits` | Arabic-Indic, Extended Arabic-Indic, Devanagari, Bengali, Thai, Myanmar, Khmer, Mongolian, NKo, Tibetan — plus mixed-script variants |
| `structural` | Left/right padding (spaces + zeros), noise embedding, partial values, case variation, repeated value |
| `encoding` | Base64 (standard, URL-safe, no-padding, MIME line-breaks, partial, double), ROT13, full/group reversal, double URL encoding, mixed NFD/NFC/NFKD normalization |
| `context_injection` | Value wrapped in email body, JSON record, XML element, CSV row, SQL snippet, and more |
| `unicode_whitespace` | Spaces replaced with NBSP, en-space, em-space, or a mixed pattern |
| `bidirectional` | Unicode bidirectional control characters (RLO, LRO, RLE, RLI, ALM) injected around or within the value |
| `soft_hyphen` | Soft hyphen (U+00AD) and word joiner (U+2060) inserted at group boundaries or between every character |
| `morse_code` | Digits encoded as International Morse Code — space-separated, slash-separated, concatenated, or newline-separated; applies to `credit_card`, `ssn`, `sin`, `iban`, `phone`, and related numeric categories |
| `encoding_chains` | Chained multi-step encodings: `base64(rot13)`, `base64(hex)`, `hex(base64)`, `rot13(base64)`, `url(base64)`, `base64(base64)`, and the triple chain `base64(rot13(hex))` — defeats scanners that only decode one layer |

**Submission strategies** (for dlpscan-cli adapter):

Each variant is tested four ways by default: as plain text, embedded in a DOCX, embedded in a PDF, and embedded in an XLSX. This exercises your scanner's file extraction pipeline, not just its regex layer.

**Built-in test payloads:**

Payloads are classified as **structured** or **heuristic** — see [Structured vs heuristic categories](#structured-vs-heuristic-categories) below.

225 payloads across 165 categories (211 structured, 14 heuristic). See [Coverage](#coverage) for a breakdown by region.

#### North America

| Label | Value | Category | Type |
|---|---|---|---|
| Visa 16-digit | `4532015112830366` | `credit_card` | structured |
| Amex 15-digit | `378282246310005` | `credit_card` | structured |
| Mastercard 16-digit | `5105105105105100` | `credit_card` | structured |
| Discover 16-digit | `6011111111111117` | `credit_card` | structured |
| JCB 16-digit | `3530111333300000` | `credit_card` | structured |
| UnionPay 16-digit | `6250941006528599` | `credit_card` | structured |
| Diners Club 14-digit | `30569309025904` | `credit_card` | structured |
| US SSN | `123-45-6789` | `ssn` | structured |
| US ITIN | `912-34-5678` | `us_itin` | structured |
| US EIN | `12-3456789` | `us_ein` | structured |
| US Medicare Beneficiary ID | `1EG4-TE5-MK72` | `us_mbi` | structured |
| US Passport | `340000136` | `us_passport` | structured |
| US state driver's licences (51) | one per state + DC | `us_dl` | structured |
| Canada SIN | `046 454 286` | `sin` | structured |
| Canadian passport | `AB123456` | `ca_passport` | structured |
| Quebec RAMQ health card | `BOUD 1234 5678` | `ca_ramq` | structured |
| Ontario health card | `1234-567-890-AB` | `ca_ontario_health` | structured |
| BC CareCard | `9123456789` | `ca_bc_carecard` | structured |
| Alberta health card | `123456789` | `ca_ab_health` | structured |
| Manitoba health card | `987654321` | `ca_mb_health` | structured |
| Saskatchewan health card | `234567890` | `ca_sk_health` | structured |
| Nova Scotia health card | `1234 567 890` | `ca_ns_health` | structured |
| New Brunswick health card | `1234567890` | `ca_nb_health` | structured |
| PEI health card | `123456789012` | `ca_pei_health` | structured |
| Newfoundland health card | `9876543210` | `ca_nl_health` | structured |
| Quebec driver's licence | `A12345678901234` | `ca_qc_drivers` | structured |
| Ontario driver's licence | `A1234-56789-01234` | `ca_on_drivers` | structured |
| BC driver's licence | `1234567` | `ca_bc_drivers` | structured |
| Manitoba driver's licence | `AB-123-456-789` | `ca_mb_drivers` | structured |
| Saskatchewan driver's licence | `12345678` | `ca_sk_drivers` | structured |
| Nova Scotia driver's licence | `AB1234567` | `ca_ns_drivers` | structured |
| New Brunswick driver's licence | `1234567` | `ca_nb_drivers` | structured |
| PEI driver's licence | `123456` | `ca_pei_drivers` | structured |
| Newfoundland driver's licence | `A123456789` | `ca_nl_drivers` | structured |
| Canadian Business Number | `111222333` | `ca_business_number` | structured |
| Canadian GST/HST registration | `111222333RT0001` | `ca_gst_hst` | structured |
| Canadian transit/routing number | `12345-678` | `ca_transit_number` | structured |
| Canadian bank account | `12345678` | `ca_bank_account` | structured |
| Mexico CURP | `BADD110313HCMLNS09` | `mx_curp` | structured |

#### Europe

| Label | Value | Category | Type |
|---|---|---|---|
| UK IBAN | `GB82WEST12345698765432` | `iban` | structured |
| Germany IBAN | `DE89370400440532013000` | `iban` | structured |
| France IBAN | `FR7630006000011234567890189` | `iban` | structured |
| Spain IBAN | `ES9121000418450200051332` | `iban` | structured |
| SWIFT/BIC code | `DEUTDEDB` | `swift_bic` | structured |
| ABA routing number | `021000021` | `aba_routing` | structured |
| UK National Insurance Number | `AB123456C` | `uk_nin` | structured |
| UK driving licence | `MORGA753116SM9IJ` | `uk_dl` | structured |
| German Personalausweis | `L01X00T47` | `de_id` | structured |
| Germany Steuer-IdNr | `86095742719` | `de_tax_id` | structured |
| French CNI | `880692310285` | `fr_cni` | structured |
| France INSEE (NIR) | `282097505604213` | `fr_insee` | structured |
| Spanish DNI | `12345678Z` | `es_dni` | structured |
| Italian Codice Fiscale | `RSSMRA85T10A562S` | `it_cf` | structured |
| Dutch BSN | `111222333` | `nl_bsn` | structured |
| Swedish Personnummer | `811228-9874` | `se_pin` | structured |
| Norwegian Fødselsnummer | `01010112345` | `no_fnr` | structured |
| Finnish Henkilötunnus | `131052-308T` | `fi_hetu` | structured |
| Polish PESEL | `44051401458` | `pl_pesel` | structured |
| Swiss AHV | `756.1234.5678.97` | `ch_ahv` | structured |
| Austria social insurance | `1234-010150` | `at_svn` | structured |
| Belgium National Register Number | `85.01.01-234.56` | `be_nrn` | structured |
| Bulgaria EGN | `8501010001` | `bg_egn` | structured |
| Croatia OIB | `12345678901` | `hr_oib` | structured |
| Cyprus tax ID | `12345678A` | `cy_tin` | structured |
| Czech birth number | `850101/1234` | `cz_rc` | structured |
| Denmark CPR | `010185-1234` | `dk_cpr` | structured |
| Estonia personal code | `38501010002` | `ee_ik` | structured |
| EU VAT number | `DE123456789` | `eu_vat` | structured |
| Greece AMKA | `01018512345` | `gr_amka` | structured |
| Hungary TAJ | `123 456 789` | `hu_taj` | structured |
| Iceland kennitala | `010185-1234` | `is_kt` | structured |
| Ireland PPS number | `1234567A` | `ie_pps` | structured |
| Latvia personal code | `010185-12345` | `lv_pk` | structured |
| Liechtenstein passport | `A12345` | `li_pp` | structured |
| Lithuania personal code | `38501010002` | `lt_ak` | structured |
| Luxembourg national ID | `1985012312345` | `lu_nin` | structured |
| Malta identity card | `12345A` | `mt_id` | structured |
| Portugal NIF | `123456789` | `pt_nif` | structured |
| Romania CNP | `1850101123456` | `ro_cnp` | structured |
| Slovakia birth number | `850101/1234` | `sk_bn` | structured |
| Slovenia EMSO | `0101850500003` | `si_emso` | structured |
| Turkey TC identity | `12345678901` | `tr_tc` | structured |

#### Asia-Pacific

| Label | Value | Category | Type |
|---|---|---|---|
| Australia TFN | `123 456 78` | `au_tfn` | structured |
| Australian Medicare card | `2123456701` | `au_medicare` | structured |
| Australian passport | `PA1234567` | `au_passport` | structured |
| New Zealand IRD | `123456789` | `nz_ird` | structured |
| Singapore NRIC | `S1234567D` | `sg_nric` | structured |
| Hong Kong HKID | `A123456(3)` | `hk_hkid` | structured |
| Japanese My Number | `123456789012` | `jp_my_number` | structured |
| Indian Aadhaar | `2345 6789 0123` | `in_aadhaar` | structured |
| Indian PAN | `ABCDE1234F` | `in_pan` | structured |
| Bangladesh National ID | `1234567890` | `bd_nid` | structured |
| Indonesia NIK | `3201234567890001` | `id_nik` | structured |
| Malaysia MyKad | `850101-01-1234` | `my_mykad` | structured |
| Pakistan CNIC | `12345-1234567-1` | `pk_cnic` | structured |
| Philippines PhilSys | `1234-5678-9012` | `ph_philsys` | structured |
| South Korea RRN | `880101-1234567` | `kr_rrn` | structured |
| Sri Lanka NIC | `123456789V` | `lk_nic` | structured |
| Thailand national ID | `1-1001-00001-85-1` | `th_nid` | structured |
| Vietnam CCCD | `001012345678` | `vn_cccd` | structured |

#### Latin America

| Label | Value | Category | Type |
|---|---|---|---|
| Brazilian CPF | `123.456.789-09` | `br_cpf` | structured |
| Brazilian CNPJ | `11.222.333/0001-81` | `br_cnpj` | structured |
| Argentine DNI | `12345678` | `ar_dni` | structured |
| Chilean RUT | `12.345.678-9` | `cl_rut` | structured |
| Colombia cédula | `123.456.789-0` | `co_cedula` | structured |
| Costa Rica cédula | `1-0123-0456` | `cr_cedula` | structured |
| Ecuador cédula | `1234567890` | `ec_cedula` | structured |
| Paraguay RUC | `12345678-9` | `py_ruc` | structured |
| Peru DNI | `12345678` | `pe_dni` | structured |
| Uruguay cédula | `1.234.567-8` | `uy_ci` | structured |
| Venezuela cédula | `V-12345678` | `ve_cedula` | structured |

#### Middle East & Africa

| Label | Value | Category | Type |
|---|---|---|---|
| UAE Emirates ID | `784-1234-1234567-1` | `uae_eid` | structured |
| Saudi National ID | `1234567890` | `sa_nid` | structured |
| South African ID | `9202204720082` | `za_id` | structured |
| Israeli Teudat Zehut | `123456782` | `il_id` | structured |
| Bahrain CPR | `850101234` | `bh_cpr` | structured |
| Iran Melli code | `1234567890` | `ir_melli` | structured |
| Iraq national ID | `123456789012` | `iq_nid` | structured |
| Jordan national ID | `9001012345` | `jo_nid` | structured |
| Kuwait civil ID | `285010112345` | `kw_civil` | structured |
| Lebanon passport | `RL123456` | `lb_pp` | structured |
| Qatar QID | `28501011234` | `qa_qid` | structured |

#### Africa

| Label | Value | Category | Type |
|---|---|---|---|
| Egypt National ID | `28503251234567` | `eg_nid` | structured |
| Ethiopia passport | `EP1234567` | `et_passport` | structured |
| Ghana card | `GHA-123456789-1` | `gh_card` | structured |
| Kenya KRA PIN | `A123456789B` | `ke_kra` | structured |
| Morocco CIN | `AB12345` | `ma_cin` | structured |
| Nigeria BVN | `12345678901` | `ng_bvn` | structured |
| Tanzania NIDA | `12345678901234567890` | `tz_nida` | structured |
| Tunisia CIN | `12345678` | `tn_cin` | structured |
| Uganda NIN | `CM12345678ABCD` | `ug_nin` | structured |

#### Functional

| Label | Value | Category | Type |
|---|---|---|---|
| Session token (32-char hex) | `abc123def456abc123def456abc123de` | `session_id` | structured |
| PIN block (ISO format 0) | `0123456789ABCDEF` | `pin_block` | structured |
| Biometric ID (UUID-style) | `12345678-ABCD-1234-EFGH-123456789ABC` | `biometric_id` | structured |
| Card expiry | `12/26` | `card_expiry` | structured |
| Card track 1 | `%B4532015112830366^SMITH/JOHN^2512101000000000?` | `card_track` | structured |
| MICR check line | `⑈021000021⑈ 123456789012 1234` | `micr` | structured |
| Financial amount | `USD 12,345.67` | `financial_amount` | structured |
| ISO 8601 date | `2024-01-15` | `date_iso` | structured |
| SIM ICCID | `89014103211118510720` | `iccid` | structured |
| Educational email | `john.smith@mit.edu` | `edu_email` | structured |
| Employee ID | `EMP1234567` | `employee_id` | structured |
| GPS coordinates | `40.7128,-74.0060` | `gps_coords` | structured |
| Insurance policy number | `POL123456789` | `insurance_policy` | structured |
| Bank reference | `ACCT12345678` | `bank_ref` | structured |
| Legal case number | `1:24-cv-12345` | `legal_case` | structured |
| Loan/mortgage number | `ABCD00123456789012345678` | `loan_number` | structured |
| National Drug Code | `0069-3190-03` | `ndc_code` | structured |
| Date of birth | `01/15/1985` | `dob` | structured |
| Postal code | `SW1A 1AA` | `postal_code` | structured |
| Masked PAN | `4532 XXXX XXXX 0366` | `masked_pan` | structured |
| Property parcel number | `123-456-789` | `parcel_number` | structured |
| AML case ID | `AML-123456789` | `aml_case_id` | structured |
| ISIN | `US0378331005` | `isin` | structured |
| Twitter/X handle | `@johnsmith` | `twitter_handle` | structured |
| URL with embedded credentials | `https://admin:password123@example.com/api` | `url_with_creds` | structured |
| Vehicle Identification Number | `1HGBH41JXMN109186` | `vin` | structured |
| Fedwire IMAD | `20240101AAAA12345678001234` | `fedwire_imad` | structured |

#### Global

| Label | Value | Category | Type |
|---|---|---|---|
| Bitcoin legacy address | `1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2` | `bitcoin` | structured |
| Ethereum address | `0x742d35Cc6634C0532925a3b844Bc454e4438f44e` | `ethereum` | structured |
| Email address | `test.user@example.com` | `email` | structured |
| US phone number | `+1-555-867-5309` | `phone` | structured |
| AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` | `aws_key` | heuristic |
| GitHub classic token | `ghp_16C7e42F292c6912E7710c838347Ae178B4a` | `github_token` | heuristic |
| Stripe test secret key | `sk_test_4eC39HqLyjWDarjtT7en6bh8Xy9mPqZ` | `stripe_key` | heuristic |
| Slack bot token | `xoxb-EXAMPLE-BOTTOKEN-abc123def` | `slack_token` | heuristic |
| Sample JWT | *(compact JWT string)* | `jwt` | heuristic |
| Top Secret classification label | `TOP SECRET` | `classification` | heuristic |
| HIPAA privacy label | `HIPAA` | `classification` | heuristic |
| Corporate confidential label | `Company Confidential` | `corp_classification` | heuristic |
| MNPI label | `MNPI` | `mnpi` | heuristic |
| Cardholder name (PCI) | `John Smith` | `cardholder_name` | heuristic |
| Privacy/compliance label | `PCI-DSS` | `privacy_label` | heuristic |
| Attorney-client privilege marker | `Attorney-Client Privileged` | `attorney_client` | heuristic |
| Confidential supervisory info | `Confidential Supervisory Information` | `supervisory_info` | heuristic |

Heuristic payloads are excluded from the default scan. Use `--include-heuristic` to include them.

---

## Canadian French support

evadex generates test content in Canadian French (`fr-CA`) so you can verify that your DLP scanner catches sensitive data when surrounded by French-language business text — a common real-world condition in Canadian financial institutions.

### French keyword context

The following French Canadian keywords are used as surrounding context in generated documents and evasion variants:

| Category | Keywords |
|---|---|
| `credit_card` | *carte de crédit*, *numéro de carte*, *mon numéro de carte est*, *carte bancaire*, *numéro de carte bancaire*, *paiement par carte* |
| `sin` | *numéro d'assurance sociale*, *NAS*, *mon NAS est*, *assurance sociale* |
| `iban` | *numéro de compte*, *virement bancaire*, *coordonnées bancaires*, *relevé bancaire* |
| `email` | *courriel*, *adresse courriel*, *mon courriel est* |
| `phone` | *numéro de téléphone*, *composez le*, *téléphone*, *cellulaire* |
| all categories | *renseignements personnels*, *données confidentielles*, *informations personnelles*, *vie privée* |

French keywords are active in two places:
1. **`context_injection` variants** — 10 additional French CA sentence templates are generated alongside the standard English ones during `evadex scan`.
2. **`splitting` variants** — French noise text is prepended/appended in `fr_ca_prefix_noise` and `fr_ca_suffix_noise` variants.

### `--language fr-CA`

Pass `--language fr-CA` to the `generate` command to produce test documents with French keyword context sentences:

```bash
evadex generate --format docx --category credit_card --category sin \
  --count 200 --language fr-CA --output test_fr_ca.docx

evadex generate --format csv --category ca_ramq --count 500 \
  --language fr-CA --output ramq_fr.csv
```

Without `--language`, the default is English (`en`).

---

## Structured vs heuristic categories

evadex classifies its built-in payload categories into two groups:

**Structured** — formats with well-defined, mathematically or syntactically validatable patterns. DLP scanners typically enforce these patterns precisely (e.g., Luhn check on credit cards, fixed-length digit groups for SSN/SIN, checksum-verified IBAN). Evasion results in this group reflect meaningful signal: a variant that evades detection is a real gap in coverage.

Categories: `credit_card`, `ssn`, `sin`, `us_itin`, `us_ein`, `us_mbi`, `us_dl`, `us_passport`, `iban`, `swift_bic`, `aba_routing`, `bitcoin`, `ethereum`, `au_tfn`, `au_medicare`, `au_passport`, `de_tax_id`, `de_id`, `fr_insee`, `fr_cni`, `uk_nin`, `uk_dl`, `es_dni`, `it_cf`, `nl_bsn`, `se_pin`, `no_fnr`, `fi_hetu`, `pl_pesel`, `ch_ahv`, `at_svn`, `be_nrn`, `bg_egn`, `hr_oib`, `cy_tin`, `cz_rc`, `dk_cpr`, `ee_ik`, `eu_vat`, `gr_amka`, `hu_taj`, `is_kt`, `ie_pps`, `lv_pk`, `li_pp`, `lt_ak`, `lu_nin`, `mt_id`, `pt_nif`, `ro_cnp`, `sk_bn`, `si_emso`, `tr_tc`, `nz_ird`, `sg_nric`, `hk_hkid`, `jp_my_number`, `in_aadhaar`, `in_pan`, `bd_nid`, `id_nik`, `my_mykad`, `pk_cnic`, `ph_philsys`, `kr_rrn`, `lk_nic`, `th_nid`, `vn_cccd`, `br_cpf`, `br_cnpj`, `mx_curp`, `ar_dni`, `cl_rut`, `co_cedula`, `cr_cedula`, `ec_cedula`, `py_ruc`, `pe_dni`, `uy_ci`, `ve_cedula`, `uae_eid`, `sa_nid`, `za_id`, `il_id`, `bh_cpr`, `ir_melli`, `iq_nid`, `jo_nid`, `kw_civil`, `lb_pp`, `qa_qid`, `eg_nid`, `et_passport`, `gh_card`, `ke_kra`, `ma_cin`, `ng_bvn`, `tz_nida`, `tn_cin`, `ug_nin`, `email`, `phone`, `ca_ramq`, `ca_ontario_health`, `ca_bc_carecard`, `ca_ab_health`, `ca_qc_drivers`, `ca_on_drivers`, `ca_bc_drivers`, `ca_passport`, `ca_mb_health`, `ca_sk_health`, `ca_ns_health`, `ca_nb_health`, `ca_pei_health`, `ca_nl_health`, `ca_mb_drivers`, `ca_sk_drivers`, `ca_ns_drivers`, `ca_nb_drivers`, `ca_pei_drivers`, `ca_nl_drivers`, `ca_business_number`, `ca_gst_hst`, `ca_transit_number`, `ca_bank_account`, `session_id`, `pin_block`, `biometric_id`, `card_expiry`, `card_track`, `micr`, `financial_amount`, `date_iso`, `iccid`, `edu_email`, `employee_id`, `gps_coords`, `insurance_policy`, `bank_ref`, `legal_case`, `loan_number`, `ndc_code`, `dob`, `postal_code`, `masked_pan`, `parcel_number`, `aml_case_id`, `isin`, `twitter_handle`, `url_with_creds`, `vin`, `fedwire_imad`

**Heuristic** — formats where detection relies on fixed prefixes, high-entropy pattern matching, or loosely defined structure. DLP rules for these categories vary widely between scanners and configurations, and a "fail" result may simply reflect that the scanner never had a strong rule for that specific format variant — not that a real exfiltration path was found.

Categories: `aws_key`, `jwt`, `github_token`, `stripe_key`, `slack_token`, `classification`, `corp_classification`, `mnpi`, `cardholder_name`, `privacy_label`, `attorney_client`, `supervisory_info`

Heuristic categories are excluded from the default scan to avoid misleading results. Include them with:

```bash
evadex scan --tool dlpscan-cli --include-heuristic
```

A warning is printed to stderr whenever `--include-heuristic` is active reminding you to interpret those results with caution.

---

## Installation

Requires Python 3.10+.

```bash
pip install evadex
```

Or install from source:

```bash
git clone https://github.com/tbustenk/evadex
cd evadex
pip install -e ".[dev]"
```

For reproducible installs with pinned, hash-verified dependencies (recommended for regulated environments):

```bash
pip install -r requirements.txt        # runtime only
pip install -r requirements-dev.txt    # runtime + test dependencies
```

These lockfiles are generated with `pip-compile --generate-hashes` and updated with each release.

---

## Quick start

Run the full built-in suite against dlpscan (text strategy):

```bash
evadex scan --tool dlpscan-cli --strategy text
```

Test a single value:

```bash
evadex scan --tool dlpscan-cli --input "4532015112830366" --strategy text
```

Test with all file strategies (slower — exercises DOCX/PDF/XLSX extraction):

```bash
evadex scan --tool dlpscan-cli --input "4532015112830366"
```

Generate an HTML report:

```bash
evadex scan --tool dlpscan-cli --strategy text --format html -o report.html
```

---

## Configuration

evadex supports an optional `evadex.yaml` config file. Config file values are defaults — any CLI flag you pass overrides the corresponding config value.

### Generating a starter config

```bash
evadex init
```

Creates `evadex.yaml` in the current directory:

```yaml
# evadex configuration file
# Run 'evadex scan --config evadex.yaml' to use this file.
# CLI flags take precedence over values in this file.

tool: dlpscan-cli
strategy: text
min_detection_rate: 85
scanner_label: production
exe: null
cmd_style: python
categories:
  - credit_card
  - ssn
  - iban
include_heuristic: false
concurrency: 5
timeout: 30.0
output: results.json
format: json
```

### Using a config file

Pass it explicitly:

```bash
evadex scan --config evadex.yaml
```

Or drop `evadex.yaml` in the current directory and evadex will pick it up automatically — no flag needed.

CLI flags always win. To override a config value for one run:

```bash
# Config says scanner_label: production — this run uses "staging" instead
evadex scan --config evadex.yaml --scanner-label staging
```

### Config keys

| Key | Type | CLI equivalent | Description |
|---|---|---|---|
| `tool` | string | `--tool` | Adapter name (`dlpscan-cli`, `dlpscan`, `presidio`) |
| `strategy` | string or list | `--strategy` | Submission strategy: `text`, `docx`, `pdf`, `xlsx`. Use a list for multiple. |
| `min_detection_rate` | number | `--min-detection-rate` | CI/CD gate threshold (0–100) |
| `scanner_label` | string | `--scanner-label` | Label recorded in JSON `meta.scanner` |
| `exe` | string or null | `--exe` | Path to scanner executable |
| `cmd_style` | `python` or `rust` | `--cmd-style` | Command format for dlpscan-cli |
| `categories` | list of strings | `--category` | Payload categories to test |
| `include_heuristic` | boolean | `--include-heuristic` | Include heuristic categories |
| `concurrency` | integer | `--concurrency` | Max concurrent requests |
| `timeout` | number | `--timeout` | Request timeout in seconds |
| `output` | string or null | `--output` | Output file path (null = stdout) |
| `format` | `json` or `html` | `--format` | Output format |
| `audit_log` | string or null | `--audit-log` | Append-only audit log file (see [Audit log](#audit-log)) |

### Validation

evadex validates the config file on load and exits with a clear error for invalid values:

```
Error: Config 'min_detection_rate' must be between 0 and 100, got: 150.0
Error: Invalid strategy value(s): foobar. Valid: docx, pdf, text, xlsx
Error: Unknown config key(s): bad_key. Valid keys: categories, cmd_style, ...
```

---

## Example output

### Terminal summary

```
Running evadex scan against dlpscan-cli at http://localhost:8080...
Done. 590 tests — N detected, N evaded
```

Detection rates depend on your scanner, its version, and how it's configured.

### JSON output (`--format json`, default)

```json
{
  "meta": {
    "timestamp": "2026-04-01T22:01:36.172424+00:00",
    "scanner": "rust-2.0.0",
    "total": 590,
    "pass": 514,
    "fail": 76,
    "error": 0,
    "pass_rate": 87.1,
    "summary_by_category": {
      "credit_card": { "pass": 109, "fail": 15, "error": 0 },
      "ssn":         { "pass": 43,  "fail": 10, "error": 0 },
      "iban":        { "pass": 36,  "fail": 8,  "error": 0 }
    },
    "summary_by_generator": {
      "delimiter":        { "pass": 72, "fail": 10, "error": 0 },
      "unicode_encoding": { "pass": 54, "fail": 13, "error": 0 }
    }
  },
  "results": [
    {
      "payload": {
        "value": "5105105105105100",
        "category": "credit_card",
        "category_type": "structured",
        "label": "Mastercard 16-digit"
      },
      "variant": {
        "value": "5105105105105100",
        "generator": "delimiter",
        "technique": "no_delimiter",
        "transform_name": "All delimiters removed",
        "strategy": "text"
      },
      "detected": true,
      "severity": "pass",
      "duration_ms": 371.01,
      "error": null,
      "raw_response": { "matches": [{ "type": "credit_card", "value": "5105105105105100" }] }
    },
    {
      "payload": {
        "value": "046 454 286",
        "category": "sin",
        "category_type": "structured",
        "label": "Canada SIN"
      },
      "variant": {
        "value": "Ο4б 4Ƽ4 ΚȢб",
        "generator": "unicode_encoding",
        "technique": "homoglyph_substitution",
        "transform_name": "Visually similar Cyrillic/Greek characters substituted",
        "strategy": "text"
      },
      "detected": false,
      "severity": "fail",
      "duration_ms": 378.57,
      "error": null,
      "raw_response": { "matches": [] }
    }
  ]
}
```

**Severity values:**

| Value | Meaning |
|---|---|
| `pass` | Scanner detected the variant (good) |
| `fail` | Scanner missed the variant — evasion succeeded |
| `error` | Adapter error (network, timeout, malformed scanner response, etc.) |

---

## CLI reference

### `evadex scan`

Run DLP evasion tests against a scanner.

```
evadex scan [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--config` | *(auto-discovered)* | Path to `evadex.yaml` config file. Auto-discovered from current directory if present. CLI flags always override config values. |
| `--tool`, `-t` | `dlpscan-cli` | Adapter to use. Built-in adapters: `dlpscan-cli`, `dlpscan`, `presidio`. |
| `--input`, `-i` | *(all built-ins)* | Single value to test. If omitted, runs all 211 structured built-in payloads (add `--include-heuristic` for all 225). Category is auto-detected (Luhn check, regex patterns for SSN/IBAN/AWS/JWT/email/phone). |
| `--format`, `-f` | `json` | Output format: `json` or `html` |
| `--output`, `-o` | stdout | Write report to file instead of stdout |
| `--strategy` | all four | Submission strategy: `text`, `docx`, `pdf`, `xlsx`. Repeat the flag for multiple. Omit to run all four. |
| `--concurrency` | `5` | Max concurrent requests |
| `--timeout` | `30.0` | Request timeout in seconds |
| `--url` | `http://localhost:8080` | Base URL (for HTTP-based adapters: `dlpscan`, `presidio`) |
| `--api-key` | *(env: `EVADEX_API_KEY`)* | API key passed as `Authorization: Bearer`. Use the environment variable in preference to the CLI flag to avoid exposure in shell history and process listings. |
| `--category` | *(all structured)* | Filter built-in payloads by category. Repeat for multiple. Values: `credit_card`, `ssn`, `sin`, `iban`, `swift_bic`, `aba_routing`, `bitcoin`, `ethereum`, `us_passport`, `au_tfn`, `de_tax_id`, `fr_insee`, `email`, `phone`, `aws_key`, `jwt`, `github_token`, `stripe_key`, `slack_token`, `classification` |
| `--variant-group` | *(all)* | Limit to specific generator(s). Repeat for multiple. Values: `unicode_encoding`, `delimiter`, `splitting`, `leetspeak`, `regional_digits`, `structural`, `encoding`, `context_injection`, `unicode_whitespace`, `bidirectional`, `soft_hyphen`, `morse_code` |
| `--include-heuristic` | off | Also run heuristic categories (`aws_key`, `jwt`, `github_token`, `stripe_key`, `slack_token`, `classification`). A warning is printed when enabled — see [Structured vs heuristic categories](#structured-vs-heuristic-categories). |
| `--scanner-label` | *(empty)* | Label recorded in the JSON `meta.scanner` field. Use to tag a specific scanner version, e.g. `python-1.3.0` or `rust-2.0.0`. Useful when comparing results across scanner builds. |
| `--exe` | `dlpscan` | Path to the scanner executable (dlpscan-cli adapter only). Use when `dlpscan` is not on `PATH` or you need to target a specific build. |
| `--cmd-style` | `python` | Command format for dlpscan-cli: `python` (invokes `dlpscan -f json <file>`) or `rust` (invokes `dlpscan --format json scan <file>`). |
| `--min-detection-rate` | *(off)* | Exit with code 1 if the detection rate falls below this threshold (0–100). Intended for CI/CD pipeline gating. Report is always written before the exit. |
| `--baseline` | *(off)* | Save this run's JSON results to a file for future comparison. |
| `--compare-baseline` | *(off)* | Compare this run against a previously saved baseline and print a regression summary to stderr. |
| `--audit-log` | *(off)* | Append a one-line JSON audit record for this run to a file. Parent directories are created if they do not exist. Can also be set via `audit_log` in `evadex.yaml`. |
| `--feedback-report` | *(off)* | Save a structured JSON feedback report to PATH. Contains per-technique evasion counts with example variant values, actionable fix suggestions, and the generated regression test code as a string field. Always written when specified, even if there are no evasions. |

### `evadex generate`

Generate test documents filled with synthetic sensitive data for DLP scanner testing. Values are embedded in realistic business sentences, tables, and paragraphs. Evasion variants use the same obfuscation techniques as `evadex scan`.

```
evadex generate --format FORMAT --output PATH [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--format` | *(required)* | Output file format: `xlsx`, `docx`, `pdf`, `csv`, `txt` |
| `--output` | *(required)* | Output file path |
| `--category` | *(all structured)* | Payload category to include. Repeat for multiple. Omit for all structured categories. |
| `--count` | `100` | Number of test values to generate **per category** |
| `--evasion-rate` | `0.5` | Fraction of values that are evasion variants (0.0–1.0) |
| `--keyword-rate` | `0.5` | Fraction of values wrapped in keyword context sentences (0.0–1.0) |
| `--technique` | *(all)* | Limit evasion variants to specific technique names. Repeat for multiple. |
| `--random` | off | Randomise categories, evasion rate, and keyword rate |
| `--seed` | *(none)* | Integer seed for reproducible output |
| `--include-heuristic` | off | Also include heuristic categories (AWS keys, tokens, JWT, etc.) |
| `--language` | `en` | Language for keyword context sentences: `en` (English) or `fr-CA` (Canadian French) |

**Format details:**

- **`xlsx`** — Multiple sheets: one `Summary` sheet plus one sheet per category. Columns include embedded text, plain value, variant value, technique, and generator. Evasion rows are highlighted yellow.
- **`docx`** — Title page with disclaimer; one heading per category; two-thirds prose paragraphs, one-third tabular layout.
- **`pdf`** — Sections per category with header/footer; evasion rows highlighted.
- **`csv`** — Flat CSV with columns: `category`, `plain_value`, `variant_value`, `technique`, `generator`, `transform_name`, `has_keywords`, `embedded_text`.
- **`txt`** — Plain-text document with section headings and numbered entry list.

**Examples:**

```bash
# 100 credit cards, 40% evasion variants → XLSX
evadex generate --format xlsx --category credit_card --count 100 \
  --evasion-rate 0.4 --output test_cards.xlsx

# Mixed categories → DOCX
evadex generate --format docx \
  --category credit_card --category ssn --category iban \
  --count 50 --evasion-rate 0.5 --output test_mixed.docx

# Specific evasion techniques only → PDF
evadex generate --format pdf --count 200 --evasion-rate 0.6 \
  --technique homoglyph_substitution --technique zero_width_zwsp \
  --output test_homoglyph.pdf

# Reproducible random document
evadex generate --format xlsx --random --count 500 --seed 42 --output random.xlsx

# CSV for programmatic inspection
evadex generate --format csv --category ssn --count 1000 \
  --evasion-rate 0.3 --output ssn_variants.csv
```

**Value generation:**

evadex generates values two ways:

- **Synthetic generators** (preferred, unlimited) — Produce structurally valid values algorithmically, so `--count 1000` always returns 1000 distinct values. Registered for:
  - `credit_card` — Luhn-valid numbers for Visa, Mastercard, Amex, Discover
  - `sin` — Valid Canadian SINs (Luhn checksum, NNN NNN NNN format)
  - `iban` — Valid IBANs for GB, DE, and FR (ISO 13616 mod-97 checksum)
  - `phone` — Canadian E.164 numbers (`+1-NPA-NXX-XXXX`) from real area codes
  - `email` — Realistic addresses with common Canadian and international domains
  - `ca_ramq` — Quebec RAMQ health card numbers (XXXX YYMM DDSS format)
  - `ca_mb_health`, `ca_sk_health` — 9-digit Manitoba/Saskatchewan health cards
  - `ca_ns_health` — Nova Scotia 10-digit health card (NNNN NNN NNN format)
  - `ca_nb_health`, `ca_nl_health` — 10-digit NB/NL health cards
  - `ca_pei_health` — 12-digit PEI health card
  - `ca_mb_drivers` — Manitoba licence (LL-NNN-NNN-NNN format)
  - `ca_sk_drivers` — Saskatchewan 8-digit licence
  - `ca_ns_drivers` — Nova Scotia licence (2 letters + 7 digits)
  - `ca_nb_drivers` — New Brunswick 7-digit licence
  - `ca_pei_drivers` — PEI 6-digit licence
  - `ca_nl_drivers` — Newfoundland licence (1 letter + 9 digits)
  - `ca_business_number` — Canadian Business Number (9 digits, CRA)
  - `ca_gst_hst` — GST/HST registration (9-digit BN + RT + 4 digits)
  - `ca_transit_number` — Transit/routing number (NNNNN-NNN format)
  - `ca_bank_account` — Bank account (7–12 random digits)
- **Seed rotation fallback** — Categories without a synthetic generator rotate through the built-in seed values.
- **Evasion variants** — Drawn from all 12 evadex generators (same techniques as `evadex scan`). Use `--technique` to restrict to specific techniques.

---

### `evadex compare`

Diff two evadex scan result JSON files and report what changed between them.

```
evadex compare [OPTIONS] FILE_A FILE_B
```

| Flag | Default | Description |
|---|---|---|
| `--format`, `-f` | `json` | Output format: `json` or `html` |
| `--output`, `-o` | stdout | Write report to file instead of stdout |
| `--label-a` | *(from JSON meta.scanner)* | Override the label for the first file |
| `--label-b` | *(from JSON meta.scanner)* | Override the label for the second file |

The compare report includes:
- Overall delta in detection rate (percentage points)
- Per-category detection rate changes
- Per-technique detection rate changes (only techniques where the rate changed)
- Per-variant diff list (variants where severity changed between the two runs)

### `evadex init`

Generate a default `evadex.yaml` config file in the current directory.

```
evadex init
```

Creates `evadex.yaml` with sensible defaults. Edit the file and run `evadex scan --config evadex.yaml`, or drop it in the working directory for auto-discovery.

### `evadex falsepos`

Measure scanner false positive rate — values that look like sensitive data but are provably invalid.

Generates structurally plausible but mathematically invalid values (Luhn-failing credit card numbers, SSNs with reserved area codes, SINs with wrong checksums, IBAN-shaped strings with invalid mod-97 checks, etc.) and submits them to the scanner. Any value the scanner flags is a false positive.

```
evadex falsepos [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--tool`, `-t` | `dlpscan-cli` | Adapter to use |
| `--category` | *(all)* | Category to test. Repeat for multiple. Supported: `credit_card`, `ssn`, `sin`, `iban`, `email`, `phone`, `ca_ramq` |
| `--count` | `100` | Number of false positive values per category |
| `--format`, `-f` | `table` | Output format: `table` (summary to stderr) or `json` (full report) |
| `--output`, `-o` | stdout | Write JSON report to file |
| `--exe` | `dlpscan` | Path to scanner executable (dlpscan-cli only) |
| `--cmd-style` | `python` | Command format for dlpscan-cli: `python` or `rust` |
| `--timeout` | `30.0` | Request timeout in seconds |
| `--concurrency` | `5` | Max concurrent scanner requests |
| `--seed` | *(random)* | Integer seed for reproducible false positive values |

**Examples:**

```bash
# Test false positive rate for credit cards
evadex falsepos --tool dlpscan-cli --category credit_card --count 100

# All categories
evadex falsepos --tool dlpscan-cli --count 100

# Save JSON report
evadex falsepos --tool dlpscan-cli --count 100 --format json -o falsepos_report.json
```

**Output:**

```
  credit_card            0/100 flagged  (0.0%)
  ssn                    2/100 flagged  (2.0%)
  sin                    0/100 flagged  (0.0%)
  ...

Overall false positive rate: 0.3%  (2/700)
```

The JSON report includes per-category rates, overall rate, and the list of specific values that were incorrectly flagged:

```json
{
  "tool": "dlpscan-cli",
  "count_per_category": 100,
  "total_tested": 700,
  "total_flagged": 2,
  "overall_false_positive_rate": 0.3,
  "by_category": {
    "credit_card": {
      "total": 100,
      "flagged": 0,
      "false_positive_rate": 0.0,
      "flagged_values": []
    },
    "ssn": {
      "total": 100,
      "flagged": 2,
      "false_positive_rate": 2.0,
      "flagged_values": ["000-12-3456", "666-99-0001"]
    }
  }
}
```

**False positive generators by category:**

| Category | Generation strategy |
|---|---|
| `credit_card` | 16-digit numbers with card-like prefixes (4, 51, 37, 6011) that fail the Luhn check |
| `ssn` | `NNN-NN-NNNN` with reserved area codes: 000, 666, 900–999 |
| `sin` | `NNN NNN NNN` with valid first digit (1–7) but wrong Luhn check digit |
| `iban` | IBAN-shaped strings (GB/DE/FR) with a deliberately wrong mod-97 check digit |
| `email` | `user@domain.invalid` — uses IANA-reserved TLDs (`.invalid`, `.test`, `.example`, `.localhost`) |
| `phone` | `+1-NPA-NXX-XXXX` with invalid NANP area codes (000, 555, 911, etc.) |
| `ca_ramq` | RAMQ-shaped `XXXX YYMM DDSS` with invalid birth month codes (00, 13–50, 63–99) |

---

### `evadex list-payloads`

List all built-in test payloads with their categories and types.

```
evadex list-payloads [--type structured|heuristic]
```

| Flag | Default | Description |
|---|---|---|
| `--type` | *(all)* | Filter to `structured` or `heuristic` payloads only |

### `evadex list-techniques`

List all registered evasion generators and the techniques each one applies.

```
evadex list-techniques [--generator NAME]
```

| Flag | Default | Description |
|---|---|---|
| `--generator`, `-g` | *(all)* | Show techniques for a specific generator only |

### Examples

```bash
# Only test credit card payloads
evadex scan --tool dlpscan-cli --strategy text --category credit_card

# Only run unicode evasion techniques
evadex scan --tool dlpscan-cli --strategy text --variant-group unicode_encoding

# Only run unicode + delimiter techniques on SSN and IBAN
evadex scan --tool dlpscan-cli --strategy text \
  --category ssn --category iban \
  --variant-group unicode_encoding --variant-group delimiter

# Test a custom value (category auto-detected)
evadex scan --tool dlpscan-cli --input "AKIAIOSFODNN7EXAMPLE" --strategy text

# File strategy only — test DOCX extraction pipeline
evadex scan --tool dlpscan-cli --input "4532015112830366" --strategy docx

# Save HTML report
evadex scan --tool dlpscan-cli --strategy text --format html -o report.html

# Target a specific scanner binary, tag the output
evadex scan --tool dlpscan-cli --exe /opt/dlpscan/dlpscan --cmd-style rust \
  --scanner-label "rust-2.0.0" --format json -o rust_results.json

# Compare two scanner builds
evadex scan --tool dlpscan-cli --scanner-label "python-1.3.0" -o python.json
evadex scan --tool dlpscan-cli --exe /opt/rust-dlpscan --cmd-style rust \
  --scanner-label "rust-2.0.0" -o rust.json
evadex compare python.json rust.json --format html -o comparison.html
```

---

## CI/CD integration

evadex supports a `--min-detection-rate` flag that exits with code 1 if the scanner's detection rate falls below a threshold. Use it as a pipeline gate to prevent deploying a scanner configuration that regresses detection coverage.

```bash
evadex scan --tool dlpscan-cli \
  --strategy text \
  --scanner-label "$(dlpscan --version)" \
  --format json -o results.json \
  --min-detection-rate 90
```

Exit code 0 means the threshold was met; exit code 1 means it was not. The report is always written before the exit check.

To track regressions against a known-good baseline:

```bash
# Save a baseline from the current production scanner
evadex scan --tool dlpscan-cli --scanner-label "prod-baseline" \
  --baseline baseline.json

# In CI: compare the candidate scanner against the baseline
evadex scan --tool dlpscan-cli --scanner-label "candidate" \
  --compare-baseline baseline.json \
  --min-detection-rate 90
```

The `--compare-baseline` flag prints a regression summary to stderr listing any variants that were previously detected and are now missed, and any improvements.

---

## Audit log

evadex can append a one-line JSON record to a log file after every scan. This gives you a durable, append-only history of what was tested, when, and what the result was — useful for compliance reviews, trend tracking, and demonstrating that regular scans are being performed.

```bash
evadex scan --tool dlpscan-cli \
  --scanner-label "rust-2.0.0" \
  --strategy text \
  --audit-log /var/log/evadex/audit.jsonl
```

Or set it in `evadex.yaml` so it fires automatically on every run:

```yaml
audit_log: /var/log/evadex/audit.jsonl
```

### Audit record format

Each run appends exactly one line. Fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO 8601 string | When the scan ran (UTC) |
| `evadex_version` | string | Installed evadex version |
| `operator` | string | OS username of the person who ran the scan |
| `scanner_label` | string | Value of `--scanner-label` (empty if not set) |
| `tool` | string | Adapter used |
| `strategies` | array | Submission strategies used |
| `categories` | array | Categories filtered to (empty = all structured) |
| `include_heuristic` | bool | Whether heuristic categories were included |
| `total` | int | Total test cases run |
| `pass` | int | Variants detected |
| `fail` | int | Variants that evaded scanner |
| `error` | int | Adapter errors |
| `pass_rate` | float | Detection rate percentage |
| `output_file` | string \| null | Path of the report file written, or null |
| `baseline_saved` | string \| null | Path of baseline saved, or null |
| `compare_baseline` | string \| null | Path of baseline compared against, or null |
| `min_detection_rate` | float \| null | Gate threshold used, or null |
| `exit_code` | int | `0` if scan succeeded, `1` if detection-rate gate failed |

### Notes

- The log file is opened in append mode — existing entries are never modified or deleted.
- Parent directories are created automatically if they do not exist.
- A write failure (permissions, disk full, bad path) is silently ignored. The scan result and exit code are never affected by audit log errors.
- The log contains detection rates and category breakdowns but **not** variant values. It is safe to store in shared log aggregation systems.

---

## Feedback loop

evadex Phase 2 implements a GAN-inspired feedback cycle: evadex is the **adversarial fuzzer** and your DLP scanner is the **discriminator**. When the fuzzer finds an evasion that works, the system automatically surfaces what failed and how to close the gap — without requiring manual triage.

After any scan that produces evasions, evadex does three things automatically:

1. **Prints fix suggestions to stderr** — one concrete, actionable normalisation step per unique bypass technique.
2. **Writes `evadex_regressions.py`** to the current directory — a pytest file with one test function per evasion, using dlpscan's `InputGuard` API. These tests fail until the scanner is fixed.
3. **Optionally writes a structured JSON feedback report** via `--feedback-report PATH`.

### Fix suggestions

Suggestions are printed to stderr after the scan summary whenever evasions are found:

```
=== Fix Suggestions ===
  • homoglyph_substitution (unicode_encoding)
    Add Cyrillic/Greek lookalikes to homoglyph normalisation map: О→0, З→3, ο→0, Α→A, Ζ→Z.
    Apply NFKC normalisation then a homoglyph table lookup before scanning
  • zero_width_zwsp (unicode_encoding)
    Strip U+200B (Zero Width Space) from input in the normalisation pipeline before pattern matching
  • base64_standard (encoding)
    Add a base64 decode pass to the normalisation pipeline; scan the decoded content
```

Each suggestion names the technique, the generator group it belongs to, and a specific normalisation step to add to the scanner's input pipeline.

### Regression test file

`evadex_regressions.py` is written to the current directory whenever there are evasions. Each test function:

- Is named after the payload label and evasion technique (`test_visa_16_digit_homoglyph_substitution`)
- Imports and invokes dlpscan's `InputGuard` with the appropriate preset (`PCI_DSS`, `PII`, or `CREDENTIALS`)
- Scans the exact obfuscated variant value that evaded detection
- Asserts `not result.is_clean` — the test passes once the scanner is fixed

```python
def test_visa_16_digit_homoglyph_substitution():
    """Visa 16-digit evaded via homoglyph_substitution — should be detected"""
    from dlpscan import InputGuard, Preset
    guard = InputGuard(presets=[Preset.PCI_DSS])
    result = guard.scan('4532\u041e15112830366')  # Visually similar Cyrillic/Greek characters substituted
    assert not result.is_clean


def test_canada_sin_zero_width_zwsp():
    """Canada SIN evaded via zero_width_zwsp — should be detected"""
    from dlpscan import InputGuard, Preset
    guard = InputGuard(presets=[Preset.PII])
    result = guard.scan('0\u200b4\u200b6\u200b \u200b4\u200b5\u200b4\u200b \u200b2\u200b8\u200b6')  # Zero-width ZWSP between every character
    assert not result.is_clean
```

Run the generated file with:

```bash
pytest evadex_regressions.py
```

Tests fail until the scanner is patched. Each time you fix a technique and re-run evadex, failing tests disappear and the regression file is regenerated to reflect the remaining gaps.

### `--feedback-report PATH`

Saves a structured JSON report containing everything in one file:

```bash
evadex scan --feedback-report feedback.json
```

**Report structure:**

```json
{
  "meta": {
    "timestamp": "2026-04-07T14:22:01.123456+00:00",
    "scanner": "python-1.6.0",
    "total_tests": 590,
    "total_evasions": 76
  },
  "techniques": [
    {
      "technique": "homoglyph_substitution",
      "generator": "unicode_encoding",
      "count": 23,
      "example_variants": ["4532\u041e15112830366", "4\u03bf32015112830366"]
    },
    {
      "technique": "zero_width_zwsp",
      "generator": "unicode_encoding",
      "count": 18,
      "example_variants": ["0\u200b4\u200b6 4\u200b5\u200b4 2\u200b8\u200b6"]
    }
  ],
  "fix_suggestions": [
    {
      "technique": "homoglyph_substitution",
      "generator": "unicode_encoding",
      "description": "Sensitive values bypassed detection by substituting ASCII digits/letters with visually identical Unicode characters from Cyrillic, Greek, or other scripts",
      "suggested_fix": "Add Cyrillic/Greek lookalikes to homoglyph normalisation map: О→0, З→3, ο→0, Α→A, Ζ→Z. Apply NFKC normalisation then a homoglyph table lookup before scanning"
    }
  ],
  "regression_test_code": "\"\"\"Regression tests generated by evadex.\n...\"\"\"\nimport pytest\n\n\ndef test_visa_16_digit_homoglyph_substitution():\n    ..."
}
```

The report is always written, even when there are no evasions (techniques and fix_suggestions will be empty arrays, regression_test_code will be an empty string).

### Three-phase design

| Phase | Role | Status |
|---|---|---|
| Phase 1 | Adversarial fuzzer — evasion generators test known-sensitive values against the scanner | ✅ Done |
| Phase 2 | Feedback generator — surfaces fix suggestions, regression tests, and structured reports when evasions succeed | ✅ Done |
| Phase 3 | False-positive adversary — generates values that *look* sensitive but aren't, to measure scanner precision | ✅ Done (`evadex falsepos`) |

Together, Phase 1 measures **false negatives** (sensitive values the scanner misses) and Phase 3 measures **false positives** (non-sensitive values the scanner incorrectly flags). Both are needed for a complete picture of scanner accuracy.

---

## Adapters

### Built-in: `dlpscan-cli`

Invokes the [dlpscan](https://github.com/oxide11/dlpscan) CLI directly as a subprocess. evadex was built and tested with dlpscan as the reference scanner. Requires `dlpscan` to be installed and on `PATH` (or provide `--exe`).

```bash
evadex scan --tool dlpscan-cli
```

For file strategies, evadex builds the document in memory and writes it to a temp file, runs the scanner against it, then immediately deletes the temp file. No persistent disk footprint from test data. File extraction support in dlpscan requires `pip install dlpscan[office]`.

### Built-in: `dlpscan`

Generic HTTP adapter for any DLP tool that exposes a REST API. Sends plain text to `POST /scan` with a `{"content": "..."}` body, and file uploads to `POST /scan/file` as multipart form data. Expects a JSON response with a `detected` boolean (configurable via the `response_detected_key` extra config option).

```bash
evadex scan --tool dlpscan --url http://my-dlpscan-server:8080 --api-key my-key
```

### Adding a custom adapter

1. Create a file anywhere in your project, e.g. `my_adapter.py`.

2. Subclass `BaseAdapter` and implement `submit()`:

```python
from evadex.adapters.base import BaseAdapter
from evadex.core.registry import register_adapter
from evadex.core.result import Payload, Variant, ScanResult


@register_adapter("my-tool")
class MyToolAdapter(BaseAdapter):
    name = "my-tool"

    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        # Send variant.value to your scanner however it expects it.
        # variant.strategy is "text", "docx", "pdf", or "xlsx".
        # Return a ScanResult with detected=True/False.
        response = await call_my_scanner(variant.value)
        detected = response.get("found", False)
        return ScanResult(
            payload=payload,
            variant=variant,
            detected=detected,
            raw_response=response,
        )
```

3. Import your adapter before invoking evadex (so the `@register_adapter` decorator fires), then use it:

```bash
python -c "import my_adapter" && evadex scan --tool my-tool
```

Or wire it up properly as a package with an entry point in `pyproject.toml`:

```toml
[project.entry-points."evadex.adapters"]
my-tool = "my_package.my_adapter"
```

**Optional hooks:**

```python
async def setup(self):
    # Called once before the batch — open connections, authenticate, etc.
    self._session = await open_session()

async def teardown(self):
    # Called once after the batch — clean up connections.
    await self._session.close()

async def health_check(self) -> bool:
    # Optional — verify the scanner is reachable.
    return await ping_scanner()
```

**File strategies:** `variant.strategy` tells you which format evadex wants to use. If your scanner only supports one method, handle what you need:

```python
from evadex.adapters.dlpscan.file_builder import FileBuilder

async def submit(self, payload, variant):
    if variant.strategy == "text":
        raw = await self._scan_text(variant.value)
    else:
        data, mime = FileBuilder.build(variant.value, variant.strategy)
        raw = await self._scan_file(data, mime)
    ...
```

`FileBuilder.build(text, fmt)` returns `(bytes, mime_type)` entirely in memory — no disk writes.

---

## Output schema

### Top-level

```json
{
  "meta": { ... },
  "results": [ ... ]
}
```

### `meta`

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO 8601 string | When the scan ran (UTC) |
| `scanner` | string | Scanner label from `--scanner-label` (empty string if not set) |
| `total` | int | Total test cases run |
| `pass` | int | Variants detected by scanner |
| `fail` | int | Variants that evaded scanner |
| `error` | int | Adapter errors |
| `pass_rate` | float | `pass / total * 100`, rounded to one decimal |
| `summary_by_category` | object | Per-category pass/fail/error counts, sorted alphabetically by category name |
| `summary_by_generator` | object | Per-generator pass/fail/error counts, sorted alphabetically by generator name |

### `results[]`

| Field | Type | Description |
|---|---|---|
| `payload.value` | string | Original sensitive value |
| `payload.category` | string | Detected category enum value |
| `payload.category_type` | string | `structured` or `heuristic` — see [Structured vs heuristic categories](#structured-vs-heuristic-categories) |
| `payload.label` | string | Human-readable label |
| `variant.value` | string | Transformed/obfuscated value submitted to scanner |
| `variant.generator` | string | Which generator produced this variant |
| `variant.technique` | string | Machine-readable technique name |
| `variant.transform_name` | string | Human-readable description of the transform |
| `variant.strategy` | string | Submission strategy: `text`, `docx`, `pdf`, `xlsx` |
| `detected` | bool | Whether the scanner flagged this variant. `false` for error results — check `severity` to distinguish |
| `severity` | string | `pass` (detected), `fail` (not detected), or `error` (adapter error) |
| `duration_ms` | float | Time for this test case in milliseconds |
| `error` | string \| null | Error message if adapter threw; `null` otherwise |
| `raw_response` | object | Raw parsed response from the adapter. For `dlpscan-cli` this is `{"matches": [...]}`. May contain match objects that include the variant value — treat the output file accordingly. |

---

## Coverage

evadex payload coverage relative to the dlpscan-rs pattern library (557 patterns across 126 categories).

| Region | dlpscan-rs categories | evadex categories covered | Notes |
|---|---|---|---|
| North America — United States | 64 patterns (US + generic DL) | `ssn`, `us_itin`, `us_ein`, `us_mbi`, `us_passport`, `us_dl` (51 state examples) | All 50 states + DC represented in `us_dl` |
| North America — Canada | 29 patterns | All 29 covered across provincial health/DL/corporate categories | Full coverage |
| North America — Mexico | 7 patterns | `mx_curp` | CURP covered; RFC, Clave Elector, NSS, INE not yet added |
| Europe — United Kingdom | 7 patterns | `iban`, `uk_nin`, `uk_dl` | NHS, UTR, Sort Code not yet added |
| Europe — Germany | 6 patterns | `de_tax_id`, `de_id`, `iban` | Social insurance, DL not yet added |
| Europe — France | 5 patterns | `fr_insee`, `fr_cni`, `iban` | DL not yet added |
| Europe — Spain | 5 patterns | `es_dni`, `iban` | NIE, NSS not yet added |
| Europe — Italy | 5 patterns | `it_cf` | DL, Partita IVA not yet added |
| Europe — Netherlands | 4 patterns | `nl_bsn`, `iban` | DL not yet added |
| Europe — Sweden | 4 patterns | `se_pin` | Org number, DL not yet added |
| Europe — Norway | 4 patterns | `no_fnr` | D-Number, DL not yet added |
| Europe — Poland | 6 patterns | `pl_pesel` | NIP, REGON, DL not yet added |
| Europe — Switzerland | 4 patterns | `ch_ahv` | UID not yet added |
| Europe — Finland | 3 patterns | `fi_hetu` | DL not yet added |
| Europe — (other 14 countries) | ~60 patterns | `at_svn`, `be_nrn`, `bg_egn`, `hr_oib`, `cy_tin`, `cz_rc`, `dk_cpr`, `ee_ik`, `eu_vat`, `gr_amka`, `hu_taj`, `is_kt`, `ie_pps`, `lv_pk`, `li_pp`, `lt_ak`, `lu_nin`, `mt_id`, `pt_nif`, `ro_cnp`, `sk_bn`, `si_emso`, `tr_tc` | Primary ID per country added |
| Asia-Pacific — Australia | 11 patterns | `au_tfn`, `au_medicare`, `au_passport` | State DLs (8 formats) not yet added |
| Asia-Pacific — New Zealand | 4 patterns | `nz_ird` | NHI, DL not yet added |
| Asia-Pacific — Singapore | 4 patterns | `sg_nric` | FIN, DL not yet added |
| Asia-Pacific — Hong Kong | 1 pattern | `hk_hkid` | Full coverage |
| Asia-Pacific — Japan | 6 patterns | `jp_my_number` | Passport, DL, residence card not yet added |
| Asia-Pacific — India | 6 patterns | `in_aadhaar`, `in_pan` | Passport, DL, Voter ID not yet added |
| Asia-Pacific — (other 9 countries) | ~30 patterns | `bd_nid`, `id_nik`, `my_mykad`, `pk_cnic`, `ph_philsys`, `kr_rrn`, `lk_nic`, `th_nid`, `vn_cccd` | Primary ID per country added |
| Latin America — Brazil | 6 patterns | `br_cpf`, `br_cnpj` | CNH, RG, Passport not yet added |
| Latin America — Chile | 2 patterns | `cl_rut` | Passport not yet added |
| Latin America — Argentina | 3 patterns | `ar_dni` | CUIL/CUIT not yet added |
| Latin America — Mexico | 7 patterns | `mx_curp` | CURP covered; RFC, Clave Elector, NSS, INE not yet added |
| Latin America — (other 7 countries) | ~30 patterns | `co_cedula`, `cr_cedula`, `ec_cedula`, `py_ruc`, `pe_dni`, `uy_ci`, `ve_cedula` | Primary ID per country added |
| Middle East — UAE | 3 patterns | `uae_eid` | Visa number not yet added |
| Middle East — Saudi Arabia | 2 patterns | `sa_nid` | Passport not yet added |
| Middle East — Israel | 2 patterns | `il_id` | Passport not yet added |
| Middle East — (other 7 countries) | ~16 patterns | `bh_cpr`, `ir_melli`, `iq_nid`, `jo_nid`, `kw_civil`, `lb_pp`, `qa_qid` | Primary ID per country added |
| Africa — South Africa | 3 patterns | `za_id` | DL, Passport not yet added |
| Africa — (other 9 countries) | ~30 patterns | `eg_nid`, `et_passport`, `gh_card`, `ke_kra`, `ma_cin`, `ng_bvn`, `tz_nida`, `tn_cin`, `ug_nin` | Primary ID per country added |
| Banking & Financial | IBAN, SWIFT, ABA, bank accounts | `iban`, `swift_bic`, `aba_routing`, `ca_transit_number`, `ca_bank_account` | Full core coverage |
| Cryptocurrency | Bitcoin, Ethereum, others | `bitcoin`, `ethereum` | 5 other crypto types in dlpscan not yet added |
| Secrets & tokens | JWT, AWS, GitHub, Stripe, Slack | all 5 covered | heuristic; excluded from default scan |
| Functional / data governance | Session IDs, PAN tracks, MICR, financial amounts, ISIN, VIN, IMAD, and more | `session_id`, `pin_block`, `biometric_id`, `card_expiry`, `card_track`, `micr`, `financial_amount`, `date_iso`, `iccid`, `edu_email`, `employee_id`, `gps_coords`, `insurance_policy`, `bank_ref`, `legal_case`, `loan_number`, `ndc_code`, `dob`, `postal_code`, `masked_pan`, `parcel_number`, `aml_case_id`, `isin`, `twitter_handle`, `url_with_creds`, `vin`, `fedwire_imad` | All added |

**Summary:** evadex covers **126 of 126 dlpscan-rs categories** (100%) with 225 payloads across 165 categories. All structured identity and financial formats are covered; a small number of secondary formats per country (alternate DLs, passport variants) remain as future additions. Verified at 94.9% detection rate across 24,283 test cases — 0 categories below 80%.

---

## Security notes

- **API keys:** Prefer the `EVADEX_API_KEY` environment variable over the `--api-key` CLI flag. Command-line arguments are visible in process listings (`ps aux`) and may be saved in shell history.
- **Output files:** The JSON report's `raw_response` fields may contain scanner match objects that echo variant values (transformed versions of sensitive test data). Apply appropriate access controls to report files.
- **Temp files:** The `dlpscan-cli` adapter writes each test variant to a temp file for subprocess invocation and deletes it immediately after the scan. No persistent disk footprint from test data.
- **Network isolation:** Run evadex and the scanner on an isolated test network. Test variant values are obfuscated but structurally derived from real sensitive patterns.

---

## License

MIT — see [LICENSE](LICENSE).
