# evadex

DLP quality assurance testing. Generate synthetic sensitive data, test your scanner, measure detection gaps.

---

## Install

```bash
pip install evadex
```

## Quick start

```bash
evadex quickstart
```

The wizard detects your environment, configures your scanner, and runs a first test. Saves config to `evadex.yaml` so subsequent runs just work.

---

## Core commands

```bash
evadex scan                          # test your scanner (banking tier, auto-detect scanner)
evadex scan --fast                   # top techniques only, ~4 min
evadex scan --tier full              # comprehensive test, all payloads

evadex generate                      # interactive: pick format, count, output
evadex generate --format xlsx        # 100-record spreadsheet
evadex generate --formats xlsx,docx,pdf --tier banking  # all formats at once

evadex falsepos                      # measure false positive rate (100 values)
evadex falsepos --count 500          # more thorough

evadex report results/scan.json      # generate HTML report
```

---

## Tiers

| Tier | Description |
|---|---|
| `banking` | Credit cards, SSN, SIN, IBAN, ABA routing — default |
| `core` | Banking + broader coverage |
| `regional` | Country-specific IDs, health cards, tax numbers |
| `full` | All 593 payloads across 502 categories |

---

## Formats

Generate test files in any of these formats:

```
xlsx · docx · pdf · csv · txt · json · xml · sql · log · eml
parquet · sqlite · zip · 7z · mbox · png · jpg
```

---

## Evasion techniques

evadex tests 13 technique families:

| Technique | Examples |
|---|---|
| `unicode_encoding` | Fullwidth digits, homoglyphs, zero-width chars, NFD normalization |
| `delimiter` | Space, hyphen, dot, tab, newline, mixed, doubled, none |
| `splitting` | Mid-value line break, HTML comment injection, JSON field split |
| `leetspeak` | Minimal, moderate, aggressive substitution tiers |
| `regional_digits` | Arabic-Indic, Devanagari, Bengali, Thai, and 6 more scripts |
| `encoding` | Base64, ROT13, double URL encoding, encoding chains |
| `context_injection` | Value in JSON record, XML element, SQL snippet |
| `bidirectional` | Unicode RLO/LRO/RLE control characters |
| `soft_hyphen` | U+00AD invisible separator at group boundaries |
| `morse_code` | Digits encoded as International Morse Code |

---

## Capital markets coverage

v3.24.0 adds securities identifiers and financial messaging references to the `banking` and `core` tiers:

| Category | Examples | Tier |
|---|---|---|
| `isin` | US0378331005 (Apple), CA7800871021 (RBC) | banking |
| `cusip_num` | 037833100 (Apple), 46625H100 (JPMorgan) | banking |
| `cins_num` | G0177J108 (UK-registered), F22797108 (French) | core |
| `sedol_num` | 2005973 (BP), 0540528 (HSBC) | core |
| `figi_num` | BBG000B9XRY4 (Apple), BBG000DMBXR2 (JPMorgan) | banking |
| `lei_num` | HWUPKR0MPOU8FGXBT394 (Apple), R0MUWSFPU8MPRO8K5P83 (BNP) | banking |
| `ticker_symbol` | AAPL, JPM, RY.TO, BRK.A | core |
| `reuters_ric` | AAPL.O, JPM.N, BP.L | core |
| `valor_num` | 3234936 (Apple/SIX), 1225514 (Nestlé) | core |
| `wkn_num` | 865985 (Apple/Frankfurt), 840400 (BMW) | core |
| `mt103_ref` | FT23148BTJK7LMNQ, PAYREF2024031401 | banking |
| `mifid_tx_id` | MIFID20230517ABC0000000012345678… | core |
| `chips_uid` | 0001JPMC | banking |
| `sepa_ref` | RF18539007547034 | banking |
| `fedwire_imad` | 20231015BNKUS33XXXX000123456789 | banking |

All securities identifiers include checksum-validated synthetic generators (CUSIP ANSI X9.6, SEDOL weighted mod-10, ISIN Luhn, FIGI Luhn, LEI ISO 17442 mod-97).

---

## Configuration

Run `evadex init` to create `evadex.yaml` in the current directory:

```yaml
tool: siphon-cli
exe: /path/to/siphon
tier: banking
concurrency: 32
```

CLI flags override config values. `evadex.yaml` is auto-discovered from the working directory.

---

## Analysis commands

```bash
evadex history                       # past scan and falsepos runs
evadex trend                         # ASCII chart of detection rate over time
evadex techniques --top 10           # techniques with highest bypass rate
evadex doctor                        # environment health check
evadex benchmark                     # measure generate/scan performance
```

## Advanced commands (Siphon-specific)

```bash
evadex entropy --url http://localhost:8080   # test entropy detection modes
evadex edm    --url http://localhost:8080   # test Exact Data Match engine
evadex lsh    --url http://localhost:8080   # test document-similarity detection
evadex bridge --port 9191                   # start HTTP API bridge
```

---

## Requirements

- Python 3.10+
- A DLP scanner (Siphon recommended, dlpscan-rs supported, any CLI scanner via adapter)

Optional extras:

```bash
pip install evadex[barcodes]      # PNG/JPG barcode generation (QR, Code128, EAN-13)
pip install evadex[data-formats]  # Parquet and SQLite output
pip install evadex[archives]      # 7z archive output
pip install evadex[bridge]        # HTTP API bridge (FastAPI)
```

---

## Full documentation

See [docs/REFERENCE.md](docs/REFERENCE.md) for the complete CLI reference:

- All flags and options for every command
- Payload coverage by region (593 payloads, 502 categories)
- Adapter configuration (Siphon, dlpscan-rs, Presidio)
- Profile system and scheduling
- Bridge/C2 integration
- Architecture overview
