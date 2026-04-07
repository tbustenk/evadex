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

**Submission strategies** (for dlpscan-cli adapter):

Each variant is tested four ways by default: as plain text, embedded in a DOCX, embedded in a PDF, and embedded in an XLSX. This exercises your scanner's file extraction pipeline, not just its regex layer.

**Built-in test payloads:**

Payloads are classified as **structured** or **heuristic** — see [Structured vs heuristic categories](#structured-vs-heuristic-categories) below.

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
| Canada SIN | `046 454 286` | `sin` | structured |
| US Passport number | `340000136` | `us_passport` | structured |
| Australia TFN | `123 456 78` | `au_tfn` | structured |
| Germany Steuer-IdNr | `86095742719` | `de_tax_id` | structured |
| France INSEE (NIR) | `282097505604213` | `fr_insee` | structured |
| UK IBAN | `GB82WEST12345698765432` | `iban` | structured |
| Germany IBAN | `DE89370400440532013000` | `iban` | structured |
| France IBAN | `FR7630006000011234567890189` | `iban` | structured |
| Spain IBAN | `ES9121000418450200051332` | `iban` | structured |
| SWIFT/BIC code | `DEUTDEDB` | `swift_bic` | structured |
| ABA routing number | `021000021` | `aba_routing` | structured |
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

Heuristic payloads are excluded from the default scan. Use `--include-heuristic` to include them.

---

## Structured vs heuristic categories

evadex classifies its built-in payload categories into two groups:

**Structured** — formats with well-defined, mathematically or syntactically validatable patterns. DLP scanners typically enforce these patterns precisely (e.g., Luhn check on credit cards, fixed-length digit groups for SSN/SIN, checksum-verified IBAN). Evasion results in this group reflect meaningful signal: a variant that evades detection is a real gap in coverage.

Categories: `credit_card`, `ssn`, `sin`, `iban`, `swift_bic`, `aba_routing`, `bitcoin`, `ethereum`, `us_passport`, `au_tfn`, `de_tax_id`, `fr_insee`, `email`, `phone`

**Heuristic** — formats where detection relies on fixed prefixes, high-entropy pattern matching, or loosely defined structure. DLP rules for these categories vary widely between scanners and configurations, and a "fail" result may simply reflect that the scanner never had a strong rule for that specific format variant — not that a real exfiltration path was found.

Categories: `aws_key`, `jwt`, `github_token`, `stripe_key`, `slack_token`, `classification`

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
    "pass": 142,
    "fail": 448,
    "error": 0,
    "pass_rate": 24.1,
    "summary_by_category": {
      "credit_card": { "pass": 30, "fail": 90, "error": 0 },
      "ssn":         { "pass": 12, "fail": 60, "error": 0 },
      "iban":        { "pass": 10, "fail": 50, "error": 0 }
    },
    "summary_by_generator": {
      "delimiter":        { "pass": 20, "fail": 60, "error": 0 },
      "unicode_encoding": { "pass": 15, "fail": 75, "error": 0 }
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
| `--input`, `-i` | *(all built-ins)* | Single value to test. If omitted, runs all 23 structured built-in payloads (add `--include-heuristic` for all 30). Category is auto-detected (Luhn check, regex patterns for SSN/IBAN/AWS/JWT/email/phone). |
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

## Security notes

- **API keys:** Prefer the `EVADEX_API_KEY` environment variable over the `--api-key` CLI flag. Command-line arguments are visible in process listings (`ps aux`) and may be saved in shell history.
- **Output files:** The JSON report's `raw_response` fields may contain scanner match objects that echo variant values (transformed versions of sensitive test data). Apply appropriate access controls to report files.
- **Temp files:** The `dlpscan-cli` adapter writes each test variant to a temp file for subprocess invocation and deletes it immediately after the scan. No persistent disk footprint from test data.
- **Network isolation:** Run evadex and the scanner on an isolated test network. Test variant values are obfuscated but structurally derived from real sensitive patterns.

---

## License

MIT — see [LICENSE](LICENSE).
