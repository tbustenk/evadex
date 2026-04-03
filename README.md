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

**Submission strategies** (for dlpscan-cli adapter):

Each variant is tested four ways by default: as plain text, embedded in a DOCX, embedded in a PDF, and embedded in an XLSX. This exercises your scanner's file extraction pipeline, not just its regex layer.

**Built-in test payloads:**

Payloads are classified as **structured** or **heuristic** — see [Structured vs heuristic categories](#structured-vs-heuristic-categories) below.

| Label | Value | Category type |
|---|---|---|
| Visa 16-digit | `4532015112830366` | structured |
| Amex 15-digit | `378282246310005` | structured |
| Mastercard 16-digit | `5105105105105100` | structured |
| US SSN | `123-45-6789` | structured |
| Canada SIN | `046 454 286` | structured |
| UK IBAN | `GB82WEST12345698765432` | structured |
| Email address | `test.user@example.com` | structured |
| US phone number | `+1-555-867-5309` | structured |
| AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` | heuristic |
| Sample JWT | *(compact JWT string)* | heuristic |

Heuristic payloads are excluded from the default scan. Use `--include-heuristic` to include them.

---

## Structured vs heuristic categories

evadex classifies its built-in payload categories into two groups:

**Structured** — formats with well-defined, mathematically or syntactically validatable patterns. DLP scanners typically enforce these patterns precisely (e.g., Luhn check on credit cards, fixed-length digit groups for SSN/SIN, checksum-verified IBAN). Evasion results in this group reflect meaningful signal: a variant that evades detection is a real gap in coverage.

Categories: `credit_card`, `ssn`, `sin`, `iban`, `email`, `phone`

**Heuristic** — formats where detection relies on fixed prefixes, high-entropy pattern matching, or loosely defined structure. DLP rules for these categories vary widely between scanners and configurations, and a "fail" result may simply reflect that the scanner never had a strong rule for that specific format variant — not that a real exfiltration path was found.

Categories: `aws_key`, `jwt`

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
    "total": 590,
    "pass": 0,
    "fail": 0,
    "error": 0,
    "pass_rate": 0.0,
    "summary_by_category": {
      "credit_card": { "pass": 0, "fail": 0, "error": 0 },
      "ssn":         { "pass": 0, "fail": 0, "error": 0 },
      "sin":         { "pass": 0, "fail": 0, "error": 0 },
      "iban":        { "pass": 0, "fail": 0, "error": 0 },
      "aws_key":     { "pass": 0, "fail": 0, "error": 0 },
      "jwt":         { "pass": 0, "fail": 0, "error": 0 },
      "email":       { "pass": 0, "fail": 0, "error": 0 },
      "phone":       { "pass": 0, "fail": 0, "error": 0 }
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
      "error": null
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
      "error": null
    }
  ]
}
```

**Severity values:**

| Value | Meaning |
|---|---|
| `pass` | Scanner detected the variant (good) |
| `fail` | Scanner missed the variant — evasion succeeded |
| `error` | Adapter error (network, timeout, etc.) |

---

## CLI reference

```
evadex scan [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--tool`, `-t` | `dlpscan-cli` | Adapter name to use |
| `--input`, `-i` | *(all built-ins)* | Single value to test. If omitted, runs all 8 structured built-in payloads (add `--include-heuristic` for all 10). Category is auto-detected (Luhn check, regex patterns for SSN/IBAN/AWS/JWT/email/phone). |
| `--format`, `-f` | `json` | Output format: `json` or `html` |
| `--output`, `-o` | stdout | Write report to file instead of stdout |
| `--strategy` | all four | Submission strategy: `text`, `docx`, `pdf`, `xlsx`. Repeat the flag for multiple. Omit to run all four. |
| `--concurrency` | `5` | Max concurrent requests |
| `--timeout` | `30.0` | Request timeout in seconds |
| `--url` | `http://localhost:8080` | Base URL (for HTTP-based adapters) |
| `--api-key` | *(env: `EVADEX_API_KEY`)* | API key passed as `Authorization: Bearer` |
| `--category` | *(all structured)* | Filter built-in payloads by category. Repeat for multiple. Values: `credit_card`, `ssn`, `sin`, `iban`, `aws_key`, `jwt`, `email`, `phone` |
| `--variant-group` | *(all)* | Limit to specific generator(s). Repeat for multiple. Values: `unicode_encoding`, `delimiter`, `splitting`, `leetspeak`, `regional_digits`, `structural`, `encoding` |
| `--include-heuristic` | off | Also run heuristic categories (`jwt`, `aws_key`). A warning is printed when enabled — see [Structured vs heuristic categories](#structured-vs-heuristic-categories). |

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
```

---

## Adapters

### Built-in: `dlpscan-cli`

Invokes the [dlpscan](https://github.com/oxide11/dlpscan) CLI directly as a subprocess. evadex was built and tested with dlpscan as the reference scanner. Requires `dlpscan` to be installed and on `PATH`.

```bash
evadex scan --tool dlpscan-cli
```

For file strategies, evadex builds the document in memory and writes it to a temp file, runs `dlpscan <file> -f json`, then deletes the temp file. File extraction support in dlpscan requires `pip install dlpscan[office]`.

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

**File strategies:** `variant.strategy` tells you which format evadex wants to use. If your scanner only supports one method, ignore strategies you don't need and handle the rest:

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
| `timestamp` | ISO 8601 string | When the scan ran |
| `total` | int | Total test cases run |
| `pass` | int | Variants detected by scanner |
| `fail` | int | Variants that evaded scanner |
| `error` | int | Adapter errors |
| `pass_rate` | float | `pass / total * 100` |
| `summary_by_category` | object | Per-category pass/fail/error counts |

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
| `detected` | bool | Whether the scanner flagged this variant |
| `severity` | string | `pass`, `fail`, or `error` |
| `duration_ms` | float | Time for this test case in milliseconds |
| `error` | string \| null | Error message if adapter threw |

---

## Publishing to PyPI

```bash
pip install build twine
python -m build
twine upload dist/*
```

Update the `[project.urls]` section in `pyproject.toml` with your real GitHub repository URL before publishing.

---

## License

MIT — see [LICENSE](LICENSE).
