# evadex

A scanner-agnostic DLP evasion test suite. evadex generates hundreds of obfuscated variants of known-sensitive values and submits them to your DLP scanner to find what slips through — including through file extraction pipelines (DOCX, PDF, XLSX), not just plain-text API calls.

Built with [dlpscan](https://github.com/oxide11/dlpscan) as the default target, with a clean adapter interface for testing any DLP tool.

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

| Label | Value |
|---|---|
| Visa 16-digit | `4532015112830366` |
| Amex 15-digit | `378282246310005` |
| Mastercard 16-digit | `5105105105105100` |
| US SSN | `123-45-6789` |
| Canada SIN | `046 454 286` |
| UK IBAN | `GB82WEST12345698765432` |
| AWS Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| Sample JWT | *(compact JWT string)* |
| Email address | `test.user@example.com` |
| US phone number | `+1-555-867-5309` |

---

## Installation

Requires Python 3.10+.

```bash
pip install evadex
```

Or install from source:

```bash
git clone https://github.com/your-org/evadex
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
Done. 501 tests — 425 detected, 76 evaded
```

### JSON output (`--format json`, default)

```json
{
  "meta": {
    "timestamp": "2026-04-01T22:01:36.172424+00:00",
    "total": 501,
    "pass": 425,
    "fail": 76,
    "error": 0,
    "pass_rate": 84.8,
    "summary_by_category": {
      "credit_card": { "pass": 150, "fail": 9,  "error": 0 },
      "ssn":         { "pass": 51,  "fail": 2,  "error": 0 },
      "sin":         { "pass": 51,  "fail": 2,  "error": 0 },
      "iban":        { "pass": 49,  "fail": 6,  "error": 0 },
      "aws_key":     { "pass": 27,  "fail": 19, "error": 0 },
      "jwt":         { "pass": 25,  "fail": 22, "error": 0 },
      "email":       { "pass": 21,  "fail": 14, "error": 0 },
      "phone":       { "pass": 51,  "fail": 2,  "error": 0 }
    }
  },
  "results": [
    {
      "payload": {
        "value": "5105105105105100",
        "category": "credit_card",
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
| `--input`, `-i` | *(all built-ins)* | Single value to test. If omitted, runs all 10 built-in payloads. Category is auto-detected (Luhn check, regex patterns for SSN/IBAN/AWS/JWT/email/phone). |
| `--format`, `-f` | `json` | Output format: `json` or `html` |
| `--output`, `-o` | stdout | Write report to file instead of stdout |
| `--strategy` | all four | Submission strategy: `text`, `docx`, `pdf`, `xlsx`. Repeat the flag for multiple. Omit to run all four. |
| `--concurrency` | `5` | Max concurrent requests |
| `--timeout` | `30.0` | Request timeout in seconds |
| `--url` | `http://localhost:8080` | Base URL (for HTTP-based adapters) |
| `--api-key` | *(env: `EVADEX_API_KEY`)* | API key passed as `Authorization: Bearer` |
| `--category` | *(all)* | Filter built-in payloads by category. Repeat for multiple. Values: `credit_card`, `ssn`, `sin`, `iban`, `aws_key`, `jwt`, `email`, `phone` |
| `--variant-group` | *(all)* | Limit to specific generator(s). Repeat for multiple. Values: `unicode_encoding`, `delimiter`, `splitting`, `leetspeak`, `regional_digits`, `structural`, `encoding` |

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

Invokes the [dlpscan](https://github.com/oxide11/dlpscan) CLI directly as a subprocess. Requires `dlpscan` to be installed and on `PATH`.

```bash
evadex scan --tool dlpscan-cli
```

For file strategies, evadex builds the document in memory and writes it to a temp file, runs `dlpscan <file> -f json`, then deletes the temp file.

### Built-in: `dlpscan`

HTTP adapter for a dlpscan instance running as a REST API. Targets `POST /scan` (text) and `POST /scan/file` (multipart upload).

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
