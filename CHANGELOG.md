# Changelog

## [0.2.0] — 2026-04-03

### Reliability fixes

- **Normalization deduplication** (`unicode_encoding`): NFD/NFC/NFKC/NFKD variants are now skipped when the normalised form is identical to the input value. For pure ASCII payloads (all structured credit cards, SSNs, IBANs, etc.), all four forms are identical — previously this silently generated 4× redundant submissions per payload, inflating total counts and making coverage appear broader than it was. Only normalization variants that actually transform the value are now emitted.
- **`json_field_split` correctness** (`splitting`): variant value was built by string concatenation, producing invalid JSON for any input containing `"` or `\`. Changed to `json.dumps`.
- **`xml_tag_injection` correctness** (`splitting`): variant value was unescaped, producing malformed XML for inputs containing `<`, `>`, or `&`. Changed to `html.escape`.

### Error handling fixes

- **Temp-file cleanup** (`dlpscan-cli` adapter): `os.unlink` in the `finally` block of `_run_on_tempfile` now catches `OSError`. On Windows, antivirus software can briefly lock a temp file after the subprocess exits, causing `PermissionError` to propagate from the `finally` block and replace the actual scan result or error with a cleanup failure.
- **`_parse_response` fallthrough** (`dlpscan` adapter): if the configured `response_detected_key` was present in the scanner response but had an unrecognised type (`None`, a nested dict, etc.), the method silently fell through to the generic heuristic key block and could return the detection result from a *different* key. The configured key is now authoritative — if it is present, the method returns immediately regardless of value type. Also added `list` handling to the configured-key branch (was only in the fallback branch).
- **`summary_by_category` ordering** (`json_reporter`): category keys are now sorted alphabetically, giving deterministic JSON output across runs. Previously, key order depended on `asyncio.as_completed` completion order.

### Payload expansion

Built-in payloads expanded from 10 to 30:

- **Credit cards** (structured): added Discover, JCB, UnionPay, Diners Club (was Visa/Amex/Mastercard only)
- **National IDs** (structured): added US Passport, Australia TFN, Germany Steuer-IdNr, France INSEE/NIR
- **Banking** (structured): added Germany/France/Spain IBANs, SWIFT/BIC code, ABA routing number
- **Cryptocurrency** (structured): added Bitcoin legacy address, Ethereum address
- **Secrets** (heuristic): added GitHub classic token, Stripe test secret key, Slack bot token
- **Classification labels** (heuristic): added `TOP SECRET`, `HIPAA`

### Tests

88 tests (up from 64). 24 new tests:

- **`tests/unit/adapters/test_parse_response.py`** (new): 14 tests covering all `_parse_response` branches — bool/int/float/string/list/null values, configured-key precedence, fallthrough prevention, unrecognised-type handling, empty response
- **`tests/unit/reporters/test_json_reporter.py`**: added error counting, `scanner` label in meta, sorted `summary_by_category`, complete result-field presence assertion
- **`tests/integration/test_cli.py`**: all tests now mock `health_check` via `AsyncMock` — no longer require `dlpscan` to be installed in the test environment; added health-check failure exit, no-payloads exit, heuristic-category-without-flag guard, unknown-variant-group exit
- **`tests/unit/core/test_registry.py`**: added assertions for `dlpscan-cli` adapter and `encoding` generator registration

### Documentation

README overhauled for production / conference use:

- Payload table expanded to all 30 payloads with category name and structured/heuristic classification
- Structured category list: 6 → 14; heuristic category list: 2 → 6
- `--input` default description: "8 structured / 10 total" corrected to "23 structured / 30 total"
- CLI reference table: added `--scanner-label`, `--exe`, `--cmd-style`; `--category` values list expanded from 8 to 20; `--api-key` entry notes env-var preference for security
- JSON schema documentation: added `raw_response` field; added `scanner` field to `meta`; updated example with realistic non-zero counts
- Added Security notes section: API key exposure in process listings/shell history, output file sensitivity (`raw_response` may contain variant values), temp-file handling, network isolation recommendation
- Removed PyPI publishing placeholder note

## [0.1.4] — 2026-04-02

### Fixed
- Move inline imports to module top level in `engine.py`, `dlpscan_cli/adapter.py`, `encoding.py`, and `cli/commands/scan.py`

## [0.1.3] — 2026-04-02

### Fixed
- CLI summary line counted adapter errors as "evaded" — now shows detected / evaded / errors separately, errors only shown when non-zero

## [0.1.2] — 2026-04-01

### Fixed
- `regional_digits` generator missing `Variant` import — same `NameError` on Python 3.10–3.13 as fixed in 0.1.1 for other generators
- `encoding` generator double URL encoding used `ord(c)` — produced malformed `%1A7`-style sequences for non-ASCII characters; now encodes UTF-8 bytes correctly

## [0.1.1] — 2026-04-01

### Fixed
- `structural` and `splitting` generators missing `Variant` import — caused `NameError` on Python 3.10–3.13
- `DlpscanClient` lazy init dropped `Authorization` header when client was not pre-warmed
- `dlpscan-cli` adapter used deprecated `asyncio.get_event_loop()` — replaced with `get_running_loop()`
- `dlpscan-cli` adapter now raises `AdapterError` on malformed JSON from scanner instead of bare `JSONDecodeError`
- URL encoding generator produced malformed `%1A7`-style sequences for non-ASCII characters — now encodes UTF-8 bytes correctly

## [0.1.0] — 2026-04-01

Initial release.

### Added
- 7 evasion generators: `unicode_encoding`, `delimiter`, `splitting`, `leetspeak`, `regional_digits`, `structural`, `encoding`
- 10 built-in test payloads: Visa, Amex, Mastercard, US SSN, Canada SIN, UK IBAN, AWS access key, JWT, email, phone
- Auto-detection of payload category from value format (Luhn check, regex patterns)
- `dlpscan-cli` adapter — invokes [dlpscan](https://github.com/oxide11/dlpscan) as a subprocess, supports text and file strategies (DOCX, PDF, XLSX)
- `dlpscan` adapter — generic HTTP adapter for REST API-based DLP scanners
- JSON and HTML report formats
- `--strategy`, `--category`, `--variant-group`, `--concurrency` CLI flags
- 64 unit and integration tests
