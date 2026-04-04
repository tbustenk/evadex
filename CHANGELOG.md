# Changelog

## [2.3.0] — 2026-04-03

### Added

- **`encoding` generator — base32 variants** (4 new techniques): standard base32 (RFC 4648 §6, A–Z 2–7), no-padding, lowercase, and extended hex alphabet (RFC 4648 §7, 0–9 A–V). Targets scanners that decode base64 before scanning but not base32.
- **`encoding` generator — hex variants** (5 new techniques): lowercase hex (`34313131…`), uppercase hex, `\xNN` escaped bytes, single `0x`-prefixed integer, and space-separated hex dump. Covers common representations in log files and hex editors.
- **`soft_hyphen` generator** — 6 techniques using invisible Unicode separators at group boundaries and between every character: soft hyphen at 4-char boundaries (`shy_group_boundaries`), soft hyphen at 2-char boundaries (`shy_2char_boundaries`), soft hyphen between every character, word joiner (U+2060) at 4-char boundaries, word joiner between every character, and alternating soft hyphen / word joiner (`mixed_shy_wj`). Applies to structured numeric/secret categories. Targets scanners that pass invisible format characters through to regex matching without stripping them first.

### Tests

171 tests (up from 146). 25 new tests:

- `tests/unit/variants/test_encoding.py`: 11 new tests — base32 standard, no-padding, lowercase, hex alphabet, decodability; hex lowercase, uppercase, escaped bytes, 0x integer, spaced bytes; MIME linebreak boundary check
- `tests/unit/variants/test_soft_hyphen.py` (new): 15 tests — variant count, SHY group boundary structure and digit preservation, 2-char boundary grouping, SHY between every char, WJ group boundaries and every-char, mixed alternation, SSN with hyphens, generator name, applicable/non-applicable categories, unique technique names

## [2.2.0] — 2026-04-03

### Added

- **`context_injection` generator** — 10 techniques that embed the sensitive value inside realistic surrounding text: payment request sentences, email bodies, log lines, multiline form blocks, audit notes, XML records, and JSON transaction records. Tests whether scanners can detect values that appear in document context rather than in isolation. Applies to all payload categories.
- **`unicode_whitespace` generator** — 8 techniques (7 single-space variants + mixed) that use Unicode whitespace characters as group separators: non-breaking space (U+00A0), en-space (U+2002), em-space (U+2003), thin space (U+2009), figure space (U+2007), narrow no-break space (U+202F), and ideographic space (U+3000). Targets scanners whose regex patterns only match ASCII `\s` or specific ASCII delimiters. Applies to structured numeric/alphanumeric categories (credit card, SSN, SIN, IBAN, phone, ABA routing, passport, TFN, DE tax ID, FR INSEE).
- **`bidirectional` generator** — 6 techniques using Unicode bidirectional control characters: RTL override wrap (U+202E), LTR override wrap (U+202D), RTL embedding (U+202B), mid-value RTL override injection, RTL isolate (U+2067, Unicode 6.3+ bidi), and Arabic letter mark injection between every character (U+061C). Tests scanners that render or normalise text before pattern-matching — such scanners may see a reversed or reordered value. Scanners matching raw codepoints are unaffected, confirming correct behaviour. Applies to all payload categories.

### Tests

139 tests (up from 113). 26 new tests across three new test files:

- `tests/unit/variants/test_context_injection.py` — 9 tests: template count, value presence in all variants, generator name, newlines in email body, JSON record parseable, XML record structure, brace-safe value handling, no `applicable_categories` restriction, unique technique names
- `tests/unit/variants/test_unicode_whitespace.py` — 12 tests: NBSP/en-space/em-space/mixed variants, digit preservation, hyphen-separated SSN input, generator name, category membership (CC, SSN), non-membership (JWT, email), unique technique names
- `tests/unit/variants/test_bidirectional.py` — 11 tests: variant count, RLO/LRO/RLE wrap structure, mid-RLO split at midpoint, RLI isolate, ALM count and char preservation, generator name, no `applicable_categories` restriction, unique technique names

## [2.1.0] — 2026-04-03

### Added

- **`evadex compare`** — new command to diff two scan result JSON files. Reports overall delta, per-category delta, per-technique delta (changed techniques only), and a full list of every variant where detection status differs. Supports `--format json` and `--format html`. `--label-a`/`--label-b` override the scanner labels from the JSON `meta.scanner` field.
- **`--min-detection-rate`** (`evadex scan`) — CI/CD gate flag. If the final detection rate falls below the given threshold, exits with code 1 and a clear `FAIL:` message. Example: `evadex scan --tool dlpscan-cli --min-detection-rate 85`.
- **`--baseline`** (`evadex scan`) — saves the current run's JSON results to a reference file. Example: `evadex scan --baseline baseline.json`.
- **`--compare-baseline`** (`evadex scan`) — diffs the current run against a saved baseline and prints regressions (variants now evading that the baseline caught) and improvements (variants now caught that the baseline missed). Does not affect exit code; informational only.
- **`evadex list-payloads`** — lists all 30 built-in payloads in a Rich table showing label, value, category, and structured/heuristic type. Supports `--type structured` or `--type heuristic` to filter.
- **`evadex list-techniques`** — lists all registered generators and their techniques in per-generator Rich tables, showing technique name and human-readable description. Supports `--generator <name>` to filter to a single generator.
- **Live progress bar** (`evadex scan`) — Rich progress bar on stderr showing completed/total count, current payload label, elapsed time, and a spinner. Transient (disappears cleanly after the scan completes so it doesn't pollute piped output).
- **`Engine.on_result` callback** — the engine now accepts an optional `on_result(result, completed, total)` callback called after each test case completes. Used internally by the progress bar; available for custom integrations.

### Tests

113 tests (up from 88). 25 new tests across two new test files:

- `tests/integration/test_compare.py` — 12 tests covering `build_comparison` logic and the `compare` CLI command (JSON output, HTML output, label override, missing file)
- `tests/integration/test_new_features.py` — 13 tests covering `--min-detection-rate` (above/below/boundary), `--baseline` file creation, `--compare-baseline` regression/improvement detection, `list-payloads` (all, structured, heuristic), `list-techniques` (all, filtered, unknown generator), and `Engine.on_result` callback

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
