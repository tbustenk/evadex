# Changelog

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
