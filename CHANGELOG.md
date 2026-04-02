# Changelog

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
