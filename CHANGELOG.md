# Changelog

## [3.16.0] — 2026-04-20

### Added

- **HTTP bridge server** — new `evadex bridge` subcommand exposes evadex over HTTP so siphon-c2 (and any other frontend) can drive scans, generation, and metrics from the browser. Install via `pip install evadex[bridge]` (FastAPI + uvicorn).
  - `POST /v1/evadex/run` — trigger a scan in the background; accepts `profile`, `tier`, `evasion_mode`, `tool`, `exe`, `scanner_label`, `categories` (C2 coarse buckets or evadex fine categories, auto-expanded). Returns `run_id` immediately with `202 Accepted`. Run status pollable at `GET /v1/evadex/run/{run_id}`.
  - `GET /v1/evadex/metrics` — detection rate, FP rate, coverage, detection / FP trends, per-coarse-category TP/FN/FP/recall/precision breakdown, top-ranked evasion techniques, and last-10 run history. Aggregated from `results/audit.jsonl` + linked archive JSON files with no mutations to the underlying data.
  - `POST /v1/evadex/generate` — produces a synthetic test artefact and streams it back as `application/octet-stream`. Honours `format`, `tier`, `category` (C2 or evadex), `count`, `evasion_rate` (accepts 0–1 or 0–100), `language`, `template`.
  - `GET /healthz` — unauthenticated liveness probe.
- **C2 ↔ evadex category mapping** — `src/evadex/bridge/categories.py` maps the six C2 coarse buckets (`PCI`, `PII`, `PHI`, `CRED`, `SECRET`, `CRYPTO`) to evadex fine-grained `PayloadCategory` values and roll s back up the other way for metrics.
- **Bridge auth + CORS** — optional `x-api-key` (`--api-key` or `EVADEX_BRIDGE_KEY`) applied to every endpoint except `/healthz`; CORS allow-list via `--cors` / `EVADEX_BRIDGE_CORS_ORIGINS` (default `*`).

### Verified

- New test file `tests/unit/test_bridge.py` covers: metrics shape + values, C2 bucket roll-up, coverage computation, empty-audit fallback, `run` returns 202 + run_id, C2 categories expanded before launch, 404 for unknown run_id, `generate` file download, `evasion_rate` normalisation (0–100 → 0–1), 500 propagation on evadex failure, CORS headers, `x-api-key` enforcement, `/healthz` always open.

## [3.15.0] — 2026-04-20

### Added

- **Profiles** — named, saved evadex configurations under `~/.evadex/profiles/<name>.yaml` (override path with `EVADEX_PROFILES_DIR`). Each profile bundles scan flags, optional `falsepos`, `c2`, `schedule`, and `output` sections. Built-in profiles are shadowed by user copies with the same name.
  - New CLI group: `evadex profile create|list|show|run|edit|delete|export|import`.
  - `profile run` translates the profile into an `evadex scan` (and optionally `evadex falsepos`) subprocess invocation; multiple profiles can be chained in one command.
  - `--save-as NAME` on `evadex scan` captures the resolved flag set (including auto-enabled `wrap_context`) into a user profile before running.
  - Environment-variable substitution: `${VAR}` placeholders anywhere in string values are substituted at run time. `profile show` keeps them as literals unless `--expand-env` is passed.
- **Five built-in profiles** shipped under `evadex.profiles.builtins`: `banking-daily` (daily Canadian banking check with weighted evasion + FP pass), `pci-dss` (credit card / IBAN / SWIFT / ABA at 90% detection), `canadian-ids` (SIN, RAMQ, all provincial DL / health cards, CA passport), `full-evasion` (full tier, adversarial, all file strategies), `quick-check` (banking text-only sanity check, random evasion).
- **Scheduling** — new CLI group `evadex schedule add|list|remove|export|run-due`. evadex does not install into the system scheduler itself; instead `schedule export --format cron` emits a cron line and `--format windows-task` emits Task Scheduler XML. `schedule run-due` polls every profile and fires those whose cron matches the current minute (with a 5-minute reentry guard based on `last_run`).
- **C2 integration hook** — profiles with a `c2:` section automatically forward `--c2-url` / `--c2-key` to scan and falsepos, so scheduled runs push results to Siphon-C2 without repeating the flags.

### Verified

- `evadex profile run quick-check-local` end-to-end: 9021 variants, 3348 detected (37.11%), 0 errors against the live Siphon binary. Profile's `last_run` stamp updated after the run.
- 694 unit tests passing (no regressions); 86 new tests cover profile CRUD, built-in parity, runner argv assembly (value / boolean / multi-value flag shapes, env-var substitution, scan-to-falsepos config inheritance), cron parsing incl. Sunday-0/7 edge, `is_due` reentry guard, cron + Task Scheduler XML export, and Click wiring for every `profile` / `schedule` subcommand.

## [3.14.0] — 2026-04-20

### Added

- **New built-in adapter: `siphon-cli`** — subprocess wrapper around the [Polygon Siphon](https://github.com/oxide11/dlpscan) CLI (`siphon.exe` / `siphon`). Parallels `dlpscan-cli` but targets Siphon's command surface:
  - Text strategy pipes the variant value via stdin to `siphon scan-text --format json`.
  - File strategies write a mode-0600 temp file and run `siphon scan --format json <path>`, deleting the temp file on success or failure.
  - `--cmd-style binary` (default) runs the binary directly; `--cmd-style cargo` wraps the invocation in `cargo run --release --bin siphon -- …` for development builds.
  - Parses Siphon's match metadata into `ScanResult` enrichment fields: `confidence`, `sub_category`, and (for credit-card matches) `bin_brand`, `bin_card_type`, `bin_country`, `bin_issuer`.
- **Auto-wrap-context for `siphon-cli`** — `--wrap-context` is now enabled by default for the siphon-cli adapter, mirroring the behaviour already applied to `dlpscan-cli --cmd-style rust`. Siphon's rules require keyword context to fire, so bare-value submissions under-report detection. Disable with `--no-wrap-context`.
- **`bin_card_type`, `bin_issuer`, `sub_category` enrichment fields** on `ScanResult`, surfaced in the JSON output.

### Verified

- Live banking-tier run against Siphon (`target/release/siphon.exe`): 9021 variants, 3350 detected (37.14%), 0 errors, 612 results with BIN enrichment present.
- False-positive suite (8 categories × 100 values, `--wrap-context`): 362 / 800 flagged (45.2%). Per-category breakdown captured in `results/falsepos/siphon_live_fp.json`.
- 608 unit tests passing (no regressions); 17 new tests cover command assembly for every cmd-style, text/file response parsing, BIN-enrichment extraction, empty-response handling, and adapter config plumbing.

## [3.13.1] — 2026-04-19

### Fixed

- **Help-text rendering** — `≤ 50%%` was rendering literally as `50%%` instead of `50%` in `evadex scan` / `evadex generate` `--evasion-mode` help and the runtime status messages. Click does not re-substitute `%`; dropped the redundant escape.
- **Pre-existing dead imports** surfaced by the audit pass — `string` in `synthetic/email.py`, `Iterable` in `feedback/technique_history.py`, `PayloadCategory` (TYPE_CHECKING block) in `synthetic/registry.py`. Removed.
- **No-placeholder f-strings** in `cli/commands/scan.py` (3 sites) and `cli/commands/generate.py` (1 site) — converted to plain strings to silence pyflakes.

### Added

- **`evasion_mode` is now a recognised key in `evadex.yaml`** — added to `KNOWN_KEYS`, `EvadexConfig` dataclass, the `load_config` validator (rejects unknown values with a clear error), and the `evadex init` template (commented placeholder with description).

### Improved

- **`evadex techniques --category <name>` empty-result message** now explicitly explains that the flag is a substring match on the technique *name*, not the PII payload category, and points at `evadex list-techniques` for the available names. The flag's `--help` text was reworded to match.

### Verified

- All 6 v3.13.0 synthetic generators pass invariant checks at count = 1 000 (SSN no reserved areas; UK NIN prefix/suffix rules; CPF / Medicare / DE-tax checksums; US DL covers all 51 states).
- 591 unit tests passing (no regressions).

## [3.13.0] — 2026-04-19

### Added — synthetic generators

- **US SSN** (`PayloadCategory.SSN`) — `AAA-BB-CCCC` with reserved area / group / serial blocks excluded.
- **UK NIN** (`PayloadCategory.UK_NIN`) — HMRC-compliant `XX NNNNNN X` with disallowed prefixes (`BG`, `GB`, `NK`, `KN`, `NT`, `TN`, `ZZ`) and forbidden first / second-letter sets.
- **Brazilian CPF** (`PayloadCategory.BR_CPF`) — `NNN.NNN.NNN-DD` with the two-pass Receita Federal checksum; all-same-digit base values rejected.
- **Australian Medicare** (`PayloadCategory.AU_MEDICARE`) — `NNNN NNNNN N` with the Services Australia weighted check digit.
- **German Steuer-IdNr** (`PayloadCategory.DE_TAX_ID`) — 11-digit with ISO 7064 MOD 11,10 check digit and the exactly-twice duplicate-digit constraint.
- **US driver licences** (`PayloadCategory.US_DL`) — cycles through all 50 state + DC formats (shape only; most state DLs have no public checksum).
- All six generators expose `iter_generate(count, seed)` for streaming use; tests cover format conformance, checksum validity, and `count=10000` behaviour.

### Added — smart evasion selection

- **`technique_success_rates`** field on every audit-log entry (`audit.jsonl`) — `{technique: pass_rate}` captured at the end of each scan.
- **`summary_by_technique`** added to `evadex scan` JSON `meta` block, alongside the existing per-category and per-generator summaries.
- **New `evadex techniques` command** — Rich table of latest / average / trend per technique. Filters: `--last`, `--top`, `--category`, `--min-runs`. Cold-start prints a hint and exits cleanly.
- **`--evasion-mode {random,weighted,adversarial,exhaustive}`** flag added to both `evadex scan` and `evadex generate`. `weighted` biases by historical evasion success; `adversarial` restricts to techniques the scanner has been catching ≤ 50 % of the time. Cold-start falls back to random with a stderr warning.

### Performance / fixed

- **SQLite writer 10k memory hang** — pre-3.13.0 the `customers` table was built in Python before insert; `--count 10000` pushed peak RSS over 500 MB and aborted in our safety harness. Now uses 1 000-row chunked `executemany`. New peak: 309 MB at 10 k.
- **Documented per-format `--count` ceilings** in the README based on measured peak RSS (CSV / SQLite linear; XLSX in-memory; PDF / DOCX recommended ≤ 2 000).

### Verified

- Concurrency sweep: `--concurrency 10 → 17.8 var/s`, `20 → 18.9`, `50 → 20.6` against the dlpscan binary on Windows. Sweet spot: 20–50 (process-spawn overhead dominates).
- 591 unit tests passing (554 + 37 new for synthetic generators and evasion-mode).

## [3.12.1] — 2026-04-19

### Fixed

- **Barcode writer (`png` / `jpg`) now encodes contextual text instead of bare values.** Empirical end-to-end test against `siphon @ 22f7971` showed Siphon's CC pattern firing on a single bare 16-digit string but failing on three newline-separated bare strings — the exact output rxing produces from a multi-QR PNG. Encoding `entry.embedded_text` (which carries the keyword sentence around the value) instead of `entry.variant_value` lifted PNG detection from `0 → 12` matches and JPG from `0 → 11` for a banking-tier `--count 5 --evasion-rate 0.0` fixture. EAN-13 still encodes the bare value because the symbology can only carry 12 numeric digits — context wouldn't survive the encode anyway.
- This brings the plain-PNG/JPG path in line with `multi_barcode_png`, which was already encoding `embedded_text or variant_value`.

### Verified

- End-to-end format detection matrix added — every new format from v3.4.0 onwards generated and submitted to a live `siphon scan`. 12 / 15 formats detect as expected. Three known issues, all on Siphon's side:
  - **`zip` / `zip_nested`** — Siphon's plain-ZIP extractor only walks `*.xml` entries (see prior reports). Generator output is structurally correct; no evadex change.
  - **`parquet`** — Siphon's `extract_parquet` hangs on any Parquet input (timed out at 5 min on a 1 KB single-row file). Generator output validates against pyarrow.

## [3.12.0] — 2026-04-19

### Added

- **New archive and message-format generators** for `evadex generate`:
  - `zip` — multi-file ZIP archive with banking-domain inner filenames (`customer_data.csv`, `transactions_q1.csv`, `audit_log.txt`, `config.json`, …) plus a `manifest.xml`. Stdlib only.
  - `zip_nested` — ZIP-inside-ZIP-inside-ZIP, three levels deep, with sensitive payloads only in the innermost archive. Tests recursive-archive extraction (which Siphon does not currently perform).
  - `7z` — 7-Zip / LZMA2 archive with the same inner-file structure as `zip`. *Requires `pip install evadex[archives]`* (py7zr).
  - `mbox` — Unix mailbox with one realistic email per entry. ~1 in 3 messages uses base64 transfer encoding so Siphon's mbox decode path is exercised.
  - `ics` — RFC 5545 iCalendar with one VEVENT per entry, payload in `SUMMARY` / `DESCRIPTION` / `ATTENDEE`. CRLF + 75-octet line-folded.
  - `warc` — WARC 1.1 web archive with one HTTP `response` record per entry (synthetic banking-portal HTML bodies).
- **`archive_evasion` variant generator** — four container-level techniques (`archive_password`, `archive_double_extension`, `archive_deep_nest`, `archive_mixed_formats`). `auto_applicable=False` so its archive-only markers don't leak into random text-pipeline selection; opt in via `--technique-group archive_evasion`.
- **`evadex[archives]` optional dependency group** — adds `py7zr` for 7z generation. ZIP / mbox / ics / warc all use stdlib only.
- **GitHub Actions workflows for Siphon** at `docs/github-actions/`:
  - `evadex-regression.yml` — runs on every push to main and every PR. Builds Siphon, starts the API, runs banking-tier scan + false-positive suite, optionally diffs against a committed `evadex_baseline.json`, posts a per-category breakdown back to the PR.
  - `evadex-daily.yml` — cron-driven daily run with full banking-tier scan + false-positive suite, Slack notification when `SLACK_WEBHOOK` is set, fails on detection drop below 85 %.
- **README "GitHub Actions workflows" subsection** under CI/CD integration with install / baseline / threshold-tuning instructions.

### Fixed

- `evadex generate --formats` previously appended the literal logical format name as the file extension, producing nonsense extensions like `.sqlite` (should be `.db`), `.multi_barcode_png` (should be `.png`), and `.zip_nested` (should be `.zip`). New `_FORMAT_EXTENSION` mapping resolves these to the conventional on-disk extension.

## [3.11.0] — 2026-04-19

### Added

- **`evadex lsh` command** — exercises Siphon's document-similarity (LSH) engine end to end. Generates a base banking-domain document (loan decision / incident report / compliance finding), registers it with Siphon, then submits six near-duplicate variants at decreasing similarity levels (~83 %, ~53 %, ~35 %, ~25 %, ~8 % empirical Jaccard) and reports the minimum similarity Siphon reliably detects. Two transports: `--transport http` (live API server) and `--transport cli` (shells out to `siphon lsh register|query` against a fresh state file).
- **`evadex.lsh` module** — Siphon-compatible 3-word shingling, exact Jaccard helper, and a deterministic near-duplicate generator that preserves sensitive tokens (digits, structured codes) under distortion. Mirrors the algorithm in `crates/siphon-core/src/lsh.rs` so empirical similarity matches what Siphon's MinHash should asymptotically estimate.
- **`lsh_variants` document template** for `evadex generate` — produces a single document containing N labelled near-duplicate sections of a base banking memo, each splittable on `--- VARIANT N ---` for offline LSH testing or human inspection.

### Fixed

- **`evadex generate --format sql`** schema bug. The `customers` table declared only `sensitive_val` but every INSERT used a category-specific column name (`card_number`, `routing_number`, `sin`, …), so the resulting SQL failed to load into any strict-mode SQL engine. Schema now declares all 11 category columns up-front; fixture loads cleanly into SQLite with 1 400 rows preserved across categories.

## [3.10.1] — 2026-04-19

### Fixed

- **Dead code removed in new modules** (3.4.0–3.10.0): unused imports in `siphon/adapter.py`, `cli/commands/entropy.py`, `cli/commands/edm.py`, `reporters/c2_reporter.py`, `generate/writers/docx_writer.py`, `generate/writers/parquet_writer.py`, `generate/writers/sqlite_writer.py`. Removed nine f-strings in `generate/templates.py` that had no placeholders.
- **`evadex generate` missing-dependency errors** were leaking raw `RuntimeError` tracebacks. The CLI now catches and prints the friendly install hint (`pip install evadex[barcodes]` or `evadex[data-formats]`) on a single red line and exits 1.
- **`evadex edm` connection errors** to a down Siphon instance showed a raw `WinError 10061`. Now prints "Could not reach Siphon at <url>. Is the scanner running?" Also added explicit handling for HTTP 404 ("Siphon's EDM API is not available — check that EDM is enabled").
- **`evadex edm` 50,000-hash warning** now also prints *before* registration starts (in addition to after), so operators can abort with Ctrl-C.
- **Inaccurate help text**: `evadex entropy` description said "three entropy scan modes" but `--mode` accepts four (`gated|assignment|all|off`). Updated docstring and the matching README section.
- **`evadex init` template**: added the missing `wrap_context` config key (previously documented in the README but absent from the generated `evadex.yaml`).

### Documentation

- CHANGELOG entries reconstructed for v3.4.0 → v3.10.0 (the file had stopped at 3.3.1).

## [3.10.0] — 2026-04-18

### Added

- **`evadex generate --format parquet`** — flat customer/banking schema (`customer_id`, `name`, `email`, `phone`, `sin`, `card_number`, `iban`, `swift_bic`, `aba_routing`, `aws_key`, `jwt`, `notes`). Snappy-compressed, 1000-row row groups so multi-group readers get exercised. Sensitive payloads route to their category column; remaining columns are filled with realistic fake data. Gated behind `pip install evadex[data-formats]` (pyarrow).
- **`evadex generate --format sqlite`** — three-table banking schema (`customers`, `transactions`, `accounts`). Uses Python stdlib `sqlite3` only — no extra install on evadex's side. Categories route to the table that owns them; unmapped categories land in `customers.notes` so nothing is dropped.
- **`--language fr-CA`** support for both formats — French column/table names (`nom`, `courriel`, `telephone`, `numero_assurance_sociale`, `numero_carte`, `clients`, `transactions`, `comptes`) and French addresses (Montréal, Québec, Laval, …).
- Shared realistic-data filler module (`_data_filler.py`) so both writers use the same name/address/date generators.
- New optional install group: `evadex[data-formats]` (pyarrow). Clear `RuntimeError` raised with install hint when missing.

### Notes

Pair with a scanner built with data-format extractors (e.g. Siphon compiled with `--features data-formats`, which reads the first 10,000 rows of Parquet and up to 5,000 rows per SQLite table).

## [3.9.0] — 2026-04-18

### Added

- **`evadex edm` command** — exercises Siphon's Exact Data Match engine end to end: register built-in payloads under an evadex-scoped category namespace (`evadex_test_<category>`), verify every registered value is detected when resubmitted, then probe which transforms Siphon's normaliser absorbs vs which defeat it. Supports register / verify / evasion / corpus / dry-run modes. Pushes results to Siphon-C2 via `--c2-url` when configured.
- **EDM corpus generator** in two shapes — built into the command (`--generate-corpus` with `json|csv`) and as a full writer format (`evadex generate --format edm_json`) that matches the shape of Siphon's `POST /v1/edm/register` request body.
- **Evasion probe transforms** covering Siphon's normaliser surface: `exact`, `uppercase`, `lowercase`, `dashes`, `spaces`, `dots`, `slashes`, `nbsp_spaces`, `homoglyph_0`, `homoglyph_o`, `zero_width`. Reports `absorbed` / `partial` / `defeats` per transform.
- Warns at Siphon's constant-time-scan threshold of 50,000 hashes (`MAX_CONSTANT_TIME_HASHES` in siphon-core) so operators notice before the server does.

### Notes

Siphon exposes no delete endpoint — true cleanup requires restarting the server or clearing `DLPSCAN_EDM_STATE`. The `evadex_test_` prefix keeps stray hashes clearly identifiable.

## [3.8.0] — 2026-04-18

### Added

- **Siphon-C2 integration** — push scan, false-positive, comparison, and history reports into the Siphon-C2 management plane so detection quality appears on the admin dashboard alongside operational metrics.
- New `src/evadex/reporters/c2_reporter.py` with typed helpers for each report shape (scan / falsepos / compare / history). Auth matches Siphon's core HTTP API: `x-api-key` header.
- `--c2-url` / `--c2-key` flags added to `scan`, `falsepos`, `compare`, `history` (with `EVADEX_C2_URL` / `EVADEX_C2_KEY` env fallback).
- `c2_url` / `c2_key` keys added to `evadex.yaml`.
- `evadex history --push-c2` batches every audit-log entry to `/v1/evadex/history` — useful for backfilling a fresh C2.

### Endpoints

- `POST /v1/evadex/scan` — counts, pass rate, per-cat / per-tech, top 50 failing variants
- `POST /v1/evadex/falsepos` — per-category FP rate plus flagged values
- `POST /v1/evadex/compare` — comparison dict with delta + diffs
- `POST /v1/evadex/history` — batched audit entries (backfill)

### Reliability

Every push swallows errors to a single stderr warning line and returns cleanly. Scan exit codes, `--min-detection-rate` gating, and on-disk outputs are unaffected by C2 reachability — per the "C2 is not critical path" architecture contract.

## [3.7.0] — 2026-04-18

### Added

- **Barcode / QR image generation** — new `--format` values `png`, `jpg`, `multi_barcode_png` produce grid-layout images with quiet zones and human-readable labels, capped at 60 codes/image to stay safe under PIL's decompression-bomb guard and Siphon's 100-codes/image decode cap.
- **`--barcode-type`** flag: `qr` (default, 4296-char capacity), `code128`, `ean13` (zero-padded), `pdf417` (via optional `pdf417gen`), `datamatrix` (via optional `pylibdmtx`), or `random`.
- **`barcode_evasion` generator** with split / noise / rotate / embed-in-document techniques. Opt-in via `--technique-group barcode_evasion` so its image-only markers don't leak into text pipelines.
- New `auto_applicable` class attribute on `BaseVariantGenerator` so out-of-band evasions can register without skewing random variant selection. `_pick_variant` now stable-sorts generators by name so seeded runs stay reproducible regardless of module import order.
- New optional install group: `evadex[barcodes]` (`qrcode[pil]`, `python-barcode[images]`, `Pillow`). Friendly `RuntimeError` raised if extras are missing.

### Notes

Targets scanners with image barcode extractors (Siphon's `extract_barcode`, which decodes via rxing — QR, Data Matrix, Aztec, PDF417, UPC, EAN, Code 39/128, ITF, Codabar).

## [3.6.0] — 2026-04-18

### Added

- **`evadex entropy` command** — submits every entropy payload in three contexts (bare / gated / assignment) and reports per-context detection plus per-mode coverage. Validates Siphon's high-entropy token detection without a live production setup.
- Six new heuristic payload categories for entropy testing: `random_api_key`, `random_token`, `random_secret`, `encoded_credential`, `assignment_secret`, `gated_secret`. All gated out of the default tier.
- **`entropy_evasion` generator** — six techniques tuned to Siphon's token rules (16-char floor, 4.5 bits/char threshold, whitespace and `,;'"()[]{}=:` delimiters): `split`, `comment`, `concat`, `low_mix`, `encode`, `space`.
- Three new `generate` templates focused on entropy shapes: `env_file` (`KEY=VALUE`), `secrets_file` (YAML keyword-value), `code_with_secrets` (bare function-call literals).
- Entropy false-positive generator: UUIDs, empty-string hashes, common-text base64, char-run repetitions — any detection here is a real FP.

### Documented gap

Siphon's entropy mode cannot catch pure-hex secrets because `log2(16) = 4.0 < 4.5` bits/char threshold. Documented in the README so operators know to layer pattern-based detection on top.

## [3.5.0] — 2026-04-18

### Added

- **`siphon` adapter** — first-class HTTP-API adapter for dlpscan-rs / Siphon, removing the CLI subprocess dependency so evadex runs in production environments where only the Siphon service is reachable.
- `POST /v1/scan` for text. Adapter extras: `presets`, `categories`, `min_confidence`, `require_context` are forwarded as request body fields. DOCX/XLSX extracted client-side and routed through the same endpoint since Siphon's API is text-only.
- `x-api-key` auth via `--api-key` / `EVADEX_API_KEY`.
- Clear errors for 401 / 403 / 429 / 5xx instead of opaque HTTP failures.
- `ScanResult` gains optional `confidence`, `bin_brand`, `bin_country`, `entropy_classification`, `validator` fields. Emitted in JSON output only when Siphon supplies them.

### Changed

- `evadex compare` now surfaces confidence-score deltas between two runs even when severity is unchanged (`>= 0.01` threshold).

## [3.4.1] — 2026-04-18

### Fixed

- **JSON / SQL / XML writers**: `context_injection` variants now place the plain value in the structured field (`card_number`, `iban`, etc.) instead of the full sentence. Sentences go in a notes field instead, matching how DLP scanners parse structured documents.
- **Filler templates**: added 23 missing dlpscan-rs context keywords across 21 categories (`credit_card`, `sin`, `iban`, `swift_bic`, `aba_routing`, …) so generated documents trigger detection in `--require-context` mode. Alignment: 23/23 categories now fully matched.

### Tests

454 unit tests, 66 integration tests — all passing.

## [3.4.0] — 2026-04-18

### Added

- **New file formats**: `eml` (RFC 2822 email), `msg` (Outlook), `json` (structured records), `xml` (ISO 20022 pain.001 payment messages), `sql` (database dump with `CREATE TABLE` / `INSERT INTO`), `log` (mixed plaintext / structured / JSON application logs).
- **Granular amount control**: `--count-per-category` (per-category overrides), `--total` (exact record budget distributed evenly), `--density` (`low` / `medium` / `high` — frequency of sensitive values in filler text).
- **Granular evasion control**: `--technique-group` (limit to a generator family), `--technique-mix` (exact proportion per group, must sum to 1.0), `--evasion-per-category` (per-category evasion rate overrides).
- **Document templates** via `--template`: `invoice`, `statement`, `hr_record`, `audit_report`, `source_code`, `config_file`, `chat_log`, `medical_record`. Each template controls overall document structure and tone.
- **`--noise-level`** (`low` / `medium` / `high`) — ratio of filler text to sensitive values.

### Tests

36 new integration tests, 0 regressions on the existing 30.

## [3.3.1] — 2026-04-14

### Fixed

- **Dead code removed in `scan.py`**: the branch `if effective_tier != (tier or "banking"): pass` was always `False` (because `effective_tier` is assigned as `tier or "banking"`) — removed entirely.
- **`has_keywords` field inconsistency in `generator.py`**: `GeneratedEntry.has_keywords` was computed by calling `rng.random()` a second time, independent of the decision that determined `embedded_text`. This meant `has_keywords` could disagree with the actual embedded text content and consumed an extra RNG step that shifted reproducibility for subsequent entries. Now a single decision flag `kw` drives both fields.
- **`run_async` return type annotation**: corrected from `AsyncIterator[ScanResult]` to `AsyncGenerator[ScanResult, None]` — `async def` with `yield` is an `AsyncGenerator`, not an `AsyncIterator` (the former is a subtype of the latter but the annotation was imprecise).
- **README `--input` description updated**: the CLI reference table entry for `--input` still described the old "all built-ins" default behaviour. Updated to reflect the 3.3.0 banking tier default.
- **Editable install now required after 3.3.0**: the package was previously installed as a flat copy in `site-packages`. After 3.3.0 source edits, the CLI resolved to the stale installed copy (showing `--concurrency [default: 5]` from the old build). The correct install command is `pip install -e .` from the repo root.

### Tests

454 unit tests — no change in test count; all pass.

## [3.3.0] — 2026-04-14

### Added

- **Banking default tier** (`--tier` flag on `evadex scan` and `evadex generate`): the default scan now runs the **banking tier** (~80 payloads) instead of all structured built-ins. Four tiers are available:
  | Tier | Payloads | Est. runtime (text) | When to use |
  |---|---|---|---|
  | `banking` *(default)* | ~80 Canadian banking focused | ~5 min | Daily checks, RBC production testing |
  | `core` | ~150 broader PII and financial | ~10 min | Weekly benchmarks |
  | `regional` | ~350 international coverage | ~20 min | Pre-release validation |
  | `full` | All 554 payloads | ~30–40 min | Major releases, compliance audits |
  Explicit `--category` always overrides `--tier`. Config key `tier` supported in `evadex.yaml`.
- **`--formats` batch flag on `evadex generate`**: generate multiple file formats in a single pass. Output is a path stem; extensions are appended automatically. Example: `--formats xlsx,docx,pdf --output reports/banking` → `banking.xlsx`, `banking.docx`, `banking.pdf`.
- **`--tier` flag on `evadex generate`**: select the payload tier for generated test documents, matching `evadex scan` tier semantics.
- **`src/evadex/payloads/tiers.py`** (new module): `BANKING_TIER`, `CORE_TIER`, `REGIONAL_TIER` as composable `frozenset[PayloadCategory]` sets; `FULL_TIER = None` as sentinel for no-filter; `get_tier_categories(tier)` lookup function; `VALID_TIERS` constant.

### Changed

- **`--concurrency` default raised from 5 to 20**: the previous default (5) was conservative to the point of leaving most hardware underutilised. Benchmarks show 20 concurrent subprocess calls is the practical ceiling for `asyncio.create_subprocess_exec` on Windows before OS process-creation becomes the bottleneck. A higher value (50) gives negligible additional speedup (~1 s) on the same hardware.
- **`dlpscan-cli` adapter now uses `asyncio.create_subprocess_exec`** instead of `subprocess.run` offloaded to a thread-pool executor. All blocking subprocess calls — health check, text scan, file scan — are now truly non-blocking. This removes the artificial serialisation imposed by `run_in_executor` and lets the concurrency semaphore gate actual I/O rather than thread slots.
- **Engine streaming**: tasks are now created and drained progressively as variants are generated (`asyncio.create_task` + polling for `.done()` tasks in the generation loop) rather than collecting all tasks upfront. The first results appear faster and the progress bar starts updating as soon as the first subprocess returns.
- **`DEFAULT_CONFIG_YAML` concurrency** updated from `5` to `20`; `tier` added as a commented example line; `categories` changed to commented examples.

### Tests

454 unit tests (up from 540 total in 3.0.2; unit subset re-baselined after suite refactor).

## [3.0.2] — 2026-04-13

### Fixed

- **README intro stat corrected**: opening paragraph stated "482/557 sub-patterns (87%)" — updated to "489/557 sub-patterns (88%)" and "414 structured" → "421 structured" to match the accurate Coverage section summary added in 3.0.0.
- **CLI reference tables completed**: `--require-context` was missing from the `evadex scan` flag table; `--require-context` and `--wrap-context` were both missing from the `evadex falsepos` flag table. All three rows are now present with accurate descriptions.
- **`require_context` added to `evadex.yaml` config**: `require_context` can now be set in `evadex.yaml` (`require_context: true/false`). The `evadex init` template includes it as a commented-out example. Previously the flag was CLI-only with no config-file equivalent.
- **Encoding chain fix suggestions made specific**: `rot13_of_base64` and `url_of_base64` were falling through to the generic `"Investigate the technique"` fallback in the feedback report. Added concrete decode-chain instructions with code examples for all seven `encoding_chains` generator techniques.

### Tests

540 tests (up from 535). Added unit tests for `require_context` config loading and an integration test for config-to-adapter propagation.

## [3.0.1] — 2026-04-13

### Added

- **`--require-context` flag** for both `evadex scan` and `evadex falsepos`: passes `--require-context` to dlpscan-rs (a top-level option before the `scan` subcommand), instructing the scanner to only flag matches when surrounding category keywords are present. Requires `--cmd-style rust`.
- **`--wrap-context` flag** for `evadex falsepos`: embeds each generated invalid value in a realistic category-specific keyword sentence before submission, simulating how sensitive data actually appears in production documents. Use together with `--require-context` for the most realistic false positive measurement.
- **False positive report `mode` field**: the JSON report produced by `evadex falsepos` now includes `require_context`, `wrap_context`, and `mode` fields so runs can be compared programmatically.
- **`CONTEXT_WRAP_TEMPLATES` and `wrap_with_context()`** in `evadex.falsepos.generators`: per-category sentence templates for context wrapping, exported for use in custom scripts.
- **README section: "False positive rate and the `--require-context` tradeoff"**: full three-way comparison table (baseline, +require-context, +wrap-context+require-context), per-technique detection rate impact, and compliance recommendations. See [False Positive Rate](#false-positive-rate-and-the---require-context-tradeoff).

### Findings (dlpscan-rs, 100 values/category, 7 categories)

| Condition | Overall FP rate | Overall detection rate |
|---|---|---|
| Baseline | 99.1% | 94.1% |
| `--require-context` | 99.6% | 94.0% (−0.1 pp) |
| `--wrap-context` + `--require-context` | 100.0% | — |

`--require-context` does not meaningfully reduce false positives on structurally-similar invalid values (FP remains ~99%). It does reduce detection of obfuscated forms: morse code (−9.6 pp) and encoding chains (−6.6 pp) are most affected.

## [3.0.0] — 2026-04-13

### Quality / correctness

- **Manitoba driver's licence seed payload corrected**: value was `BOUDIN123456` (6 letters + 6 digits — invalid format); corrected to `AB-123-456-789` (2 letters + dashes + 9 digits), matching the synthetic generator and the documented `LL-NNN-NNN-NNN` format.
- **Nova Scotia driver's licence seed payload corrected**: value was `SMITH123456789` (5 letters + 9 digits — invalid format); corrected to `AB1234567` (2 letters + 7 digits), matching the `NSDriversSyntheticGenerator` output format.
- **Quebec driver's licence format test fixed**: regex was `^[A-Z]\d{14}$` (off by 2); corrected to `^[A-Z]\d{12}$` to match the actual 1-letter + 12-digit Quebec DL format.
- **Nova Scotia DL synthetic generator docstring fixed**: module-level comment said `LL-NNNNNNN` (with dash); corrected to `LLNNNNNNN` to match actual generator output (no dash).
- **Stale `list-payloads` count assertions updated**: after payload expansion the structured count grew from 47 → 485 and the heuristic count from 7 → 69; all three test assertions now match real output.
- **`test_list_payloads_shows_all` count made exact**: assertion `"54 payload"` was accidentally passing as a substring of `"554 payload(s)"`; updated to `"554 payload"` so the test is meaningful.

### Coverage

- 554 payloads (up from 547), 489 distinct categories (up from 482).

### Tests

535 tests (up from 530). No new test files — all additions are fixes to existing assertions.

## [2.6.2] — 2026-04-07

### Added

- **Key Findings section in scan summary**: after the technique breakdown table, evadex now prints a plain-English synthesis of the scan results. Up to five findings are generated:
  1. **Top bypass technique** — the generator with the highest bypass rate and a severity-adjusted label ("consistently evades" ≥80%, "shows highest bypass rate" otherwise)
  2. **Cross-category impact** — a second generator that bypasses ≥30% of tests across at least half the payload categories tested (omitted if no generator qualifies)
  3. **Most exposed payload category** — the category with the highest bypass rate, when ≥40%
  4. **File vs text strategy gap** — when multiple strategies were tested and the gap between file extraction and plain-text bypass rates is ≥5 percentage points
  5. **Zero-bypass technique classes** — generators that evaded no tests (up to four; suppressed when too many qualify to be informative)
  - When all variants are detected: prints a single positive finding instead
  - Colour-coded: red for high-severity bypass patterns, yellow for moderate, green for strengths

### Fixed

- **`→` (U+2192) in Top Bypass Categories caused `UnicodeEncodeError` on Windows cp1252 terminals**: replaced with `—` (em dash, present in cp1252).

### Tests

267 tests (up from 257). 10 new tests in `tests/unit/test_key_findings.py`:

- `test_no_results_produces_no_output`
- `test_all_detected_reports_clean`
- `test_highest_bypass_generator_named`
- `test_bypass_rate_shown_in_finding`
- `test_file_strategy_gap_reported_when_significant`
- `test_no_strategy_finding_when_text_only`
- `test_zero_bypass_generator_reported`
- `test_zero_bypass_not_reported_when_too_many`
- `test_unknown_generator_uses_raw_name`
- `test_all_known_generators_have_labels`

## [2.6.1] — 2026-04-07

### Fixed

- **Version number corrected in `pyproject.toml`**: was still `"2.5.0"` after the 2.6.0 release; every audit log entry written since 2.6.0 was published recorded `evadex_version: "2.5.0"` instead of the correct version. Corrected to `"2.6.0"`.
- **`test_silently_ignores_bad_path` made reliable cross-platform**: the old test wrote to `/proc/evadex_audit.jsonl` and assumed it would fail on all OSes. On Windows `/proc` does not exist as a filesystem restriction in the same way, making the test depend on platform-specific behaviour. Replaced with a `monkeypatch` that injects a `PermissionError` directly into `builtins.open` — the failure is guaranteed and platform-independent.
- **Lockfiles regenerated** after version bump: `requirements.txt` and `requirements-dev.txt` updated to reflect `evadex==2.6.0`.

### Tests

257 tests (up from 254). 3 new tests in `tests/unit/test_config.py`:

- `test_audit_log_string_is_accepted` — valid path string loads correctly
- `test_audit_log_null_is_accepted` — explicit null loads as None
- `test_audit_log_wrong_type_raises` — integer value raises UsageError

## [2.6.0] — 2026-04-07

### Added

- **Audit log** (`--audit-log PATH` / `audit_log:` in config): after every completed scan, evadex appends one JSON line to a log file recording the timestamp, operator (OS username), evadex version, scanner label, tool, strategies, categories, detection counts, pass rate, output file path, baseline paths, gate threshold, and exit code. Parent directories are created automatically. Write failures are silently ignored — a log error never affects the scan result or exit code. Set the path once in `evadex.yaml` and every run is automatically recorded without passing the flag each time.
- **Dependency lockfiles** (`requirements.txt`, `requirements-dev.txt`): generated with `pip-compile --generate-hashes`. Pin all transitive dependencies to exact versions with SHA-256 hashes for reproducible, tamper-evident installs.

### Config

`audit_log` is now a recognised config key. It accepts a string path or null. Validation exits with a clear error if the value is not a string or null.

### Tests

254 tests (up from 242). 12 new tests:

- `tests/unit/test_audit.py` (7 tests): `append_audit_entry` creates and appends correctly, creates parent directories, record contains all required fields, silently ignores bad paths, timestamp is ISO 8601, operator field is a non-empty string
- `tests/integration/test_config_cli.py` (5 tests): `--audit-log` CLI flag creates file with correct fields; multiple runs append separate lines; `audit_log` config key is applied; `exit_code: 1` is recorded when the detection-rate gate fails; write failure on bad path does not affect scan exit code

## [2.5.3] — 2026-04-07

### Fixed

- **`Variant` dataclass is now frozen** (`core/result.py`): `Variant` fields are never mutated after construction — the engine creates a new `Variant` per strategy rather than modifying the generator's original. Making the class frozen enforces this invariant and prevents accidental field assignment in future code.
- **Scanner labels escaped in compare HTML report** (`reporters/compare_html_reporter.py`): `label_a` and `label_b` (from `--scanner-label` or `--label-a`/`--label-b`) were rendered without the `| e` Jinja2 escape filter in all seven places they appear in the template. A label containing `&`, `<`, or `>` (e.g. `"rust-2.0.0 & python-1.3.0"`) would produce malformed HTML. All occurrences now use `| e`.

## [2.5.2] — 2026-04-07

### Fixed

- **`unicode_encoding` duplicate technique names** (`variants/unicode_encoding.py`): all three zero-width injection variants (ZWSP U+200B, ZWNJ U+200C, ZWJ U+200D) were emitted under the same technique name `"zero_width_injection"`. This caused `summary_by_generator` aggregation, per-technique comparison deltas, and `list-techniques` deduplication to conflate three distinct evasion techniques into one. Renamed to `"zero_width_zwsp"`, `"zero_width_zwnj"`, and `"zero_width_zwj"`. **Note:** baseline files produced before this fix will show these three variants as new/absent in `evadex compare` output — re-run the baseline to reset.
- **HTML report displays corrupted data for encoded variants** (`reporters/html_reporter.py`): the variant value cell (`{{ r.variant.value[:60] }}`) was rendered without the Jinja2 `| e` escape filter. Variants from `html_entity_decimal` (e.g. `&#52;&#53;&#49;`) were decoded by the browser and displayed as the original numeric value instead of the encoded string. Variants from `context_injection` containing XML tags (e.g. `<record>...`) corrupted the table structure. Fixed by adding `| e`.
- **`--baseline` and `--compare-baseline` same file destroys baseline** (`cli/commands/scan.py`): when both flags pointed to the same path, the scan wrote new results to the file first, then compared against itself — always showing zero delta and permanently destroying the original baseline. Now detected early (before the scan runs) and exits with a clear error message.
- **`structural` generator produced empty string variants** (`variants/structural.py`): `partial_first_half`, `partial_last_half`, and `partial_minus_one` were yielded unconditionally. For single-character inputs (or other very short values where `mid == 0`), this produced empty strings — variants that cannot meaningfully test scanner detection. Added guards to skip these when the result would be empty or identical to the original.
- **Engine `on_result` callback exception aborted scan** (`core/engine.py`): an uncaught exception from the `on_result` callback propagated through `run_async`, causing the scan to stop mid-run and lose all subsequent results. The callback is now wrapped in `try/except Exception: pass` so a buggy callback is silently ignored and the scan always completes.

### Tests

242 tests (up from 238). 4 new tests:

- `tests/unit/variants/test_unicode_encoding.py`: `test_zero_width_technique_names_are_unique` — asserts the three zero-width techniques have distinct names (`zero_width_zwsp`, `zero_width_zwnj`, `zero_width_zwj`)
- `tests/unit/variants/test_structural.py`: `test_partial_no_empty_variants` — asserts no empty string variant is produced for single-char and two-char inputs
- `tests/integration/test_new_features.py`: `test_engine_on_result_exception_does_not_abort_scan` — a callback that raises must not interrupt the scan
- `tests/integration/test_new_features.py`: `test_baseline_and_compare_baseline_same_file_rejected` — same-file conflict exits with code 1 before any scan runs

## [2.5.1] — 2026-04-07

### Fixed

- **Config `tool` validation now enforced** (`config.py`): the `VALID_TOOLS` set was defined but never applied in `load_config()` — an invalid tool name (e.g. `tool: bad-scanner`) was accepted without error and only failed later during the scan with a less clear message. Now raises `UsageError` at config load time with the list of valid adapters.
- **Config `categories: []` now rejected** (`config.py`): an empty list was silently accepted and then ignored (falsy check in `scan.py`), giving the impression all categories were being tested. Now raises `UsageError` with a clear message: _"Remove the key to run all structured categories."_
- **`compare` null `summary_by_category` no longer crashes** (`compare.py`): if a result file had `summary_by_category: null` (e.g., manually edited or produced by a very old build), `meta.get("summary_by_category", {})` returned `None` rather than the default `{}` (`.get()` returns the stored value, not the default, when the key is present). The comparison then crashed with `TypeError: 'NoneType' object is not iterable`. Fixed with `or {}` fallback.
- **`list-techniques` generator errors now surfaced** (`cli/commands/list_techniques.py`): a generator that raised an exception during technique enumeration was silently caught and displayed as having zero techniques, hiding the failure entirely. Now prints a `[red]Error loading generator ...[/red]` line so broken generators are immediately visible.
- **`delimiter` generator duplicate variants eliminated** (`variants/delimiter.py`): the `mixed_delimiter` and `excessive_delimiter` techniques did not check whether their output was identical to the original input value before yielding. Inputs already formatted with alternating or doubled delimiters would produce a duplicate of the original as a variant. Both now guard with `if result != value`.

### Tests

238 tests (up from 236). 2 new tests in `tests/unit/test_config.py`:

- `test_invalid_tool_value` — verifies `tool: bad-scanner` raises `UsageError` matching `"tool"`
- `test_empty_categories_list_raises` — verifies `categories: []` raises `UsageError` matching `"categories"`

## [2.5.0] — 2026-04-06

### Added

- **`evadex init` command** — generates a default `evadex.yaml` config file in the current directory. Errors cleanly if one already exists.
- **Config file support (`evadex.yaml`)** — all `scan` options can now be set in a YAML config file. Config values are defaults; CLI flags always override them. Supported keys: `tool`, `strategy`, `min_detection_rate`, `scanner_label`, `exe`, `cmd_style`, `categories`, `include_heuristic`, `concurrency`, `timeout`, `output`, `format`.
- **`--config PATH` flag on `evadex scan`** — explicitly load a config file from any path.
- **Auto-discovery** — if `--config` is not passed, evadex automatically loads `evadex.yaml` from the current directory if present.
- **Config validation** — clear error messages for unknown keys, invalid values, out-of-range numbers, and wrong types. Exits with code 2 before any scan runs.
- **Output file security notice** — a warning is now printed to stderr whenever scan results are written to a file, reminding users to restrict access (results may contain obfuscated variants of sensitive test values).
- **`evadex.yaml` added to `.gitignore`** — prevents accidental commit of config files that may contain internal paths or sensitive labels.
- **README: Configuration section** — documents `evadex init`, the full config file format, config key reference table, and validation error examples.

### Security fixes

- **Temp file permissions** — temp files written by the `dlpscan-cli` adapter now have `chmod 0o600` applied immediately after creation (owner-read/write only). Prevents other local processes from reading payload values (card numbers, SSNs, etc.) from the filesystem during the brief window between write and scan. Best-effort on Windows where ACLs apply instead.
- **Raw tracebacks replaced with clear error messages** — `FileNotFoundError` when writing `--output` or `--baseline` to a non-existent directory now prints `Cannot write output file '...': No such file or directory` and exits 1. Previously the raw Python traceback was printed to the terminal.
- **Empty or wrong-schema `--compare-baseline` handled cleanly** — an empty file or a JSON file missing `meta`/`results` keys now exits with a descriptive message rather than a `JSONDecodeError` or `KeyError` traceback.
- **`build_comparison` validates inputs** — raises `ValueError` with a descriptive message if either argument is missing required keys, rather than surfacing a bare `KeyError` to callers.
- **`KeyboardInterrupt` / `SystemExit` not swallowed by engine** — the per-task `except Exception` in `Engine._run_one` now explicitly re-raises `KeyboardInterrupt` and `SystemExit` before the catch-all, ensuring Ctrl+C always propagates.

### Dependencies

- Added `pyyaml>=6.0`.
- All runtime and dev dependencies now have upper-bound caps (`click>=8.1,<9`, etc.) to prevent silent breakage from major-version upgrades landing in CI.

### Tests

236 tests (up from 200). 46 new tests:

- `tests/unit/test_config.py` (23 tests) — config loading, partial configs, empty configs, missing file, unknown keys, and every validation error path (invalid strategy, format, cmd_style, min_detection_rate out of range, invalid category, concurrency ≤ 0, timeout ≤ 0, non-bool include_heuristic). Auto-discovery presence/absence. Default config YAML round-trip.
- `tests/integration/test_config_cli.py` (13 tests) — `evadex init` creates file, file content is valid, errors if file exists. `--config` loads values, CLI flags override config, concurrency override and default. Auto-discovery loads config from cwd, scan works without config file. Validation errors for invalid strategy, unknown key, missing file, and out-of-range min_detection_rate surface correctly through the CLI.
- `tests/integration/test_new_features.py` (6 new tests) — output/baseline write to non-existent directory exits cleanly; empty and wrong-schema `--compare-baseline` files exit cleanly; adapter exception produces error `ScanResult` rather than crashing; `KeyboardInterrupt` propagates out of the engine.
- `tests/integration/test_compare.py` (4 new tests) — `build_comparison` raises `ValueError` on empty dict and missing meta fields; `compare` CLI command exits cleanly on bad-schema and empty JSON files.

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
