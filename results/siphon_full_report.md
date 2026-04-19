# Siphon end-to-end test report

**Date:** 2026-04-19
**Tester:** Kenzie Butts (evadex)
**Reporting suite:** evadex v3.11.0 (in development)

---

## 1. Build under test

| Field | Value |
|---|---|
| Repo | `C:/Users/Ryzen5700/dlpscan-rs` |
| Commit | `75fd593` ("Merge pull request #131 — siphon-c2 wireframes 2NrOz") |
| Branch | `main` |
| Build profile | `cargo build --release --features full` |
| Build time | 4 m 08 s |
| Binaries produced | `siphon.exe`, `dlpscan.exe`, `benchmark.exe`, `profile.exe`, `profile2.exe` |
| Build warnings | 2 — unused `Response` import in `src/api.rs:769`, unused `http_builder` var at `src/api.rs:910` |

---

## 2. Critical blocker — `siphon serve` is missing

**Severity:** High (blocks every HTTP-based test in this report)

The library exposes `api::serve(ApiConfig)` in `src/api.rs:765`, complete with HTTP/1.1 + HTTP/2 routing for `/v1/scan`, `/v1/edm/*`, and `/v1/lsh/*`. **No CLI subcommand dispatches to it.** `src/main.rs:53` declares the `Commands` enum with `Scan`, `ScanDir`, `ScanText`, `Guard`, `Categories`, `Presets`, `Init`, `Config`, `TestPattern`, `Info`, `Edm`, `Lsh`, `Tui`, `Top` — but no `Serve`.

```text
$ ./target/release/siphon serve
error: unrecognized subcommand 'serve'
```

This forces every HTTP-API test to fall back to a binary-shell adapter or be skipped entirely. evadex commands that target Siphon's HTTP endpoints exclusively — `evadex entropy --tool siphon`, `evadex edm --tool siphon` — cannot run against the current binary at all.

**Recommendation:** add a `Serve { host, port, key, … }` variant to `Commands` in `src/main.rs` that calls `tokio::runtime::Runtime::new()?.block_on(api::serve(cfg))`. Roughly 20 lines of code; the `async-support` feature is already in the `full` build.

---

## 3. Test results

All scanner tests below ran against `siphon.exe @ 75fd593` via the `dlpscan-cli` adapter (`--cmd-style rust`). Banking tier — 489 payloads × 17 generators × ~1.05 evasions/payload = 8705 variants.

### 3.1 Detection rate (banking tier, text strategy)

| Metric | Value |
|---|---|
| Total variants | 8 705 |
| Pass (detected) | 3 238 |
| Fail (evaded) | 5 467 |
| Errors | 0 |
| **Overall detection rate** | **37.2 %** |

Saved to `results/scans/siphon_api_latest.json` and copied to `results/baseline.json` for future regression comparisons.

### 3.2 False-positive rate (`evadex falsepos`, `--wrap-context`, 100/cat)

| Category | Flagged / total | FP rate |
|---|---|---|
| `ca_ramq` | 100 / 100 | **100.0 %** |
| `ssn` | 100 / 100 | **100.0 %** |
| `phone` | 59 / 100 | 59.0 % |
| `entropy` | 48 / 100 | 48.0 % |
| `iban` | 26 / 100 | 26.0 % |
| `sin` | 26 / 100 | 26.0 % |
| `credit_card` | 0 / 100 | 0.0 % |
| `email` | 0 / 100 | 0.0 % |
| **Overall** | **359 / 800** | **44.9 %** |

**Notable:** the `ca_ramq` and `ssn` recognisers flag 100 % of structurally invalid values when those values appear next to a keyword (`wrap_context`). Pattern is matching shape-only; checksum or reserved-range validation is bypassed. The credit-card recogniser correctly rejects every Luhn-failing value — that's the gold standard the others should match.

Saved to `results/falsepos/siphon_falsepos_latest.json`.

### 3.3 Entropy detection — **not run**

`evadex entropy` only supports the `siphon` adapter (HTTP-only). Blocked by the missing `serve` subcommand. Once Serve is exposed, re-run:

```bash
evadex entropy --tool siphon --url http://localhost:8080 --api-key $KEY
```

The harness covers 6 entropy categories (`random_api_key`, `random_token`, `random_secret`, `encoded_credential`, `assignment_secret`, `gated_secret`) submitted in 3 contexts (bare / gated / assignment) plus 6 evasion techniques tuned to Siphon's 16-char floor + 4.5 bits/char threshold (split, comment, concat, low_mix, encode, space).

### 3.4 EDM detection — **not run end-to-end**

Same blocker — `evadex edm --tool siphon` requires HTTP. The corpus generator (`evadex edm --generate-corpus --output corpus.json`) does run offline and emits 541 entries across 477 categories in Siphon's expected `POST /v1/edm/register` body shape. Evasion-probe transforms ready to run once Serve is available: `exact, uppercase, lowercase, dashes, spaces, dots, slashes, nbsp_spaces, homoglyph_0, homoglyph_o, zero_width`.

Note also: `evadex edm` does not accept `--tier banking`. Filed for follow-up — should accept `--tier` to match `evadex scan`/`falsepos` flag surface.

### 3.5 LSH document similarity (new in this report)

evadex v3.11.0 ships a brand-new `evadex lsh` command. Tested via the binary's `lsh register` / `lsh query` subcommands against a fresh state file (no shared production vault touched). Base document: 198-word loan-decision memorandum (`evadex.lsh.BASE_DOCUMENTS["loan_decision"]`). Variants generated with stable seed; sensitive tokens preserved across distortion so the LSH "same record" property holds.

| Variant | Empirical Jaccard (ground truth) | Siphon reported | Detected at threshold = 0.5 ? |
|---|---|---|---|
| exact (sanity) | 100 % | 100 % | yes |
| distort 5 % | 83 % | 85 % | **yes** |
| distort 10 % | 53 % | — | **no** |
| distort 15 % | 35 % | — | no |
| distort 20 % | 35 % | — | no |
| distort 30 % | 25 % | — | no |
| distort 50 % | 8 % | — | no |

**Minimum reliably detected similarity: 83 %.**

**Finding (likely-by-design but undocumented):** the 10 %-distortion variant has empirical Jaccard 53 %, comfortably above the user-supplied `--threshold 0.5`, yet Siphon returned no match. Reason: `DocumentVault::default_vault()` uses 128 hashes × 16 bands × `threshold = 0.8`, and the LSH band-index (`add_to_index` / `get_candidates` in `crates/siphon-core/src/lsh.rs:330-366`) is the sole candidate filter. The user-supplied threshold passed to `query()` only post-filters; if a document never hits a shared band bucket it is invisible regardless of the query threshold.

**Recommendation:** either (a) document this clearly so callers know "use a vault tuned for 0.5 if you want to query at 0.5", or (b) widen `default_vault()` (more bands, fewer rows per band) to retain candidate recall down to ~0.5 similarity.

Saved to `results/scans/siphon_lsh_latest.json`.

### 3.6 Worst categories (from §3.1)

The 15 categories where ≥96 % of variants slip past Siphon's detector. Useful prioritisation list for ruleset improvements:

| Category | Detected / total | Detection rate |
|---|---|---|
| `ca_postal_code` | 3 / 100 | 3.0 % |
| `teller_id` | 3 / 100 | 3.0 % |
| `ca_pr_card` | 3 / 99 | 3.0 % |
| `chips_uid` | 3 / 99 | 3.0 % |
| `insurance_policy` | 4 / 122 | 3.3 % |
| `dob` | 4 / 119 | 3.4 % |
| `card_expiry` | 4 / 116 | 3.4 % |
| `ca_ns_drivers` | 4 / 108 | 3.7 % |
| `ca_nl_drivers` | 4 / 107 | 3.7 % |
| `ca_transit_number` | 4 / 105 | 3.8 % |
| `hsm_key` | 4 / 100 | 4.0 % |
| `account_balance` / `income_amount` | 4 / 96 each | 4.2 % |
| `dti_ratio` | 4 / 95 | 4.2 % |
| `pin_block` | 6 / 123 | 4.9 % |

Most are categories where evadex generates structurally valid Canadian/banking-specific values (provincial drivers, postal codes, RAMQ-adjacent IDs) that the current Siphon ruleset lacks named patterns for.

### 3.7 Top evasion generators still bypassing detection

| Generator | Detected / total | Detection rate |
|---|---|---|
| `morse_code` | 3 / 80 | **3.8 %** |
| `regional_digits` | 169 / 924 | 18.3 % |
| `encoding_chains` | 114 / 553 | 20.6 % |
| `structural` | 184 / 861 | 21.4 % |
| `encoding` | 338 / 1379 | 24.5 % |
| `delimiter` | 173 / 456 | 37.9 % |
| `barcode_evasion` | 124 / 316 | 39.2 % |
| `unicode_encoding` | 329 / 786 | 41.9 % |
| `splitting` | 331 / 790 | 41.9 % |
| `bidirectional` | 217 / 474 | 45.8 % |
| `unicode_whitespace` | 157 / 287 | 54.7 % |
| `context_injection` | 948 / 1580 | 60.0 % |

Morse code (3.8 %) is the cheapest immediate win — a single normaliser pass would lift detection on 77 of the 80 variants currently missed. Regional digits (Arabic-Indic, Khmer, Bengali, Thai, …) at 18.3 % is the next largest gap and aligns with Canadian-French language requirements; folding non-ASCII digit characters back to `0-9` before pattern matching would close most of it.

### 3.8 Comparison to historical CLI runs

`results/audit.jsonl` shows nine prior runs from 2026-04-19 00:02 against earlier builds (commit `96df67a`). All-categories pass rates across those runs cluster around 100 % — but that's because they were single-input tests (one variant each), not full banking-tier runs. The 37.2 % pass rate from this run is the first against `75fd593` and now serves as the canonical baseline (`results/baseline.json`).

---

## 4. Generated-fixture format verification

Each format generated with `--tier banking --count 20` (count 5 for image formats):

| Format | Size | Validation | Notes |
|---|---|---|---|
| `eml` | 75 KB | parses with stdlib `email.message_from_file` | morse-newline variants embed raw `\n` in the body; consider quoted-printable round-trip review |
| `json` | 388 KB | parses; 1 400 records, 674 carry `_evasion_technique` metadata | clean |
| `xml` | 768 KB | parses; 1 400 ISO 20022 `CdtTrfTxInf` elements | clean |
| `sql` | 299 KB | **was broken — fixed in this PR** | schema declared `sensitive_val` only but INSERTs referenced category-specific columns (`card_number`, `routing_number`, …) — every row failed in strict-mode MySQL / SQLite. Schema now declares all 11 category columns; loads cleanly into SQLite, 1 400 rows |
| `log` | 226 KB | parses line-by-line | morse-newline variants legitimately span multiple lines — by-design but worth noting downstream log aggregators may stitch incorrectly |
| `parquet` | 195 KB | reads via pyarrow; 1 400 rows × 14 columns × 2 row groups (snappy) | clean |
| `sqlite` (`.db`) | 236 KB | reads via stdlib `sqlite3`; tables `customers` (1 400), `transactions` (20), `accounts` (40) | clean |
| `png` | 101 KB | opens via PIL; 962 × 7 180 px barcode grid | clean |
| `jpg` | 888 KB | opens via PIL; 962 × 7 180 px | clean |

---

## 5. Action items (proposed)

| Priority | Owner suggestion | Item |
|---|---|---|
| **P0** | dlpscan-rs | Wire `Commands::Serve` into `src/main.rs` so the HTTP API server can be started from the binary. Unblocks `evadex entropy` and `evadex edm` end-to-end tests. |
| **P1** | dlpscan-rs | Document `DocumentVault::default_vault()` candidate-recall floor (~0.8 Jaccard) or expand bands so `query(text, threshold=0.5)` actually recalls down to 0.5. |
| **P1** | dlpscan-rs | Add validation passes for `ssn` and `ca_ramq` (currently 100 % FP rate on structurally-invalid values placed in keyword context). |
| **P2** | dlpscan-rs | Add normalisation passes for the four cheapest evasion families: morse code (96 % evade), regional digits (82 %), encoding chains (79 %), structural mixed-case (79 %). Each is a few lines in the input pipeline. |
| **P2** | dlpscan-rs | Add named patterns for the missing banking categories: `ca_postal_code`, `teller_id`, `ca_pr_card`, `chips_uid`, `insurance_policy`, `card_expiry`, provincial drivers/health cards. |
| **P3** | dlpscan-rs | Cosmetic: clean two `cargo build --features full` warnings in `src/api.rs:769` and `src/api.rs:910`. |
| **P2** | evadex | Add `--tier` to `evadex edm` for parity with `scan`/`falsepos`. |

---

## 6. Reproduction

All steps run on `C:/Users/Ryzen5700` with `python -m evadex` (evadex installed editable from source).

```bash
# Build
cd C:/Users/Ryzen5700/dlpscan-rs && git pull && cargo build --release --features full

# Banking-tier scan
python -m evadex scan --tool dlpscan-cli \
  --exe C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe \
  --cmd-style rust --tier banking --strategy text \
  --scanner-label "siphon-rust-$(git -C C:/Users/Ryzen5700/dlpscan-rs rev-parse --short HEAD)" \
  --format json -o results/scans/siphon_api_latest.json

# False positives
python -m evadex falsepos --tool dlpscan-cli \
  --exe C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe \
  --cmd-style rust --count 100 --wrap-context --format json \
  -o results/falsepos/siphon_falsepos_latest.json

# LSH
python -m evadex lsh --exe C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe \
  --similarity 0.5 -o results/scans/siphon_lsh_latest.json

# Baseline (saved during scan)
python -m evadex scan ... --baseline results/baseline.json
```
