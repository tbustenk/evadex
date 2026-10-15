# evadex Backlog

Last updated: 2026-10-15

## Ready to build

### High priority — measurement you can trust
- [x] `scan --seed`; `detection_rate` / `error_rate`; `ci` grades verdicts only and exits 2 when inconclusive (PR #30, v3.41.0)
- [x] `ci --max-fp` runs `falsepos` instead of reading a key scan never wrote (PR #30)
- [x] `scan --batch`: one `scan-dir` per batch of submissions; HTTP transport forwards scan options (PR #31)
- [ ] **Repeat-run variance figure.** Run the same seed twice and two different seeds on the northam tier; publish the run-to-run spread so a "+3.9 pp" has an error bar. Add `evadex compare` support for "same scanner, different seed".
- [ ] **Errors in the summary's per-technique table.** `_print_summary` ranks techniques by bypassed/total; an errored submission neither bypassed nor detected. Show errors per family.
- [ ] **`scan --min-detection-rate` should grade `detection_rate`** (errors excluded) with its own error gate, matching `ci`. Left on `pass_rate` in 3.41.0 so existing profiles keep their meaning; change with a major note.

### Siphon gate (lives in `dlpscan-rs`)
- [ ] `batch: true`, `--seed`, `--concurrency 64`, `--fp-category` (all but `entropy`), `2>&1 | tee`, timeout 180 → 60 min, threshold raised toward the measured baseline. Then make it a **required check** (needs an `oxide11/dlpscan-rs` admin; `tbustenk` has push only).

### Dead weight and legacy
- [ ] **Remove `adapters/siphon/`** once `edm` and `entropy` are moved to siphon-api's endpoints. It targets `POST /v1/scan` + `x-api-key` on port 8000, the server `siphon serve` no longer launches; returns 404 against a current Siphon; zero tests. `docs/github-actions/*.yml` were switched to `siphon-cli --transport http` in 3.41.0.
- [ ] **`cache/`**: `ScanCache` is not referenced by `scan.py`; only `evadex cache stats|clear` touches it. Wire it in or delete it.
- [ ] **`lsh/`**: 282 lines, zero tests, untouched since May. Decide.
- [ ] **`bridge/` push to siphon-api**: `_push_results_to_siphon` posts to `/v1/evadex/runs`; siphon-api has moved 263 commits since the bridge last changed. Verify the payload shape against `ingest_evadex_run` or add a contract test.

### Taxonomy
- [ ] **`HEURISTIC_CATEGORIES` vs `CATEGORY_TYPES` drift**: 56 categories typed `HEURISTIC` still run by default (API keys, tokens, private keys, labels). Deriving one list from the other drops them from default `core`/`regional`/`full` runs and breaks comparisons with earlier baselines. Needs a deliberate call.
- [ ] `docs/techniques.md` prose covers 24 of 158 technique names; the generated **Technique index** at the bottom lists all of them. Regenerate the index when a generator changes (script: enumerate `all_generators()` over one builtin payload per category, collect `(generator, technique, transform_name)`).

### Detection coverage gaps (2.10.0 northam baseline, 21,805 submissions, 80.4%)
- [ ] `morse_code` 65.0% bypass (52/80) — context-required IDs skipped by Siphon's morse alt-path by design
- [ ] `capital_markets` 39.0% (156/400)
- [ ] `unicode_whitespace` 34.6% (274/791), `structural` 34.6% (696/2013)
- [ ] `context_injection` 26.6% (984/3700), `encoding` 23.8%, `encoding_chains` 22.4%, `delimiter` 22.0%
- [ ] `leetspeak` 100% (3/3) — three variants; decide whether leetspeak on digits is a real evasion or a sample-size artefact

## Not doing
- Forcepoint / McAfee adapters, hosted SaaS evadex — parked until the measurement items above are done; a number nobody can reproduce is not worth more adapters.

## Recently completed
- [x] v3.41.0 — seed, error accounting, real FP gate, batched CLI transport, HTTP option forwarding, `ci --fp-category`, hygiene + doc drift (PRs #30, #31, #32)
- [x] v3.40.x — ticker templates and seeds, MiFID → heuristic, WKN/RIC mapped to siphon-core 2.10.0 rules
- [x] Closed stale PRs #12 / #13 (features had shipped directly to main)
