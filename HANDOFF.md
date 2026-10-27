# evadex — Handoff Notes

Last updated: 2026-10-27

Companion to `CLAUDE.md` (architecture/conventions) and `BACKLOG.md` (work
queue). This is the "resume here after a break" quick-start.

## Current state

- **Version: 3.42.0** (`pyproject.toml` is the source of truth; `CHANGELOG.md`
  is the user-facing release notes). 3.41.1 skips the variants DOCX/XLSX
  cannot carry instead of recording errors; 3.42.0 embeds real fonts in the
  PDF fixture and leaves out what no font can draw.
- **Tests — all passing** (verified 2026-10-27, run from a neutral cwd):
  - `pytest tests/unit -q` → **1406 passed**
  - `pytest tests/integration -q` → **300 passed**
  - `ruff check src` → clean (CI runs exactly this; `tests/` is not linted in CI)
- **PyPI:** `pip install evadex` (3.28.2 was the first push; 3.42.0 is not
  published yet).
- **Scanner under test:** Siphon (`dlpscan-rs`) siphon-cli 2.9.0 /
  siphon-core 2.12.0 on `main` as of 2026-10-27. Last full baseline: northam
  tier, 21,805 submissions, **80.4%** detection, 0 errors, on siphon-core
  2.10.0 (`results/rebaseline_northam/northam_2.10.0.json`, local only).
  Siphon's gate measures the same tier on every detection-bearing PR:
  text 78.8% · docx 76.8% · xlsx 75.4% · pdf 75.2% (2026-10-19, seed
  20261015, evadex 3.42.0).

## Open PRs

None. #30–#35 are on `main` (3.41.0 → 3.42.0).

## To resume work

```bash
git checkout main && git pull
pip install -e ".[dev,bridge,barcodes,data-formats,archives]"
python -m evadex doctor        # environment / adapter health
cd ~ && python -m pytest /path/to/evadex/tests/unit -q   # neutral cwd, see gotcha below
```

## Key commands

- **Scan (CLI, batched):** `python -m evadex scan --tool siphon-cli --exe <siphon> --tier northam --batch --seed 1`
- **Scan (HTTP):** `python -m evadex scan --transport http --url http://localhost:8080 --tier northam`
- **Repeat a run exactly:** every scan prints `Seed: N`; pass `--seed N`.
- **False positives:** `python -m evadex falsepos --count 50 --wrap-context`
  (the `entropy` category is random high-entropy strings; expect it to be flagged)
- **CI gate:** `python -m evadex ci --min-detection 78 --max-fp 5 --fp-category credit_card ... --seed N`
  exit 0 pass · 1 threshold violated · 2 inconclusive (scan failed, too many errors, FP run failed)
- **Bridge (HTTP API for C2/dashboards):** `python -m evadex bridge --port 8081`
- **Score / leaderboard / coverage / explain / report:** as before

## Architecture

See `CLAUDE.md`. Short version: `core/registry.py` (`load_builtins()` — edit it
to register any new generator/adapter), `core/engine.py` async fan-out,
`adapters/` (the one that matters is `siphon_cli`, CLI + HTTP + batch),
`variants/` one file per technique family (17 families, 158 technique names;
`docs/techniques.md#technique-index` is generated from them), `generate/writers/`
one per file format, `cli/commands/` 36 subcommands.

## Gotchas that bite on resume (full list in CLAUDE.md)

- **`ScanResult.severity` polarity is inverted**: `PASS` = scanner caught it.
- **Three rates in scan JSON.** `pass_rate` counts errors as misses (kept for
  old comparisons); `detection_rate` excludes them; `error_rate` is the share
  that never got a verdict. `ci` grades `detection_rate`.
- **Run tests from a neutral cwd.** The repo-root `evadex.yaml` is
  auto-discovered and leaks into CliRunner tests.
- **Never `ruff check --fix` `core/registry.py`** without re-reading it.
- **`transport: http` decodes file strategies to text** before posting; only
  the CLI transport exercises Siphon's file extractors. Baselines taken over
  HTTP and over CLI are not the same measurement.
- **The `siphon` adapter is legacy** (targets a server `siphon serve` no
  longer launches). `edm` and `entropy` still default to it.

## Biggest remaining gaps

1. **Siphon's gate** (`dlpscan-rs/.github/workflows/evadex-quality-gate.yml`)
   has `batch: true`, `--seed 20261015`, `--concurrency 64`,
   `--max-error-rate 2`, one job per strategy with its own floor (text 75 /
   docx 73 / pdf 71 / xlsx 72), `--fp-category` on the text job and `2>&1 |
   tee` since 2026-10-16/19. dlpscan-rs #544 makes it run (or skip) on every
   PR so it can be a required check; flipping that needs an admin on
   `oxide11/dlpscan-rs` (dlpscan-rs #515).
2. **Morse** 65% bypass, **capital markets** 39%, **unicode whitespace** and
   **structural** ~35% on the 2.10.0 baseline.
3. **Per-category deltas are still noisy**: few payloads per category. A seed
   fixes the sentences but not the sample size.
4. **Dead weight**: `cache/` is never called by `scan`; `lsh/` has no tests;
   `adapters/siphon/` is legacy; `bridge/` push contract to siphon-api is
   unverified against the current `ingest_evadex_run`.
5. **`HEURISTIC_CATEGORIES` vs `CATEGORY_TYPES` drift** (56 categories typed
   heuristic but run by default) — see the 3.40.2 changelog note.
