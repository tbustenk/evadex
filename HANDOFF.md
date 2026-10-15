# evadex — Handoff Notes

Last updated: 2026-10-15

Companion to `CLAUDE.md` (architecture/conventions) and `BACKLOG.md` (work
queue). This is the "resume here after a break" quick-start.

## Current state

- **Version: 3.41.0** (`pyproject.toml` is the source of truth; `CHANGELOG.md`
  is the user-facing release notes).
- **Tests — all passing** (verified 2026-10-15, run from a neutral cwd):
  - `pytest tests/unit -q` → **1369 passed**
  - `pytest tests/integration -q` → **300 passed**
  - `ruff check src` → clean (CI runs exactly this; `tests/` is not linted in CI)
- **PyPI:** `pip install evadex` (3.28.2 was the first push; publish 3.41.0
  once the PRs below are on `main`).
- **Scanner under test:** Siphon (`dlpscan-rs`) 2.10.0 / siphon-core 2.10.0.
  Last full baseline: northam tier, 21,805 submissions, **80.4%** detection,
  0 errors (`results/rebaseline_northam/northam_2.10.0.json`, local only).

## Open PRs (merge in this order; each is stacked on the previous)

| PR | Branch | Summary |
|---|---|---|
| #30 | `feat/seeded-wrap-context-error-accounting` | `scan --seed`, `meta.detection_rate` / `error_rate`, `ci --max-error-rate`, real `ci --max-fp` (it read a key scan never wrote and passed every gate) |
| #31 | `feat/batched-cli-transport` | `scan --batch`: one `siphon scan-dir` per batch instead of one process per submission (identical verdicts, ~5x faster); HTTP transport forwards `require_context` / `min_confidence` / `categories`; `ci --fp-category` |
| #32 | `chore/hygiene-docs-3.41` | this file, `BACKLOG.md`, `.gitignore`, generated technique index, legacy-adapter notice, stale counts |

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
   needs `batch: true`, `--seed`, a threshold near the real baseline, `2>&1`
   before its `tee` (the uploaded report has always been empty), and to become
   a required check — only an admin on `oxide11/dlpscan-rs` can do the last.
2. **Morse** 65% bypass, **capital markets** 39%, **unicode whitespace** and
   **structural** ~35% on the 2.10.0 baseline.
3. **Per-category deltas are still noisy**: few payloads per category. A seed
   fixes the sentences but not the sample size.
4. **Dead weight**: `cache/` is never called by `scan`; `lsh/` has no tests;
   `adapters/siphon/` is legacy; `bridge/` push contract to siphon-api is
   unverified against the current `ingest_evadex_run`.
5. **`HEURISTIC_CATEGORIES` vs `CATEGORY_TYPES` drift** (56 categories typed
   heuristic but run by default) — see the 3.40.2 changelog note.
