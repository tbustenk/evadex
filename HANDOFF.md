# evadex — Handoff Notes

Last updated: 2026-07-04

Companion to `CLAUDE.md` (architecture/conventions) and `BACKLOG.md` (work
queue). This is the "resume here after a break" quick-start.

## Current state

- **Version: 3.34.0** (`pyproject.toml` is the source of truth; `CHANGELOG.md`
  is the user-facing release notes).
- **Tests — all passing** (verified 2026-07-04):
  - `python -m pytest tests/unit -q` → **1204 passed**
  - Integration: **300** (per CHANGELOG 3.34.0 — `1504/1504` total). Run with
    `pytest tests/integration -v` from a neutral cwd (see gotcha below).
- **PyPI:** `pip install evadex` (latest published stream; 3.28.2 was the first
  PyPI push, current tree is 3.34.0).
- **Branch:** `main`, clean except untracked scratch files (see below).
- **Working tree:** several untracked root-level scratch scripts
  (`check_*.py`, `evadex_regressions.py`, `inspect_results.py`) and a `results/`
  / `test_output/` dir — these are **local analysis scratch, not part of the
  package** (documented in `CLAUDE.md`). Do not commit them.

## Open PRs

| PR | Branch | Summary | Notes |
|---|---|---|---|
| #13 | `feat/auto-transport-sse-watch` | feat: auto transport, SSE stream, regression watch — v3.30.0 | **stale** — these features already landed on `main` (v3.30.0+). Close or rebase; do not re-merge. |
| #12 | `feat/push-results-to-siphon` | feat(bridge): push completed scan results to siphon-api postgres | **stale** — shipped as v3.29.1. Close. |

> Both open PRs predate the direct-to-`main` releases that superseded them.
> First resume action is to reconcile/close them (see checklist).

## To resume work

```bash
git checkout main && git pull
pip install -e ".[dev,bridge,barcodes,data-formats,archives]"
python -m evadex doctor        # environment / adapter health
python -m evadex quickstart    # interactive first-run wizard → writes evadex.yaml
```

## Key commands

- **Scan:** `python -m evadex scan --transport http --url http://localhost:8080/api --tier northam --fast`
- **False positives:** `python -m evadex falsepos --count 50`
- **Regression watch:** `python -m evadex watch --threshold 2.0`
- **Bridge (HTTP API for C2/dashboards):** `python -m evadex bridge --port 8081`
- **Status:** `python -m evadex status`
- **Score (0-100 scanner quality):** `python -m evadex score` · `leaderboard` · `coverage` · `explain`
- **CI gate:** `python -m evadex ci --min-detection 30 --max-fp 20`
- **Report (HTML w/ trend sparkline):** `python -m evadex report`

## Architecture

- `src/evadex/core/` — registry (`load_builtins()` — **edit it to register any
  new generator/adapter**), async fan-out engine, result dataclasses.
- `src/evadex/bridge/` — FastAPI HTTP API (`/v1/evadex/run|metrics|generate`),
  push-results-to-siphon.
- `src/evadex/adapters/` — scanner adapters (`siphon`, `siphon_cli` w/ CLI+HTTP
  transport, `dlpscan`, `presidio`, `http_generic`, `netskope`).
- `src/evadex/payloads/` — tiers + curated fixtures; capital-markets categories.
- `src/evadex/synthetic/` — checksum-correct synthetic-value generators.
- `src/evadex/variants/` — one file per evasion technique family.
- `src/evadex/generate/writers/` — one writer per file format (docx/pdf/xlsx/…).
- `src/evadex/cli/commands/` — all CLI subcommands.
- `src/evadex/{profiles,feedback,reporters,lsh}/` — profiles, smart-mode
  feedback loop, JSON/HTML reporters, LSH near-dup generation.

Full detail (plus non-obvious gotchas) lives in `CLAUDE.md`.

## Gotchas that bite on resume (see CLAUDE.md for full list)

- **`ScanResult.severity` polarity is inverted**: `PASS` = scanner *caught* the
  evasion (good); `FAIL` = bypass succeeded (bad). Always read as "did the
  scanner do its job".
- **Run tests from a neutral cwd.** The repo-root `evadex.yaml`
  (`tool: siphon-cli`, `transport: http`, `url:`) is auto-discovered and leaks
  into CliRunner tests; `cd ~ && pytest /path/to/tests/unit` or use
  `isolated_filesystem()`. CI is unaffected (no local `evadex.yaml`).
- **Never `ruff check --fix` `core/registry.py`** without re-reading it — it
  deletes the 21 `# noqa: F401` side-effect imports and silently breaks the
  whole plugin registry.
- **Windows:** `cli/app.py` wraps stdout/stderr in UTF-8 at import (Rich
  box-drawing crashes on cp1252). Don't remove.

## What was built (this sprint: 3.29.1 → 3.34.0)

- **v3.34.0** — HTML report Detection-Trend sparkline + delta card;
  capital-markets evasion variants (grouped-spaces CUSIP, ISIN country-prefix
  noise, Bloomberg suffix).
- **v3.33.0** — `score` / `leaderboard` / `explain` / `coverage` commands
  (composite 0-100 scanner quality from audit history + gap analysis).
- **v3.32.0** — `export --format parquet`, Netskope adapter, capital-markets
  variants (ISIN/CUSIP/SEDOL/LEI/FIGI/RIC).
- **v3.31.0** — `evadex ci` quality-gate command, generic HTTP adapter, HTML
  report risk-rating badge + compliance mapping (PCI DSS / PIPEDA / HIPAA).
- **v3.30.x** — auto transport selection, SSE stream endpoint, regression
  `watch` command, `compare --baseline auto`, `techniques --by-category`.
- **v3.29.x** — HTTP transport for siphon-cli (~12× throughput), bridge
  push-results-to-siphon, evadex → postgres via siphon-api.

## Biggest remaining gaps

1. **Morse-code bypass** — ~29% residual evasion (down from ~50%). Remaining
   failures are context-required IDs (SSN/SIN/AU_TFN/DE_TAX_ID/FR_INSEE) that
   Siphon's morse alt-path skips by design. Coordinate with Siphon PR #349.
2. **Regional digits** — Thai / Extended Arabic-Indic / Arabic-Indic now all
   PASS against Siphon; keep an eye on them in fresh baselines.
3. **Context-injection variants** — still relatively weak; worth expanding.
4. **More scanner adapters** — Forcepoint, McAfee (currently siphon/dlpscan/
   presidio/http_generic/netskope).
5. **Hosted / SaaS evadex** — no multi-tenant hosted version yet; commercial
   opportunity.

## Resumption checklist

1. Reconcile/close the two stale open PRs (#12, #13 — already superseded on `main`).
2. `pip install -e ".[dev]"` and run `pytest tests/unit -q` to confirm green.
3. Run evadex against the latest Siphon (`scan --transport http … --tier northam`)
   for a fresh detection baseline.
4. Tackle context-injection variants + a new scanner adapter, or scope the
   hosted-SaaS idea.
