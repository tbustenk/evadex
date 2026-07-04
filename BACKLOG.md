# evadex Backlog

Last updated: 2026-07-04

## Ready to build

### Medium priority
- [x] `evadex export --format parquet` — dump audit log to Parquet for BI tool ingestion (v3.32.0)

### Detection coverage gaps (from recent evadex data)
- [ ] Morse code remaining bypass — ~29% evasion rate (down from ~50%); remaining failures are SSN/SIN/AU_TFN/DE_TAX_ID/FR_INSEE (context-required patterns skipped in Siphon alt path by design — see dlpscan-rs BACKLOG.md for rationale)
- [x] Regional digits bypass — Thai (U+0E50), Extended Arabic-Indic (U+06F0), Arabic-Indic (U+0660) all PASS; Siphon HOMOGLYPH_MAP already covered them
- [x] Context injection technique — all 7 tested context_injection variants PASS in Siphon
- [x] Morse IBAN bypass — all 4 evadex variants (space/nosep/newline/slash sep) now detected in Siphon 2.1.4; slash variant fixed by slash decoder accepting multi-char alpha tokens

## In progress (open PRs — both superseded by direct-to-main releases)
- [ ] #13 — feat: auto transport, SSE stream, regression watch (v3.30.0) — **stale**, already on main; close/rebase
- [ ] #12 — feat(bridge): push completed scan results to siphon-api postgres (v3.29.1) — **stale**, already on main; close

## Resumption notes (for when you come back)

Start here:
1. Check open PRs — #12 and #13 are stale (their features already shipped to
   main via later releases). Close or rebase; don't re-merge.
2. Run evadex against the latest Siphon for a fresh baseline
   (`python -m evadex scan --transport http --url http://localhost:8080/api --tier northam --fast`).
3. Tackle context-injection variants (still weak) and the morse bypass gap
   (~29% residual — coordinate with Siphon PR #349).
4. Consider a SaaS / hosted version of evadex for commercial potential; add a
   new scanner adapter (Forcepoint / McAfee) to broaden coverage.

See `HANDOFF.md` for full state, versions, and commands.

## Recently completed
- [x] v3.34.0 — HTML report Detection-Trend sparkline + delta card; capital-markets evasion variants (grouped-spaces CUSIP, ISIN country-prefix noise, Bloomberg suffix)
- [x] v3.33.0 — `score`, `leaderboard`, `explain`, `coverage` commands (composite scanner quality + gap analysis)
- [x] v3.32.0 — parquet export, Netskope adapter, capital-markets evasion variants (ISIN/CUSIP/SEDOL/LEI/FIGI/RIC)
- [x] v3.31.0 — `evadex ci` quality gate command, generic HTTP adapter, HTML report risk rating + compliance mapping (PR #15)
- [x] v3.30.1 — compare --baseline auto, techniques --by-category, doctor scans/sec, watch sliding baseline
- [x] v3.30.0 — auto transport, SSE stream endpoint, regression watch command
- [x] v3.29.1 — bridge profiles endpoint, C2 profile dropdown, profile init seeding
- [x] v3.29.0 — HTTP transport for siphon-cli (12x throughput vs CLI), bridge push-to-siphon, evadex → postgres via siphon-api
- [x] v3.28.2 — published to PyPI
- [x] v3.28.x — schedule, benchmark, report, export, diff, validate, status, cache commands
