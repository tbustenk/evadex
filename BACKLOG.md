# evadex Backlog

Last updated: 2026-06-21

## Ready to build

### Medium priority
- [ ] `evadex export --format parquet` — dump audit log to Parquet for BI tool ingestion

### Detection coverage gaps (from recent evadex data)
- [ ] Morse code bypass — ~50% evasion rate; target <30%
- [ ] Regional digits bypass (Thai, Extended Arabic-Indic) — high bypass rate in northam tier
- [ ] Context injection technique — `evadex watch` now surfaces regressions, but context_injection variants still weak

## In progress
- (none)

## Recently completed
- [x] v3.31.0 — `evadex ci` quality gate command, generic HTTP adapter, HTML report risk rating + compliance mapping (PR #15)
- [x] v3.30.1 — compare --baseline auto, techniques --by-category, doctor scans/sec, watch sliding baseline
- [x] v3.30.0 — auto transport, SSE stream endpoint, regression watch command
- [x] v3.29.1 — bridge profiles endpoint, C2 profile dropdown, profile init seeding
- [x] v3.29.0 — HTTP transport for siphon-cli (12x throughput vs CLI), bridge push-to-siphon, evadex → postgres via siphon-api
- [x] v3.28.2 — published to PyPI
- [x] v3.28.x — schedule, benchmark, report, export, diff, validate, status, cache commands
