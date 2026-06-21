# evadex Backlog

Last updated: 2026-06-21

## Ready to build

### High priority
- [x] HTTP transport mode (`transport: http`) — SiphonCliAdapter POSTs to siphon-api instead of spawning subprocess (v3.29.0)
- [x] Auto transport (`transport: auto`) — probes HTTP endpoint on startup; falls back to CLI subprocess automatically (v3.30.0)
- [x] SSE bridge endpoint — GET /v1/evadex/run/{run_id}/stream; 1-second cadence; C2 EventSource support (v3.30.0)
- [x] Regression watch command — `evadex watch`; rolling baseline, pp-drop threshold, webhook POST alert (v3.30.0)

### Medium priority
- [x] `evadex compare --baseline auto` — auto-pick most recent matching archive instead of requiring an explicit path (v3.30.1)
- [x] Per-category detection trending — `evadex techniques --by-category`; detection rate per category across scan history (v3.30.1)
- [x] evadex doctor transport speed — show estimated scans/sec for the resolved transport in doctor output (v3.30.1)
- [x] Watch command: sliding baseline — `evadex watch --baseline sliding --window N`; roll baseline forward after N clean runs (v3.30.1)
- [ ] `evadex export --format parquet` — dump audit log to Parquet for BI tool ingestion

### Detection coverage gaps (from recent evadex data)
- [ ] Morse code bypass — ~50% evasion rate; target <30%
- [ ] Regional digits bypass (Thai, Extended Arabic-Indic) — high bypass rate in northam tier
- [ ] Context injection technique — `evadex watch` now surfaces regressions, but context_injection variants still weak

## In progress
- (none)

## Recently completed
- [x] v3.29.1 — bridge profiles endpoint, C2 profile dropdown, profile init seeding
- [x] v3.29.0 — HTTP transport for siphon-cli (12x throughput vs CLI), bridge push-to-siphon, evadex → postgres via siphon-api
- [x] v3.28.2 — published to PyPI
- [x] v3.28.x — schedule, benchmark, report, export, diff, validate, status, cache commands
- [x] v3.30.1 — backlog sprint: compare --baseline auto, techniques --by-category, doctor scans/sec, watch sliding baseline
- [x] v3.30.0 — auto transport, SSE stream endpoint, regression watch command
