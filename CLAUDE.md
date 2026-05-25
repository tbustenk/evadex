# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`evadex` is a scanner-agnostic DLP (data loss prevention) evasion test suite. It takes a sensitive value (credit card, SSN, IBAN, AWS key, etc.), runs it through a battery of evasion techniques (unicode tricks, delimiter swaps, encoding, regional digits, splitting, morse, etc.), embeds each variant in plain text and in real document formats (DOCX/PDF/XLSX/...), submits everything to a configured DLP scanner via an adapter, and reports what slipped through. Python 3.11+, distributed on PyPI, CLI-first (`evadex = evadex.cli.app:main`).

Current version: **3.28.0** (see `pyproject.toml`; CHANGELOG is the user-facing release notes). Test suite: **1132 unit + 300 integration = 1432** total; **all 1132 unit tests pass**. CI runs `tests/unit` on Python 3.11 and 3.13 plus a Docker image-build step (`.github/workflows/ci.yml`).

## Common commands

Install dev environment:
```
pip install -e ".[dev]"
```

Test suite (CI runs `tests/unit` on Python 3.11 and 3.13):
```
pytest tests/unit -v
pytest tests/integration -v
pytest tests/unit/variants/test_unicode_encoding.py::test_zero_width_injection   # single test
```
`tests/conftest.py` has a session-scoped autouse fixture that calls `load_builtins()`, so adapter/generator decorators have fired in every test.

Lint (CI runs these but tolerates failures — `|| true`):
```
ruff check src/
ruff format --check src/
```

Docker (CI also builds both):
```
docker build -f deploy/Dockerfile -t evadex:latest .
docker build -f deploy/Dockerfile.bridge -t evadex-bridge:latest .   # FastAPI bridge on :8081
```

Run the CLI end-to-end against a scanner (the `siphon-cli`, `dlpscan-cli`, and `presidio` adapters all require the corresponding tool installed locally; `evadex doctor` reports environment health):
```
evadex quickstart                              # interactive first-run wizard, writes evadex.yaml
evadex scan --tier northam                     # default tier (NA + capital markets)
evadex scan --fast                             # high-bypass techniques only
evadex generate --formats xlsx,docx,pdf        # synthesize test files
evadex falsepos --count 500                    # measure scanner false-positive rate
evadex bridge --port 9191                      # start HTTP API for dashboards / Siphon-C2
```
CLI flags override `evadex.yaml`; `evadex.yaml` is auto-discovered from the working directory and is git-ignored.

## Architecture

### Plugin registry (most important pattern)

`src/evadex/core/registry.py` holds two module-level dicts populated by decorators: `@register_generator(name)` for variant generators and `@register_adapter(name)` for scanner adapters. `load_builtins()` is the only place that imports each implementation module — that's what triggers the decorators. **Adding a new generator or adapter requires editing `load_builtins()`**; otherwise the class is invisible.

Lookup is by name: `get_generator("unicode_encoding")`, `get_adapter("siphon-cli", config)`, `all_generators()`.

### Scan engine

`src/evadex/core/engine.py::Engine` is the async fan-out. For each `payload × variant_generator × variant × strategy`, it submits to `adapter.submit(payload, variant)` under an `asyncio.Semaphore(concurrency)`. Default concurrency is 32 (benchmark-validated; do not lower without a reason).

- **Streaming mode** (default, `--stream`): tasks created as variants are generated. Lower peak memory; `total_submitted` only known at the end.
- **Batch mode** (`--no-stream`): all `(payload, variant, strategy)` tuples enumerated first, then submitted. `total_submitted` is known up front for progress bars.
- A `technique_filter` set, when present (used by `--fast`), trims variants to a whitelist of technique names before submission.
- An `on_result(result, completed, total)` callback yields progress to the CLI; exceptions in it are swallowed.

### Two extension points

| Interface | Base class | Subclasses live in |
|---|---|---|
| Generate evasion variants of a value | `evadex.variants.base.BaseVariantGenerator` (yields `Variant`s from `generate(value)`) | `src/evadex/variants/` — one file per technique family |
| Submit a variant to a scanner | `evadex.adapters.base.BaseAdapter` (async `submit()`, plus optional `setup`/`teardown`/`health_check`) | `src/evadex/adapters/{siphon,siphon_cli,dlpscan,dlpscan_cli,presidio}/` |

Generators may set `applicable_categories: set[PayloadCategory]` to restrict themselves (e.g. `morse_code` only applies to numeric IDs); the engine skips inapplicable (gen, payload) pairs. `auto_applicable=False` excludes a generator from random/auto runs so it only fires when explicitly requested via `--technique-group` (used for barcode image transforms).

### Data model — `src/evadex/core/result.py`

Three dataclasses + one giant enum:

- `Payload(value, category: PayloadCategory, label)` — the secret to test.
- `Variant(value, generator, technique, transform_name, strategy)` — frozen; one obfuscated form. `strategy` is `"text"|"docx"|"pdf"|"xlsx"` and tells the adapter *how* to deliver it (plain-text submission vs embedded in a real document).
- `ScanResult(payload, variant, detected, raw_response, error, ...)` — adapter output. `severity` is `PASS` if detected (scanner caught the evasion — good), `FAIL` if not (bypass succeeded — bad), `ERROR` on adapter exception. **This polarity is inverted from typical pass/fail intuition — always read it as "did the scanner do its job".**
- `PayloadCategory` enum + `CATEGORY_TYPES` dict — ~500 entries covering global ID schemes. Categories are tagged `STRUCTURED` (deterministic regex-detectable like IBAN, SSN) or `HEURISTIC` (entropy/context-dependent like AWS_KEY, CLASSIFICATION).

When **adding a new payload category**: add to the enum, add to `CATEGORY_TYPES`, optionally add to one or more tiers in `payloads/tiers.py`, and optionally add a synthetic generator in `synthetic/` (with a validator in `synthetic/validators.py`) so `evadex generate` can synthesize fresh valid values.

### Tiers and payloads

`src/evadex/payloads/tiers.py` defines five frozensets of categories: `northam` (default, NA + capital markets, ~102 cats), `banking` (Canadian banking focus), `core` (~150), `regional` (~350 international), `full` (everything). Used by `scan`, `generate`, `quickstart`, `init`.

`src/evadex/payloads/builtins.py` is the curated list of *test fixtures* — real-looking but synthetic values with known categories. `src/evadex/synthetic/` is the *generators* used by `evadex generate` and `evadex falsepos` to produce arbitrary quantities of valid checksum-correct identifiers per region (CUSIP, SEDOL, ISIN with Luhn, LEI mod-97, etc.).

### File-format strategies

`src/evadex/generate/writers/` has one writer per output format (xlsx, docx, pdf, csv, txt, json, xml, sql, log, eml, parquet, sqlite, zip, 7z, mbox, png/jpg barcodes, warc, ics, msg, edm_json). The `--strategy` flag on `scan` chooses which document wrapper(s) variants get embedded in before submission, exercising the scanner's file-extraction pipeline rather than just its regex layer. **DOCX uses raw `lxml.etree.SubElement` instead of python-docx's ORM** for table rows/paragraphs (25× speedup, ~1.5s vs 37s for 1000 rows) — don't "fix" this back to the friendlier API. The paragraph-insertion path specifically uses `sect_pr.addprevious(p)` rather than `body.insert(idx, p)` — see v3.26.1 entry below for the O(n²) regression that fix resolved.

### Other subsystems

- `src/evadex/profiles/` — YAML profile system (`evadex profile run …`); built-in profiles under `profiles/builtins/*.yaml` (`banking-daily`, `canadian-ids`, `full-evasion`, `pci-dss`, `quick-check`).
- `src/evadex/bridge/` — FastAPI HTTP API (`/v1/evadex/run`, `/v1/evadex/metrics`, `/v1/evadex/generate`) so dashboards / Siphon-C2 / automation can drive evadex remotely. Optional extra: `pip install evadex[bridge]`.
- `src/evadex/feedback/` — reads the audit log to power smart evasion modes (`weighted` biases toward historically-bypassing techniques, `adversarial` restricts to ≤50% detection rate, `fast_mode` selects the top techniques).
- `src/evadex/reporters/` — `JsonReporter`, `HtmlReporter`, plus `compare_*` reporters for diffing two scan runs (used by `evadex compare` with trend arrows and verdict).
- `src/evadex/lsh/` — synthetic near-duplicate document generation for testing LSH-style document-similarity detection (the `evadex lsh` command).

### Windows-specific gotcha

`src/evadex/cli/app.py` wraps `sys.stdout`/`sys.stderr` in `TextIOWrapper(..., encoding="utf-8")` at import time because Rich's box-drawing characters crash on the default Windows cp1252 codec. Don't remove this — the development machine for this repo runs Windows 11.

## Conventions

- `VALID_TIERS`, `VALID_STRATEGIES`, `VALID_TOOLS`, etc. in `src/evadex/config.py` are the canonical option sets. The CLI builds Click choices from them — when you add a tier or strategy you update *both* the relevant module *and* `config.py`.
- The package version in `pyproject.toml` is the source of truth; `CHANGELOG.md` is kept current per release with `Added`/`Changed`/`Fixed`/`Tests`/`Verified` sections. Match that style if asked to add a changelog entry.
- Pytest is configured with `asyncio_mode = "auto"` (in `pyproject.toml`) — `async def test_…` works without `@pytest.mark.asyncio` decorators.

## Things in the working tree that are *not* part of the codebase

Several Python scripts at the repo root (`evadex_regressions.py`, `check_*.py`, `inspect_results.py`) are untracked local analysis scratch files — they are not part of the package and are not run by tests or CI. Ignore them unless the user references them by name.

## Recent additions and gotchas

These are behaviours added in recent point releases that aren't obvious from the code structure alone. Knowing them avoids re-deriving the same questions.

### Integration tests must run from a clean cwd (v3.26.2)
`tests/integration/conftest.py` installs an autouse fixture (`_isolate_cwd_from_repo_config`) that `monkeypatch.chdir(tmp_path)` for every integration test. The CLI auto-discovers `evadex.yaml` from `Path.cwd()` via `evadex.config.find_config`, so launching pytest from the repo root would otherwise leak the project's `tool: siphon-cli`, `min_detection_rate: 85`, and `output: results.json` into tests that mock `DlpscanCliAdapter` and read JSON from stdout. Tests that *do* want auto-discovery (e.g. `test_auto_discovery_loads_config`) write their own `evadex.yaml` inside a `runner.isolated_filesystem()` block, which chdir's again on top of the autouse chdir.

### `evadex.yaml` auto-discovery extends to `evadex falsepos` (v3.25.5)
`evadex falsepos` now mirrors `evadex scan`'s `evadex.yaml` auto-discovery — `--config <path>` flag, plus auto-load from the working directory when no `--config` is passed. CLI flags continue to override config values. Before v3.25.5, profile runs failed on the falsepos step whenever the scanner binary lived outside `PATH` (built-in profiles deliberately omit `exe:` because that path is machine-local). See `src/evadex/cli/commands/falsepos.py`.

### Profile `output.dir` is load-bearing (v3.25.6)
When a profile YAML specifies `output.dir`, `evadex profile run` translates it into `--output` flags on the underlying `evadex scan` and `evadex falsepos` invocations. Files land as `<dir>/<profile-name>_<UTC-timestamp>_scan.json` and `<dir>/<profile-name>_<UTC-timestamp>_falsepos.json`; the same UTC stamp is shared so paired runs stay grouped. `~` and `${ENV}` are expanded. `output.format` (when set) picks the extension; defaults to `json`. Directory is created if absent. If `scan.output` is set explicitly on the profile, it still wins — `output.dir` is the implicit fallback. The plumbing lives in `src/evadex/profiles/runner.py::_resolve_output_path` and `src/evadex/cli/commands/profile.py::profile_run`.

### `--save-as` does *not* persist `--fast` (documented in v3.25.6)
`--fast` is intentionally excluded from `scan_flags_to_profile_dict` in `src/evadex/profiles/runner.py`. It resolves to a machine-specific technique whitelist via `pick_fast_techniques(audit_log)` in `src/evadex/feedback/fast_mode.py`, so persisting it would freeze a stale, host-local snapshot. Operators who want a locked-in reduced technique set should use `--variant-group` (which **is** persisted).

### HTML report polish (v3.25.5)
`src/evadex/cli/commands/report.py` reads `importlib.metadata.version("evadex")` and stamps it into the footer. "Top Evasion Techniques" is labelled "(ranked by variants bypassed)" with a clarifying note that the Recommendations section ranks separately by evasion rate with a 10-sample minimum — the two lists may legitimately differ. `_bar()` no longer emits `class="bar-fill "` with a trailing empty class.

### Plugin registry protected against ruff autofix (v3.25.4)
Every side-effect import in `src/evadex/core/registry.py::load_builtins()` carries a `# noqa: F401` marker. An earlier `ruff check --fix` deleted all 21 imports thinking they were unused; that broke the entire generator/adapter registry and only `test_adapter_registered` caught the regression. **Never run `ruff check --fix` on `registry.py` without re-reading it first.**

### DOCX paragraph insertion uses `addprevious`, not positional `insert` (v3.26.1)
`_fast_add_paragraphs` in `src/evadex/generate/writers/docx_writer.py` builds `<w:p>` elements and attaches them to the body via `sect_pr.addprevious(p)`. An earlier implementation used `body.insert(insert_at + idx, p)`, which is O(idx) in lxml because the C layer walks children to reach the position — over ~68 k prose paragraphs (full `northam` × `count=1000`) the cumulative cost was O(K²) ≈ 145 s. `addprevious` is a O(1) libxml2 linked-list insert. The fix dropped end-to-end CLI generation for that workload from 147 s to ~10 s. Don't refactor back to positional `body.insert` without re-benchmarking.

### `output.retain_days` is enforced by `evadex profile run` (v3.26.1)
The profile runner now prunes old result files after every successful run. The helper lives at `evadex.profiles.runner.prune_old_results(profile)` and is also re-exported from `evadex.profiles`. It deletes `<profile-name>_*_scan.*` and `<profile-name>_*_falsepos.*` files in `output.dir` whose mtime is older than `retain_days` days. Behaviour is intentionally defensive: no-op when `retain_days` is unset / zero / negative / non-integer; no-op when `output.dir` is missing; individual unlink failures are logged and skipped (the run never fails because of pruning). The match pattern is glob-scoped to the profile name, so sibling profiles in the same directory are not touched.

### Credit-card synthetic generator uses reserved test BINs (v3.26.1)
`src/evadex/synthetic/credit_card.py::_PREFIXES` and the duplicate pool in `src/evadex/generate/generator.py::_CC_PREFIXES` are restricted to brand-published test BIN ranges: `4111` (Visa), `5500` (Mastercard), `3714` / `3782` (Amex), `6011` (Discover). Output is still Luhn-valid and still recognised by brand-detection regexes, but the BIN never matches an issued card — safe to ship inside bank synthetic-test corpora without account-collision risk. Keep the two prefix lists in sync.

## Open observations / known limitations

- **Built-in profiles never write `last_run`.** By design — they're read-only templates in `src/evadex/profiles/builtins/*.yaml`. To track runs you need a writable user copy via `evadex profile init` (or `profile create`).
- **`output.format` only meaningfully affects the file extension.** The underlying `scan` / `falsepos` commands always emit JSON; the `format` field is a hint passed through to the path constructor so future formats can be added without a code change.
