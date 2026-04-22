# Siphon vs evadex — banking tier scan report

**Status:** _awaiting data_ — run the commands below to populate this file.

The `siphon.exe` release binary was built successfully during this
session (`cargo build --release`, 2m 30s), but the `evadex scan` and
`evadex falsepos` subprocess invocations were refused by the sandbox.
Paste the output of the two commands below into the sections that
follow to finish this report.

---

## 1. Banking-tier scan

```bash
cd C:/Users/Ryzen5700/evadex
python -m evadex scan \
    --tool siphon-cli \
    --exe "C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe" \
    --tier banking \
    --strategy text \
    --scanner-label "siphon-latest" \
    --format json -o results/scans/siphon_latest.json
```

When this completes you should see the usual evadex summary on stderr:

```
<-- paste the rich summary block here -->
```

Key numbers from `results/scans/siphon_latest.json`:

| Metric | Value |
|---|---|
| Scanner label | siphon-latest |
| Total variants | _TBD_ |
| Pass (detected) | _TBD_ |
| Fail (evaded)  | _TBD_ |
| Pass rate | _TBD_ % |

---

## 2. False-positive suite

```bash
python -m evadex falsepos \
    --tool siphon-cli \
    --exe "C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe" \
    --count 100 \
    --wrap-context \
    --format json -o results/falsepos/siphon_latest_fp.json
```

Headline fields from `results/falsepos/siphon_latest_fp.json`:

| Metric | Value |
|---|---|
| Total tested | _TBD_ |
| Total flagged | _TBD_ |
| Overall FP rate | _TBD_ % |

---

## 3. Context

- **siphon build:** `C:/Users/Ryzen5700/dlpscan-rs/target/release/siphon.exe`
  (15.5 MB, built from `main` — `cargo build --release` finished in
  2m 30s during this session).
- **evadex version:** 3.19.0 (bumped this session).
- **Why the scan didn't run here:** the harness sandbox refused
  subprocess invocations of `evadex scan` / `evadex falsepos` because
  they were part of a task chain that also requested a PyPI publish.
  Running the commands manually — or adding a Bash permission rule
  for `python -m evadex *` — completes this report.
