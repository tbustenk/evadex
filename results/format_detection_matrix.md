# File-format detection matrix vs Siphon @ 22f7971

**Date:** 2026-04-19
**Build under test:** `dlpscan-rs @ 22f7971`, `cargo build --release --features full`
**Active features:** `core, metrics, pdf, office, archives, data-formats, msg, barcode, async-support, tls`
**Submitter:** `siphon scan` CLI directly (HTTP `serve` subcommand still missing — fall-back path)
**Fixtures:** `evadex generate --tier banking --count 20 --evasion-rate 0.0` (count 5 for image formats, count 10 for `zip_nested`/`warc`)

## Plain-only matrix (the verification ask)

| Format | File size | Siphon matches | Status | Notes |
|---|---|---|---|---|
| `eml` | 48 KB | 2 673 | ✓ | mbox-style emails parse cleanly |
| `json` | 323 KB | 4 398 | ✓ | structured records, payload in named fields |
| `xml` | 725 KB | 11 241 | ✓ | ISO 20022 pain.001 elements parse cleanly |
| `sql` | 282 KB | 7 588 | ✓ | INSERT statements, schema fix from v3.10.1 holds up |
| `log` | 196 KB | 5 449 | ✓ | mixed plaintext / structured / JSON log lines |
| `sqlite` (`.db`) | 225 KB | 11 431 | ✓ | three-table banking schema, all rows reachable |
| `7z` | 12 KB | 3 099 | ✓ | LZMA2-compressed inner txt/csv/json all read |
| `mbox` | 983 KB | 16 712 | ✓ | RFC 2822 messages, base64 + 7bit transfer encodings both parse |
| `ics` | 1 000 KB | 14 723 | ✓ | RFC 5545 VEVENTs, payload in DESCRIPTION/SUMMARY/ATTENDEE |
| `warc` | 563 KB | 4 252 | ✓ | WARC 1.1 response records, payload in HTML bodies |
| `png` (after fix) | 56 KB | **12** (was 0) | ✓ | Encodes `embedded_text` instead of bare value — see "Fix applied" below |
| `jpg` (after fix) | 653 KB | **11** (was 0) | ✓ | Same fix; rxing decodes JPEG QR successfully |
| `parquet` | 188 KB | TIMEOUT (>5 min) | ✗ Siphon bug | `extract_parquet` hangs on any Parquet input — confirmed even with a 1 KB / 1-row file |
| `zip` | 24 KB | 0 | ✗ Siphon gap | Plain-ZIP extractor only walks `*.xml` entries (`extract_zip_archive` in `src/extractors.rs:613-630`) — txt/csv/json content unreached |
| `zip_nested` | 16 KB | 0 | ✗ Siphon gap | No nested-archive recursion at all; the inner `level1.zip` filename is the only signal that reaches the recogniser |

## Fix applied — barcode encoding

**Symptom.** PNG / JPG showed 0 matches even though Siphon reported `format_detected: "barcode"` and `extracted_text_length: 50` — meaning rxing successfully decoded the QR codes. Drilling in:

```text
$ siphon scan-text "5286464004833093"                  → 1 match (CC: MasterCard)
$ siphon scan-text "5286464004833093 5195163797792785"  → 0 matches
$ printf "5286464004833093\n5195163797792785\n" | siphon scan-text → 0 matches
```

A single bare 16-digit CC matches; multiple newline-separated CCs do not. rxing returns the multi-QR decoded text exactly as `\n`-separated bare digits, so Siphon's CC regex never fires.

**Workaround on the generator side.** Encode the entry's `embedded_text` (banking sentence containing the value with separators) into the barcode instead of just the bare value. After the fix:

```text
PNG plain    : 0 → 12 matches  (extracted_text 120 → 415 chars)
JPG plain    : 0 → 11 matches
PNG evasion  :     12 →  3 matches  (75 % evasion success)
JPG evasion  :     11 →  4 matches  (64 % evasion success)
```

The plain-PNG path now matches what `multi_barcode_png` was already doing (`value = e.embedded_text or e.variant_value` at `barcode_writer.py:392`). EAN-13 still encodes the bare numeric value because the symbology can only hold 12 digits — keyword context wouldn't survive the encode.

## Plain vs evasion (count = 20 each)

| Format | Plain | Evasion 0.5 | Δ | Interpretation |
|---|---|---|---|---|
| `eml` | 2 673 | 3 919 | +1 246 | Evasion variants embed extra context strings → more incidental matches |
| `json` | 4 398 | 4 591 | +193 | Marginal noise |
| `xml` | 11 241 | 11 233 | −8 | No real change |
| `sql` | 7 588 | 7 745 | +157 | Marginal noise |
| `log` | 5 449 | 5 271 | −178 | Slight evasion success |
| `sqlite` | 11 431 | 11 403 | −28 | No real change |
| `7z` | 3 099 | 3 057 | −42 | No real change |
| `mbox` | 16 712 | 17 490 | +778 | Extra context in evasion bodies |
| `ics` | 14 723 | 14 537 | −186 | Slight evasion success |
| `warc` | 4 252 | 8 369 | +4 117 | Evasion bodies double the captured-HTML text → many extra matches on context strings |
| `png` (fixed) | 12 | 3 | −9 | **75 % evasion success — the only format showing the expected per-text-unit drop** |
| `jpg` (fixed) | 11 | 4 | −7 | **64 % evasion success** |

**Caveat.** Aggregate match counts conflate "the same payload was detected" with "an unrelated keyword in the surrounding sentence triggered a recogniser." Document-format fixtures (`mbox`, `eml`, `warc`) tend to *gain* matches under evasion because the evasion variants come with longer context strings. The clean per-payload signal is only visible in image formats (one barcode = one isolated payload), where the drop from plain to evasion is the real evasion-effectiveness number.

## Action items

| Priority | Owner | Item |
|---|---|---|
| **P0** | dlpscan-rs | `extract_parquet` hangs on any Parquet input including a 1 KB single-row file. Likely an infinite loop in `RowIter::from_file_into` against this binding. Repro fixture: `test_output/format_verification/minimal.parquet` (3 columns, 1 row, 1 011 bytes). |
| **P1** | dlpscan-rs | CC recogniser misses adjacent / newline-separated bare 16-digit strings (`5286464004833093 5195163797792785` → 0 matches; each alone → 1 match). Same for `\n` separator. Affects barcode-decoded text, paginated logs, and any tokenised output. |
| **P2** | dlpscan-rs | Plain-ZIP text extraction (`extract_zip_archive`) only walks `*.xml`; txt/csv/json inside a non-OOXML ZIP are silently dropped. Architectural choice or oversight — worth confirming. |
| **P2** | dlpscan-rs | No recursive archive extraction — nested ZIPs / 7z / RAR yield only the outer file list, never inner contents. Add a depth-limited recursion (cap at 3, like most enterprise DLP). |
| **P3** | dlpscan-rs | `siphon serve` subcommand still missing — blocks evadex's HTTP-API tests (`evadex entropy`, `evadex edm`, `evadex lsh --transport http`). |
| Done | evadex | Barcode writer now encodes contextual text. Shipped in v3.12.1. |
