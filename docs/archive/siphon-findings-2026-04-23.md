# Siphon findings — 2026-04-23

Findings surfaced during evadex v3.20.2 reliability testing against Siphon.

- **Siphon**: `siphon 2.1.0` @ commit `cfb7def` (`crates/siphon-core`)
- **evadex**: v3.20.2
- **Tester**: Kenzie Butts
- **Scope**: DLP scanner detection & false-positive behaviour, text-strategy scans only. All repros use `siphon scan-text --format json` with stdin, UTF-8 encoding.

---

## Summary

| # | Finding | Severity | File |
|--:|---|---|---|
| 1 | Quebec HC pattern never fires; ISIN shadows it on the same 12-char shape | **High** — blocks RAMQ detection entirely | `patterns/mod.rs:2172–2182` |
| 2 | `Chile RUN/RUT` is `context_required: false` and fires on Canadian RAMQ digit layouts | **High** — dominant source of cross-category FPs | `patterns/mod.rs:4139–4146` |
| 3 | MRN keyword list leaks `maladie` / `médical` into banking docs → false MRN hits on any 6–10 digit run | **Medium** — systemic FP risk in French corpora | `context/keywords.rs` (MRN section) |
| 4 | USA SSN context gate does not fire on natural phrasings (`"my SSN is 123-45-6789"`, `"Social Security Number: …"`, …) | **High** — SSN is effectively never detected in scan-text | `context/keywords.rs` (USA SSN section) + gate logic |
| 5 | SSN regex does no area-code validation (reserved 000 / 666 / 900–999 would pass if the gate fired) | **Low** (blocked by #4) | `patterns/mod.rs:1529–1565` |
| 6 | Quebec HC regex does no structural validation (invalid birth months / days pass) | **Low** (blocked by #1) | `patterns/mod.rs:2172–2182` |

Findings 1 and 4 are the two important ones — both prevent a whole category from being detected. The rest are FP-quality issues.

---

## F1 — Quebec HC never fires; ISIN wins the race

**File**: `crates/siphon-core/src/patterns/mod.rs:2172–2182`

Quebec HC pattern:
```rust
PatternDef {
    category: "North America - Canada",
    sub_category: "Quebec HC",
    regex: r"\b[A-Z]{4}\d{8}\b",
    case_insensitive: false,
    specificity: 0.55,
    context_required: true,
},
```

ISIN pattern (at `patterns/mod.rs:3956` approx):
```rust
PatternDef {
    // category: "Financial - Securities",
    sub_category: "ISIN",
    regex: r"\b[A-Z]{2}[A-Z0-9]{9}[0-9]\b",   // 12 chars
    specificity: 0.75,
    context_required: false,
}
```

Both patterns target **12-character tokens**. ISIN's shape is a superset of Quebec HC's (`[A-Z]{4}\d{8}` is a valid match for `[A-Z]{2}[A-Z0-9]{9}[0-9]`). ISIN has higher specificity (0.75 vs 0.55) and no context gate. Result: **Quebec HC is never reachable**.

### Reproduction
```bash
for t in \
    "Quebec HC TREM85120123." \
    "RAMQ number TREM85120123." \
    "carte assurance maladie TREM85120123" \
    "TREM85120123 RAMQ"
do
  printf '%s' "$t" | siphon scan-text --format json
done
```

Every input above returns a single match: `"sub_category": "ISIN"` with confidence 0.75. None return `"Quebec HC"`.

### Impact
evadex can generate any valid-shape RAMQ and embed it in a Quebec-HC-keyword-rich sentence, and the scanner will always misclassify it as ISIN. Production impact: RAMQ PII gets tagged as securities data, or worse, an ISIN rule that routes to a different team fires on patient data.

### Suggested fix options
- Raise Quebec HC specificity above ISIN when RAMQ / Quebec HC / `assurance maladie` keywords are nearby, OR
- Add Luhn-minus-check-digit structural validation to ISIN (real ISINs have a mod-10 check digit — `[A-Z]{4}\d{8}` values never satisfy it), OR
- Reorder evaluation so context-gated patterns that *have* their context win ties against ungated ones at equal or lower specificity.

---

## F2 — Chile RUN/RUT fires on Canadian RAMQ values without context

**File**: `crates/siphon-core/src/patterns/mod.rs:4139–4146`

```rust
PatternDef {
    category: "Latin America - Chile",
    sub_category: "Chile RUN/RUT",
    regex: r"\b\d{1,2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]?[\dkK]\b",
    specificity: 0.65,
    context_required: false,
},
```

### Reproduction
```bash
printf 'KMFS 3198 2006' | siphon scan-text --format json
printf 'DGKQ 7715 1826' | siphon scan-text --format json
printf 'Quebec HC RAMQ: KMFS 3198 2006 on file.' | siphon scan-text --format json
```

All three return `"sub_category": "Chile RUN/RUT"` with `has_context: false`. The digit portion `3198 2006` parses as `\d{1,2}[sep]\d{3}[sep]\d{3}[sep][\dkK]` after `\b` anchoring mid-token.

### Impact
This fired on 7/50 Canadian RAMQ false-positive values during evadex testing — every `[A-Z]{4} \d{4} \d{4}` RAMQ with the right digit alignment misclassifies as a Chilean tax ID. At 0.65 specificity with no context gate, the blast radius is any document containing such digit groupings.

### Suggested fix
Chile RUN/RUT should be `context_required: true`. Keywords like `rut`, `run`, `chile`, `tax id` + country selectors. The specificity 0.65 implies meaningful signal, but without a context gate the regex pattern is too loose for a middle-specificity tier.

---

## F3 — MRN keyword list leaks `maladie` / `médical` / `patient`

**File**: `crates/siphon-core/src/context/keywords.rs` (Medical Record Number section)

MRN regex is deliberately broad (`\b\d{6,10}\b`, `patterns/mod.rs:841–848`) and relies 100 % on context gating. The French medical keywords in the gate bleed into Canadian banking documents that mention health-related context even loosely:

### Reproduction
```bash
printf "Le dossier médical du patient contient le numéro 12345678." | siphon scan-text --format json
# -> [{"sub_category": "Medical Record Number", "text": "12345678", "has_context": true}]

printf "Patient MRN 12345678 admitted yesterday." | siphon scan-text --format json
# -> MRN match

printf "Numéro d'assurance maladie RAMQ du patient : ZDBX 3543 0818." | siphon scan-text --format json
# -> [{"sub_category": "Japan Health Insurance", "text": "3543 0818"}]   ← collateral on digit group
```

### Impact
French banking documents mentioning health-card context (statements for RAMQ auto-deduct, HR records that reference medical leave, insurance claims with benefits amounts) risk getting every 6–10 digit number re-classified as MRN. On the scan we ran, medical-context wraps around RAMQ digit portions produced MRN matches on arbitrary digit blocks.

### Suggested fix
Require **two independent** medical keywords for MRN (not any single one), or tighten to narrow-sense MRN keywords only (`mrn`, `medical record number`, `chart number`, `epic id`, `patient id`) and drop broad ones like `maladie` / `patient` on their own. `maladie` in French literally means "illness" — it appears in drug disclaimers, insurance FAQs, HR leave policies, every patient-facing banking communication.

---

## F4 — SSN context gate does not fire on natural phrasings (high-impact)

**Files**: `context/keywords.rs` (USA SSN section) plus gate-logic in the scanner.

USA SSN regex is correct (`patterns/mod.rs:1561`). The pattern is `context_required: true` and keyword-gated. But no natural phrasing I tested triggers the gate:

### Reproduction
```bash
for t in \
    "My social security number is 123-45-6789." \
    "Employee SSN: 123-45-6789 on file." \
    "SSN 123-45-6789" \
    "The patient SSN is 123-45-6789" \
    "social security 123-45-6789" \
    "Social Security Number: 123-45-6789"
do
  printf '%s' "$t" | siphon scan-text --format json
done
```

Every single input returns `[]`. No SSN match. No other category match either.

### Impact
SSN is effectively undetectable in text scans today. This is the single highest-impact finding — the scanner's evadex score for SSN is whatever the baseline seed value happens to be + noise, but SSN won't fire on real documents either.

### Hypothesis to check first
The keyword gate may be requiring exact whole-phrase matches rather than token-substring matches, or it may be case-sensitive on a list that was registered with specific casing. `test-pattern` the actual keyword entries against the reproductions above — pick one that *should* match (`"my social security number is"` is about as canonical as it gets) and trace why the gate returns false.

### Also worth checking
- Whether `collapse_padding` or another normalisation is mangling the `123-45-6789` token before the regex runs.
- Whether the SSN pattern's `\b` anchor is interacting with the separator class in a way that requires the separator to be exactly `-` (and not a fuzzy lookalike).

---

## F5 — SSN regex does no area-code validation

**File**: `crates/siphon-core/src/patterns/mod.rs:1561`

```rust
regex: r"\b\d{3}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]\d{2}[-.\s/\\_\x{2013}\x{2014}\x{00a0}]\d{4}\b",
```

The SSA never issues numbers with area codes 000, 666, or 900–999. The regex accepts all of them.

### Reproduction
End-to-end reproduction is blocked by **F4** (gate never fires, so we can't observe whether reserved values still match). Static inspection of the regex confirms no area-code exclusion.

### Impact
Low while F4 is active (the gate is the limiting factor). Once F4 is fixed, the scanner will flag every reserved-area-code SSN-shaped string — this is where evadex false-positive generation lives.

### Suggested fix
Replace the first `\d{3}` with an exclusion pattern: `(?!000|666|9\d\d)\d{3}`. The SSA area-code exclusions are stable and publicly documented. Adding them eliminates a FP class without needing a secondary validator.

---

## F6 — Quebec HC regex does no structural validation

**File**: `crates/siphon-core/src/patterns/mod.rs:2172–2182`

```rust
regex: r"\b[A-Z]{4}\d{8}\b",
```

RAMQ structure: 3-letter surname prefix + 1-letter given-name prefix + YYMMDDSS digits, where **months 01–12 encode males and 51–62 encode females**. Any other month value (00, 13–50, 63–99) is structurally invalid. The current regex accepts all of them.

### Reproduction
Blocked by **F1** (Quebec HC never reachable because ISIN wins). Static inspection confirms no structural validation.

### Suggested fix
Once F1 is resolved, tighten the regex:
```rust
regex: r"\b[A-Z]{4}\d{2}(?:0[1-9]|1[0-2]|5[1-9]|6[0-2])\d{2}\d{2}\b",
```
That character-class rewrite excludes ~80 % of shape-valid but structurally-invalid values at the regex layer. Check-digit validation (RAMQ uses mod-10 on positions 5-11, see Régie de l'assurance maladie du Québec reference) would reject the remainder.

---

## Priority order for fixing

Suggested order:
1. **F4** — SSN context gate. Highest impact, whole category disabled.
2. **F1** — Quebec HC vs ISIN priority. Whole category unreachable.
3. **F2** — Chile RUN context gate. Largest FP source in the banking tier.
4. **F3** — MRN keyword tightening. Moderate FP source in French docs.
5. **F5**, **F6** — Structural validation. Blocked by F4 / F1 respectively.

Happy to re-run the evadex sweep once any of these land and report deltas. The evadex repro corpus is deterministic (`--seed 42`), so before/after comparisons are directly meaningful.
