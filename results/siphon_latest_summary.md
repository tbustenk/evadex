# Siphon Evasion Summary — d8eaf09 (2026-05-04)

**Scanner commit:** `d8eaf09`  
**Tier:** northam (Canada + US + capital markets)  
**Scan date:** 2026-05-04  
**Variants tested:** 21,693 across 102 categories, 136 techniques

---

## Overall Detection

| Metric | Value | Delta vs prior run |
|---|---|---|
| Detection rate | 31.7% | ▼ −0.3pp |
| Variants evaded (pass) | 6,875 | +66 |
| Variants blocked (fail) | 14,818 | — |
| False positive rate | 14.5% | ▼ −1.1pp (prev: 15.6%) |

**Verdict: REGRESSED** — detection down 0.3pp. The false positive rate improved by 1.1pp. The `ca_on_drivers` drop (−8.8pp) and `cins_num` drop (−8.1pp) warrant investigation before the next production release. The `leet_moderate` technique regressed to 100% evasion (was 0% in prior run), suggesting a normalization rule was removed or broken.

---

## Category Changes (≥3pp delta)

### Improved
| Category | Prev | Now | Delta |
|---|---|---|---|
| ca_sk_health | 27.8% | 35.2% | +7.4pp |
| ca_nb_health | 28.7% | 35.2% | +6.5pp |
| ca_business_number | 60.2% | 64.8% | +4.6pp |
| sepa_ref | 53.1% | 57.1% | +4.0pp |
| dob | 51.2% | 54.5% | +3.3pp |

### Regressed
| Category | Prev | Now | Delta |
|---|---|---|---|
| ca_on_drivers | 42.1% | 33.3% | −8.8pp |
| cins_num | 34.1% | 26.0% | −8.1pp |
| ca_bc_drivers | 53.5% | 45.7% | −7.8pp |
| ca_nexus | 40.4% | 33.3% | −7.1pp |
| us_npi | 35.4% | 29.3% | −6.1pp |

---

## Top 5 Strongest Categories (lowest evasion)

| Category | Evasion Rate |
|---|---|
| swift_bic | 18.9% |
| email | 19.6% |
| card_track2 | 19.8% |
| masked_pan | 22.2% |
| iban | 23.0% |

---

## Top 5 Weakest Categories (highest evasion)

| Category | Evasion Rate |
|---|---|
| employee_id | 97.6% |
| us_passport_card | 97.1% |
| dti_ratio | 97.0% |
| ltv_ratio | 97.0% |
| reuters_ric | 96.9% |

---

## Capital Markets Coverage

| Identifier | Evasion Rate | Status |
|---|---|---|
| CUSIP | 24.8% | Detected (Securities Identifiers) |
| SEDOL | 32.4% | Detected (Securities Identifiers) |
| FIGI | 37.8% | Detected (Securities Identifiers) |
| LEI | 38.1% | Detected (Securities Identifiers) |
| CINS | 74.0% | Detected — high evasion, patterns brittle |
| VALOR | 55.7% | Detected — moderate evasion |
| WKN | 90.1% | Detected — very high evasion |
| MiFID TX ID | 95.6% | Detected but near-total evasion — pattern too weak |
| ISIN | N/A | Not included in northam-tier scan |
| FIX ClOrdID | N/A | **No siphon rule** — gap documented in evadex v3.25.3 |

**Key gap:** FIX Protocol ClOrdID (tag 11) has no siphon detection rule. Payloads added in evadex v3.25.3 to track this gap going forward. MiFID TX ID detection is functionally useless at 4.4% block rate.

---

## Top Bypassing Evasion Techniques

| Technique | Evasion Rate |
|---|---|
| base64_urlsafe | 100.0% |
| leet_minimal | 100.0% |
| leet_moderate | 100.0% |
| morse_newline_sep | 100.0% |
| homoglyph_substitution | 96.3% |

`leet_moderate` regressed to 100% (was 0% in prior run) — a siphon rule that previously caught leet substitutions appears to have been removed or broken.

---

## Top 5 Fix Recommendations

1. **Investigate leet_moderate regression** — previously blocked, now 100% evaded. Likely a normalization rule removal in d8eaf09.
2. **Add FIX ClOrdID rule to siphon** — no pattern exists for FIX tag 11 order identifiers, a common field in capital markets order flow logs.
3. **Strengthen MiFID TX ID pattern** — 95.6% evasion renders the current rule effectively useless against minimal obfuscation.
4. **Investigate ca_on_drivers / ca_bc_drivers drops** — 7–9pp regressions on Canadian provincial driver's licence detection.
5. **Improve CINS/WKN/VALOR rules** — CINS at 74% and WKN at 90% evasion indicate Securities Identifier patterns are brittle.

---

## Files

| File | Path |
|---|---|
| Scan results | `results/scans/siphon_latest.json` |
| False positive results | `results/falsepos/siphon_latest_fp.json` |
| Comparison (vs prior run) | `results/comparisons/comparison_latest.json` |
| Full HTML report | `results/siphon_latest_report.html` |
