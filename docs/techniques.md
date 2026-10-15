# evadex evasion techniques

Every evasion technique in evadex follows a common anatomy. Each entry
below gives a **name** (the string the generator emits as
`variant.technique`), a **one-line description**, an **example**
showing an input and the bytes it produces, a **real-world context**
explaining when an attacker would use it, and a **fix** — what a
scanner should do to catch the technique reliably.

This document is consumed by `evadex list-techniques --verbose` so the
machine-readable view stays in sync with what's written here.

## Generator families

The generators below are the top-level `--technique-group` names you
pass on the CLI (`evadex scan --variant-group unicode_whitespace`, for
example). Each family contains one or more named techniques.

---

### `unicode_whitespace` — Unicode whitespace insertion

Replace ASCII space (and the implicit space between digit groups) with
a wide range of Unicode whitespace characters. To the human eye the
value is unchanged; to a scanner the byte sequence is different.

**When attackers use it:** copying a credit-card number into an email,
a chat message, or a document where the renderer collapses any
whitespace. Any scanner that tokenises on ASCII `\s` alone will miss
the value.

**The fix:** Unicode-normalise (NFKC) and strip all non-ASCII
whitespace characters before pattern matching. Python users can use
`unicodedata.normalize("NFKC", value)`.

#### Techniques

- **`unicode_nbsp`** — Groups separated by non-breaking space (U+00A0).
  Example: `4532 0151 1283 0366` → `4532 0151 1283 0366`.
- **`unicode_en_space`** — En-space (U+2002) between groups.
- **`unicode_em_space`** — Em-space (U+2003) between groups.
- **`unicode_thin_space`** — Thin space (U+2009) — often used in
  typography and frequently stripped by poorly-designed normalisers.
- **`unicode_figure_space`** — Figure space (U+2007), renders the same
  width as a digit so credit cards line up visually.
- **`unicode_narrow_nbsp`** — Narrow non-breaking space (U+202F).
- **`unicode_ideographic_space`** — Ideographic space (U+3000), common
  in CJK locales.
- **`unicode_mixed_spaces`** — Alternating NBSP and thin space between
  groups, so a lookup table keyed on a single character misses.
- **`zero_width_space`** — U+200B between every 2-3 characters. Zero
  visible impact but every byte-level match fails.
- **`zero_width_joiner` / `zero_width_non_joiner`** — U+200D / U+200C
  insertions. Same idea as ZWSP, different codepoint — attackers
  rotate through all three to bypass per-codepoint filters.

---

### `unicode_encoding` — Homoglyphs and variant digit forms

Substitute ASCII letters and digits with visually-identical characters
from another Unicode block (Cyrillic, Greek, fullwidth Latin,
mathematical alphanumerics).

**When attackers use it:** phishing emails, pasted secrets, and any
place where the renderer shows the same glyph regardless of codepoint.
Compliance tools that only check `[A-Za-z0-9]` patterns will miss
every homoglyph variant.

**The fix:** NFKC-normalise and then map Cyrillic/Greek/fullwidth
characters back to their ASCII equivalents (`unicodedata.normalize`
handles most cases; Cyrillic needs a dedicated confusables table —
Unicode TR39 provides one).

#### Techniques

- **`homoglyph_substitution`** — Cyrillic а/е/о/р/с/х for Latin
  a/e/o/p/c/x. Example: `john.smith@bank.com` →
  `jоhn.smith@bаnk.cоm` (Cyrillic о and а).
- **`fullwidth_digits`** — 0 → ０, 1 → １, etc. Renders the same but
  fails ASCII `\d` matches.
- **`mathematical_bold_digits`** — U+1D7CE..U+1D7D7. Same idea, rarer
  block, fewer normalisers catch it.
- **`mathematical_script_digits`** — U+1D7D8..U+1D7E1.
- **`circled_digits`** — ① ② ③ — valid digits to
  `str.isdigit`, but not `re.match(r'\d+')` in ASCII mode.

---

### `bidirectional` — Right-to-left override attacks

Insert Unicode bidirectional control characters (U+202E RLO, U+202D
LRO, U+2066..U+2069) so the rendered text differs from the stored
text.

**When attackers use it:** file names (`report‮txt.exe`),
chat messages, and any reviewer workflow where a human approves a
value that looks benign but stores as something else.

**The fix:** reject or flag any input containing bidirectional
override codepoints. DLP tools can simply log any value containing
U+202A..U+202E or U+2066..U+2069 as suspicious regardless of the
pattern match.

#### Techniques

- **`rlo_override`** — Wrap the value with RLO (U+202E), reversing
  display order. Example: `4532 1234 5678 9012` →
  `‮2109 8765 4321 2354`.
- **`bidi_wrap`** — LRI/PDI pair (U+2066 + U+2069) around the value,
  forcing a left-to-right embedding that confuses regex anchors.

---

### `soft_hyphen` — Invisible separator injection

Soft hyphens (U+00AD) are a "hint" character — most renderers hide
them entirely unless a line break is needed. A value with soft hyphens
between groups reads cleanly but doesn't match a fixed-digit regex.

**When attackers use it:** Word/Google Docs exports, HTML forms,
anywhere a copy-paste workflow preserves bytes but the display does
not.

**The fix:** strip U+00AD before matching, and log any strip that
removes more than two characters as an evasion signal.

#### Techniques

- **`soft_hyphen_group`** — Insert U+00AD between every group of four
  digits. Example: `4532015112830366` →
  `4532­0151­1283­0366`.

---

### `encoding` — Single-layer encodings

Encode the value in a common scheme (base64, rot13, hex, URL
percent-encoding, HTML entities). Many scanners scan plain text only.

**When attackers use it:** exfiltration through channels where
encoding is expected (base64 in JSON, hex in config files, HTML
entities in form posts).

**The fix:** heuristically detect and decode common encodings before
matching. Base64 is unambiguous (length ÷ 4, alphabet), hex is
unambiguous, rot13 requires entropy checks.

#### Techniques

- **`base64`** — `base64.b64encode(value.encode())`. Example:
  `4532015112830366` → `NDUzMjAxNTExMjgzMDM2Ng==`.
- **`rot13`** — Caesar cipher with a 13-character shift.
- **`url_double_encode`** — `%254532%2520...` — two levels of
  percent-encoding defeat naive single-decode.
- **`html_entity_hex`** — `&#x34;&#x35;...` for each character.
- **`html_entity_decimal`** — `&#52;&#53;...` — the decimal form.

---

### `encoding_chains` — Nested encodings

Two or more encodings stacked. Scanners that decode one layer deep
stop there and see opaque text.

**When attackers use it:** advanced exfil — embedding a rot13 string
inside a base64 blob inside a JSON value. Requires a two-layer decoder
to reveal.

**The fix:** decode iteratively until the output looks ASCII-text-like
or decoding fails, up to a bounded depth (3–4 layers). Log any string
that required ≥ 2 decodes to match.

#### Techniques

- **`base64_of_rot13`** — rot13 then base64. Single base64 decode
  yields rot13 gibberish; a rot13-aware decoder is needed.
- **`rot13_of_base64`** — base64 then rot13.

---

### `splitting` — Value splitting across boundaries

Break the value across line ends, table cells, HTML tags, or
delimiters so no single scanner window contains the full value.

**When attackers use it:** multi-line logs, CSV exports split across
columns, HTML documents where the value is wrapped by markup.

**The fix:** scan with a sliding window that joins across whitespace
and trivial separators; for HTML, strip tags before scanning.

#### Techniques

- **`newline_split`** — Insert `\n` every few characters.
- **`every_other_char_space`** — `4 5 3 2 0 1 5 1 ...`.

---

### `structural` — Structural manipulation

Reverse the string, zero-pad to an unexpected length, or split the
value into named fields in a JSON object.

**When attackers use it:** programmatic exfil where the structure is
controlled by the attacker (JSON API request, config file).

**The fix:** anchor patterns less strictly (allow variable lengths,
detect common rotations), and scan structured formats by value rather
than by raw text.

#### Techniques

- **`reversed`** — `value[::-1]`.
- **`zero_padded`** — Prefix with a few zeroes so length checks fail.

---

### `delimiter` — Non-standard delimiters

Swap the space, hyphen, or slash for another printable delimiter
(underscore, dot, pipe, etc.).

**When attackers use it:** log lines, URLs, any format where the
delimiter varies legitimately.

**The fix:** allow a broader character class for delimiters in
patterns — or normalise delimiters before matching.

#### Techniques

- **`hyphen_delimiter`**, **`underscore_delimiter`**,
  **`dot_delimiter`**, **`pipe_delimiter`** — each swaps the default
  delimiter for the named character.

---

### `leetspeak` — Substitution cipher (`0` for `O`, `1` for `I`, ...)

Classic substitution cipher. Well known, so most modern scanners have
a map — but legacy rule-based engines still miss it.

**When attackers use it:** older phishing campaigns, obfuscated
hostnames, informal exfil channels.

**The fix:** build a canonical leetspeak → ASCII normaliser and run it
before pattern matching.

#### Techniques

- **`leet_substitution`** — `password` → `p4ssw0rd`, etc.

---

### `regional_digits` — Non-Latin digit scripts

Arabic-Indic (٠-٩), Devanagari (०-९), Thai (๐-๙), Bengali (০-৯) digits
all satisfy `str.isdigit()` but not ASCII `\d` — so a structured
number in a non-Latin script is invisible to an ASCII-mode regex.

**When attackers use it:** locales where non-Latin digits are valid
(Egyptian bank statements often use Arabic-Indic numerals).

**The fix:** use `\d` in Unicode mode or, better, normalise the digit
script to ASCII via `unicodedata.decimal()` before matching.

#### Techniques

- **`regional_arabic_indic`** — Arabic-Indic digits.
- **`regional_devanagari`** — Devanagari digits.
- **`regional_thai`** — Thai digits.
- **`regional_bengali`** — Bengali digits.

---

### `morse_code` — Morse-encoded digits

Encode the digits/letters as Morse code with a separator between
characters.

**When attackers use it:** niche exfil channels and CTF-style
obfuscation; genuine DLP products rarely include morse in their
signature set.

**The fix:** detect high concentrations of `.` and `-` with consistent
group separators and decode heuristically.

#### Techniques

- **`morse_space_sep`** — Space between letters, slash between words.
- **`morse_dot_dash`** — Compact morse without delimiters.
- **`morse_slash_sep`** — Explicit `/` delimiter.

---

### `context_injection` — Plausible business prose wrapping

Wrap the sensitive value in realistic business sentences so the
surrounding text pushes the line past entropy or volume thresholds.

**When attackers use it:** slipping credentials into long documents
where bulk filters (size, entropy, known-text ratio) are the only
defence.

**The fix:** apply pattern matchers independently of volume filters;
do not let a low-entropy wrapper cancel a high-confidence match.

#### Techniques

- **`business_wrap`** — Wraps the value in a one-paragraph compliance
  blurb.
- **`code_comment_wrap`** — Wraps in a code comment with plausible
  file path context.

---

### `entropy_evasion` — Entropy-targeted padding

Extend or pad the sensitive value so its entropy falls below typical
"looks like a secret" thresholds (3.5–4.0 bits per char).

**When attackers use it:** secret-scanner evasion (e.g. GitHub push
protection) where detection is entropy-based rather than regex-based.

**The fix:** combine entropy with keyword proximity — a low-entropy
string near the word `password` is still a finding.

#### Techniques

- **`low_entropy_padding`** — Append a long repeating block to pull
  entropy down.
- **`dictionary_wrap`** — Surround the secret with high-frequency
  English words.

---

### `archive_evasion` — Container transport

Place the sensitive data inside a ZIP, 7z, or tar.gz archive that the
scanner does not extract.

**When attackers use it:** email attachments, file uploads, any
channel where archive extraction is configurable and may be off.

**The fix:** enable recursive archive extraction in scan configuration,
with a depth cap to avoid zip bombs.

#### Techniques

- **`zip_passthrough`** — Plain value inside a `.zip`.
- **`nested_zip`** — Value inside a zip inside a zip.
- **`sevenzip`** — Value inside a `.7z`.

---

### `barcode_evasion` — Image-encoded data

Render the sensitive value as a QR code, Code128, Data Matrix, or
PDF417 barcode. Without OCR and a barcode decoder, the scanner sees
only pixels.

**When attackers use it:** printed forms, mobile workflows, any
scenario where a device scans an image for human consumption.

**The fix:** enable image OCR + barcode decoding for content that
may contain printed forms (banking statements, invoices, shipping
labels).

#### Techniques

- **`qr_encoded`** — QR code of the value (highest payload capacity).
- **`code128_encoded`** — Code128 1D barcode.
- **`datamatrix_encoded`** — Data Matrix 2D barcode.
- **`pdf417_encoded`** — PDF417 barcode (common for driver licences).

---

## Seed bypass-probability estimates

Each generator family has an estimated bypass probability against a
generic DLP text scanner. See
[`src/evadex/feedback/seed_weights.py`](../src/evadex/feedback/seed_weights.py)
for the machine-readable table and rationale. These seed weights drive
`--evasion-mode weighted` on cold-start (no audit history) and are
blended 70 % empirical / 30 % seed once history is present.

---

## Technique index

Generated from the registry (`evadex list-techniques --verbose` reads the same generators). One row per technique name a generator can emit; the label is the `transform_name` recorded on each variant.

### `unicode_encoding` (10)

| technique | label |
|---|---|
| `fullwidth_digits` | ASCII digits replaced with fullwidth equivalents (U+FF10–FF19) |
| `homoglyph_substitution` | Visually similar Cyrillic/Greek characters substituted |
| `html_entity_decimal` | HTML decimal entities for every character |
| `html_entity_hex` | HTML hex entities for every character |
| `url_percent_encoding_digits` | Only digits percent-encoded |
| `url_percent_encoding_full` | All characters percent-encoded |
| `url_percent_encoding_mixed` | Alternating percent-encoding |
| `zero_width_zwj` | Zero-width ZWJ between every character |
| `zero_width_zwnj` | Zero-width ZWNJ between every character |
| `zero_width_zwsp` | Zero-width ZWSP between every character |

### `delimiter` (9)

| technique | label |
|---|---|
| `dot_delimiter` | Groups separated by dots |
| `excessive_delimiter` | Doubled hyphen delimiters |
| `hyphen_delimiter` | Groups separated by hyphens |
| `mixed_delimiter` | Alternating space and hyphen delimiters |
| `newline_delimiter` | Groups separated by newlines |
| `no_delimiter` | All delimiters removed |
| `slash_delimiter` | Groups separated by slashes |
| `space_delimiter` | Groups separated by spaces |
| `tab_delimiter` | Groups separated by tabs |

### `splitting` (10)

| technique | label |
|---|---|
| `css_comment_injection` | CSS comment injected between every character |
| `fr_ca_prefix_noise` | French Canadian noise text prepended |
| `fr_ca_suffix_noise` | French Canadian noise text appended |
| `html_comment_injection` | HTML comment injected between every character |
| `json_field_split` | Value split across two JSON fields |
| `mid_line_break` | Line break injected at midpoint |
| `prefix_noise` | Noise text prepended |
| `suffix_noise` | Noise text appended |
| `whitespace_padding` | Space inserted between every character |
| `xml_tag_injection` | Value wrapped in XML data tag |

### `leetspeak` (3)

| technique | label |
|---|---|
| `leet_aggressive` | Aggressive leetspeak substitution |
| `leet_minimal` | Minimal leetspeak substitution (a→4, e→3, i→1, o→0, s→5) |
| `leet_moderate` | Moderate leetspeak substitution |

### `regional_digits` (12)

| technique | label |
|---|---|
| `regional_arabic_indic` | Digits replaced with Arabic-Indic digits |
| `regional_bengali` | Digits replaced with Bengali digits |
| `regional_devanagari` | Digits replaced with Devanagari digits |
| `regional_extended_arabic_indic` | Digits replaced with Extended Arabic-Indic digits (Urdu/Persian) |
| `regional_khmer` | Digits replaced with Khmer digits |
| `regional_mixed_alternating` | Alternating Arabic-Indic and Devanagari digits |
| `regional_mixed_partial` | First half Thai digits, second half Bengali digits |
| `regional_mongolian` | Digits replaced with Mongolian digits |
| `regional_myanmar` | Digits replaced with Myanmar digits |
| `regional_nko` | Digits replaced with NKo digits |
| `regional_thai` | Digits replaced with Thai digits |
| `regional_tibetan` | Digits replaced with Tibetan digits |

### `structural` (13)

| technique | label |
|---|---|
| `left_pad_spaces` | 10 spaces prepended |
| `left_pad_zeros` | 5 zeros prepended |
| `lowercase` | Entire value lowercased |
| `mixed_case` | Alternating upper/lower case |
| `noise_embedded` | Value surrounded by noise characters |
| `overlapping_prefix` | Noise prefix prepended |
| `partial_first_half` | First half of value only (tests partial detection) |
| `partial_last_half` | Last half of value only |
| `partial_minus_one` | Last character removed |
| `repeated` | Value repeated twice with space separator |
| `right_pad_spaces` | 10 spaces appended |
| `right_pad_zeros` | 5 zeros appended |
| `uppercase` | Entire value uppercased |

### `encoding` (20)

| technique | label |
|---|---|
| `base32_hex_alphabet` | Value base32-encoded with extended hex alphabet (0–9, A–V) |
| `base32_lowercase` | Value base32-encoded, lowercase alphabet |
| `base32_no_padding` | Value base32-encoded, padding stripped |
| `base32_standard` | Value base32-encoded (standard alphabet A–Z, 2–7) |
| `base64_double` | Value base64-encoded twice |
| `base64_mime_linebreaks` | Base64 with MIME-style line breaks every 76 characters |
| `base64_no_padding` | Value base64-encoded, padding stripped |
| `base64_partial` | First half literal, second half base64-encoded |
| `base64_standard` | Value base64-encoded (standard alphabet) |
| `double_url_encoding` | Double percent-encoding (%XX → %25XX) |
| `double_url_encoding_digits` | Double percent-encoding on digits only |
| `hex_0x_integer` | Value encoded as a single 0x-prefixed hex integer |
| `hex_escaped_bytes` | Value as \xNN escape sequences per byte |
| `hex_lowercase` | Value hex-encoded, lowercase (e.g. 34313131…) |
| `hex_spaced_bytes` | Value as space-separated hex bytes (hex dump style) |
| `hex_uppercase` | Value hex-encoded, uppercase |
| `reversed_full` | Entire value reversed |
| `reversed_group_order` | 4-character groups reversed in order |
| `reversed_within_groups` | Digits reversed within each 4-character group |
| `rot13` | ROT13 applied to all alphabetic characters |

### `encoding_chains` (7)

| technique | label |
|---|---|
| `base64_of_base64` | double base64 of value |
| `base64_of_hex` | base64 of hex encoding of value |
| `base64_of_rot13` | base64 of ROT13 of value |
| `base64_of_rot13_of_hex` | base64 of ROT13 of hex of value (triple chain) |
| `hex_of_base64` | hex of base64 of value |
| `rot13_of_base64` | ROT13 of base64 of value |
| `url_of_base64` | URL encoding of base64 of value |

### `context_injection` (20)

| technique | label |
|---|---|
| `audit_note` | Value referenced in an audit note |
| `confidential_header` | Value under a confidential document header |
| `email_body` | Value embedded inside an email body |
| `email_header_body` | Value in an email with headers and body |
| `fr_ca_audit_note` | Value referenced in a French Canadian audit note |
| `fr_ca_confidential_header` | Value under a French Canadian confidential document header |
| `fr_ca_email_body` | Value embedded inside a French Canadian email body |
| `fr_ca_email_header_body` | Value in a French Canadian email with headers and body |
| `fr_ca_json_record` | Value inside a French Canadian JSON-like transaction record |
| `fr_ca_log_line` | Value embedded in a French Canadian log line |
| `fr_ca_multiline_form` | Value in a French Canadian multiline form-style block |
| `fr_ca_pii_notice` | Value in a French Canadian personal information notice |
| `fr_ca_sentence_payment_request` | Value in French Canadian payment request sentence |
| `fr_ca_sentence_reference` | Value in French Canadian confidential reference sentence |
| `json_record` | Value inside a JSON-like transaction record |
| `log_line` | Value embedded in a log line |
| `multiline_form` | Value in a multiline form-style block |
| `sentence_payment_request` | Value in payment request sentence |
| `sentence_reference` | Value in confidential reference sentence |
| `xml_record` | Value inside an XML-like record element |

### `unicode_whitespace` (8)

| technique | label |
|---|---|
| `unicode_em_space` | Groups separated by em-space (U+2003) |
| `unicode_en_space` | Groups separated by en-space (U+2002) |
| `unicode_figure_space` | Groups separated by figure space (U+2007) — same width as a digit |
| `unicode_ideographic_space` | Groups separated by ideographic space (U+3000) |
| `unicode_mixed_spaces` | Alternating non-breaking space and thin space between groups |
| `unicode_narrow_nbsp` | Groups separated by narrow no-break space (U+202F) |
| `unicode_nbsp` | Groups separated by non-breaking space (U+00A0) |
| `unicode_thin_space` | Groups separated by thin space (U+2009) |

### `bidirectional` (6)

| technique | label |
|---|---|
| `alm_between_chars` | Arabic letter mark ('\u061c', U+061C) injected between every character |
| `lro_wrap` | Value wrapped in LTR override ('\u202d'...'\u202c') |
| `mid_rlo_inject` | RTL override injected at midpoint — second half rendered reversed |
| `rle_embed` | Value inside RTL embedding ('\u202b'...'\u202c') |
| `rli_isolate` | Value wrapped in RTL isolate ('\u2067'...'\u2069') — Unicode 6.3+ bidi |
| `rlo_wrap` | Value wrapped in RTL override ('\u202e'...'\u202c') — display order reversed |

### `soft_hyphen` (6)

| technique | label |
|---|---|
| `mixed_shy_wj` | Alternating soft hyphen and word joiner between every character |
| `shy_2char_boundaries` | Soft hyphen (U+00AD) at every 2-char boundary |
| `shy_between_every_char` | Soft hyphen (U+00AD) inserted between every character |
| `shy_group_boundaries` | Soft hyphen (U+00AD) at every 4-char group boundary — invisible in rendering |
| `wj_between_every_char` | Word joiner (U+2060) inserted between every character |
| `wj_group_boundaries` | Word joiner (U+2060) at every 4-char group boundary — inhibits line breaks invisibly |

### `morse_code` (4)

| technique | label |
|---|---|
| `morse_newline_sep` | Digits encoded as Morse; each symbol on its own line |
| `morse_no_sep` | Digits encoded as Morse; symbols concatenated with no separator |
| `morse_slash_sep` | Digits encoded as Morse; symbols separated by forward slashes |
| `morse_space_sep` | Digits encoded as Morse; symbols separated by spaces |

### `entropy_evasion` (6)

| technique | label |
|---|---|
| `entropy_comment` | Insert ";c"; delimiter comment mid-token to break tokenization |
| `entropy_concat` | Split into "part1" + "part2" concatenated literals |
| `entropy_encode` | Base64-encode the whole value (double encoding) |
| `entropy_low_mix` | Append low-entropy padding to dilute per-char entropy |
| `entropy_space` | Insert spaces every 4 chars to fall below min token length |
| `entropy_split` | Split high-entropy token across newlines every 15 chars |

### `barcode_evasion` (4)

| technique | label |
|---|---|
| `barcode_embed` | Embed barcode inside a larger document image |
| `barcode_noise` | Overlay salt-and-pepper noise on the rendered barcode |
| `barcode_rotate` | Rotate the barcode ~15° off-axis |
| `barcode_split` | Split value across two barcodes on the same image |

### `archive_evasion` (4)

| technique | label |
|---|---|
| `archive_deep_nest` | Bury payload 5 levels deep in nested archives |
| `archive_double_extension` | Rename archive with a misleading double extension |
| `archive_mixed_formats` | Stack different container formats (ZIP > DOCX > CSV) |
| `archive_password` | Wrap archive in a password-protected ZIP (weak password) |

### `capital_markets` (16)

| technique | label |
|---|---|
| `bloomberg_suffix` | Bloomberg market-sector suffix appended |
| `country_prefix_noise` | Bracketed ISO country-code prefix prepended |
| `grouped_spaces_3` | Space every 3 chars (CUSIP print grouping) |
| `hyphen_at_third` | Hyphen inserted at one-third position |
| `lowercase_all` | All characters lowercased |
| `mixed_case_alt` | Alternating case starting from second char |
| `noisy_prefix_reference` | Generic 'REFERENCE: ' prefix to trigger context match without real context |
| `noisy_suffix_prospectus` | Trailing parenthetical to shift span offset |
| `padded_spaces` | Single space on each side |
| `reversed` | Value reversed character-by-character |
| `slash_before_check` | Forward-slash inserted before check digit |
| `space_after_prefix` | Space inserted after 2-char prefix (country code / LOU prefix) |
| `space_before_check` | Space inserted before check digit |
| `truncate_check` | Check digit removed |
| `zwsp_block4` | Zero-width no-break space every 4 chars |
| `zwsp_mid` | Zero-width space inserted at midpoint |

