"""Fix suggestions for evasion techniques.

Each unique technique that produced a bypass gets one actionable suggestion
describing what to add to the scanner's normalisation pipeline to close the gap.

Technique names are taken directly from the generator classes in evadex/variants/.
"""
from __future__ import annotations

from typing import NamedTuple

from evadex.core.result import ScanResult, SeverityLevel


class Suggestion(NamedTuple):
    technique: str
    generator: str
    description: str
    suggested_fix: str


# Map from technique name → (description, suggested_fix).
# Descriptions explain *what happened*; suggested_fix is the concrete remediation.
_TECHNIQUE_FIXES: dict[str, tuple[str, str]] = {
    # ── Unicode encoding ──────────────────────────────────────────────────────
    "zero_width_zwsp": (
        "Sensitive values bypassed detection via Zero Width Space (U+200B) inserted between digits",
        "Strip U+200B (Zero Width Space) from input in the normalisation pipeline before pattern matching",
    ),
    "zero_width_zwnj": (
        "Sensitive values bypassed detection via Zero Width Non-Joiner (U+200C) inserted between digits",
        "Strip U+200C (Zero Width Non-Joiner) from input in the normalisation pipeline",
    ),
    "zero_width_zwj": (
        "Sensitive values bypassed detection via Zero Width Joiner (U+200D) inserted between digits",
        "Strip U+200D (Zero Width Joiner) from input in the normalisation pipeline",
    ),
    "homoglyph_substitution": (
        "Sensitive values bypassed detection by substituting ASCII digits/letters with visually"
        " identical Unicode characters from Cyrillic, Greek, or other scripts",
        "Add Cyrillic/Greek lookalikes to homoglyph normalisation map: О→0, З→3, ο→0, Α→A, Ζ→Z."
        " Apply NFKC normalisation then a homoglyph table lookup before scanning",
    ),
    "fullwidth_digits": (
        "Sensitive values bypassed detection using fullwidth Unicode digit/letter forms (０–９, Ａ–Ｚ)",
        "Apply NFKC normalisation to collapse fullwidth characters to their ASCII equivalents before scanning",
    ),
    "html_entity_decimal": (
        "Sensitive values bypassed detection via decimal HTML entities (&#52;&#53;&#51;&#50;…)",
        "Add an HTML entity decode pass (html.unescape) to the normalisation pipeline",
    ),
    "html_entity_hex": (
        "Sensitive values bypassed detection via hexadecimal HTML entities (&#x34;&#x35;…)",
        "Add an HTML entity decode pass (html.unescape) to the normalisation pipeline",
    ),
    "url_percent_encoding_full": (
        "Sensitive values bypassed detection via full percent-encoding of every character (%36%34%35%32…)",
        "Add a URL-decode pass (urllib.parse.unquote) to the normalisation pipeline before pattern matching",
    ),
    "url_percent_encoding_digits": (
        "Sensitive values bypassed detection via percent-encoding of digit characters only",
        "Add a URL-decode pass (urllib.parse.unquote) to the normalisation pipeline before pattern matching",
    ),
    "url_percent_encoding_mixed": (
        "Sensitive values bypassed detection via mixed percent-encoding (some digits encoded, others literal)",
        "Add a URL-decode pass (urllib.parse.unquote) to the normalisation pipeline before pattern matching",
    ),
    "mixed_normalization": (
        "Sensitive values bypassed detection via mixed Unicode normalisation forms (NFD/NFC/NFKD/NFKC)",
        "Apply NFKC normalisation to all input before pattern matching to canonicalise mixed Unicode forms",
    ),
    "normalization_nfkc": (
        "Sensitive values bypassed detection via NFKC-incompatible Unicode compositions",
        "Apply NFKC normalisation to all input before pattern matching",
    ),
    "normalization_nfd": (
        "Sensitive values bypassed detection via NFD decomposed Unicode characters",
        "Apply NFKC normalisation to all input before pattern matching to recompose decomposed characters",
    ),
    # ── Encoding obfuscation ──────────────────────────────────────────────────
    "base64_standard": (
        "Sensitive values bypassed detection after standard base64 encoding",
        "Add a base64 decode pass to the normalisation pipeline; scan the decoded content",
    ),
    "base64_no_padding": (
        "Sensitive values bypassed detection after base64 encoding without padding characters",
        "Add a base64 decode pass with padding tolerance (pad to multiple of 4) to the normalisation pipeline",
    ),
    "base64_partial": (
        "Sensitive values bypassed detection after partial base64 encoding (first half literal,"
        " second half base64-encoded)",
        "Add a partial-base64 decode pass: detect and decode any base64-looking substring"
        " (match /[A-Za-z0-9+/]{12,}={0,2}/) within the input before scanning",
    ),
    "base64_double": (
        "Sensitive values bypassed detection after double base64 encoding",
        "Apply base64 decode twice before pattern matching to handle double-encoded values",
    ),
    "rot13_of_base64": (
        "Sensitive values bypassed detection after ROT13 applied to a base64-encoded value"
        " (decode ROT13 first, then base64 to recover the original)",
        "Add a two-stage decode pass: apply ROT13 first, then base64-decode the result."
        " Implement as: base64.b64decode(codecs.decode(value, 'rot_13'))",
    ),
    "url_of_base64": (
        "Sensitive values bypassed detection after URL-encoding applied to a base64-encoded value"
        " (percent-decode first, then base64 to recover the original)",
        "Add a two-stage decode pass: URL-decode (urllib.parse.unquote) first, then base64-decode"
        " the result. Apply in the normalisation pipeline before pattern matching.",
    ),
    "base64_of_rot13": (
        "Sensitive values bypassed detection after base64 encoding applied to a ROT13-encoded value"
        " (base64-decode first, then ROT13 to recover the original)",
        "Add a two-stage decode pass: base64-decode first, then apply ROT13."
        " Implement as: codecs.decode(base64.b64decode(value).decode('ascii'), 'rot_13')",
    ),
    "base64_of_hex": (
        "Sensitive values bypassed detection after base64 encoding applied to a hex-encoded value"
        " (base64-decode first, then hex-decode to recover the original)",
        "Add a two-stage decode pass: base64-decode first, then hex-decode the result."
        " Implement as: bytes.fromhex(base64.b64decode(value).decode('ascii'))",
    ),
    "hex_of_base64": (
        "Sensitive values bypassed detection after hex encoding applied to a base64-encoded value"
        " (hex-decode first, then base64-decode to recover the original)",
        "Add a two-stage decode pass: hex-decode first, then base64-decode the result."
        " Implement as: base64.b64decode(bytes.fromhex(value))",
    ),
    "base64_of_base64": (
        "Sensitive values bypassed detection after two rounds of base64 encoding",
        "Apply base64 decode twice before pattern matching to handle double-encoded values",
    ),
    "base64_of_rot13_of_hex": (
        "Sensitive values bypassed detection after a triple encoding chain:"
        " hex → ROT13 → base64 (decode all three in reverse order to recover the original)",
        "Add a three-stage decode pass: base64-decode, then ROT13, then hex-decode."
        " Implement as: bytes.fromhex(codecs.decode(base64.b64decode(value).decode(), 'rot_13'))",
    ),
    "base32_standard": (
        "Sensitive values bypassed detection after base32 encoding",
        "Add a base32 decode pass to the normalisation pipeline",
    ),
    "base32_no_padding": (
        "Sensitive values bypassed detection after base32 encoding without padding",
        "Add a base32 decode pass with padding tolerance to the normalisation pipeline",
    ),
    "base32_lowercase": (
        "Sensitive values bypassed detection after lowercase base32 encoding",
        "Add a case-insensitive base32 decode pass to the normalisation pipeline",
    ),
    "base32_hex_alphabet": (
        "Sensitive values bypassed detection after base32hex (extended hex) encoding",
        "Add a base32hex decode pass to the normalisation pipeline",
    ),
    "hex_lowercase": (
        "Sensitive values bypassed detection after lowercase hex encoding (e.g. 34353332…)",
        "Add a hex decode pass (match /(?:[0-9a-f]{2})+/) to the normalisation pipeline",
    ),
    "hex_uppercase": (
        "Sensitive values bypassed detection after uppercase hex encoding",
        "Add a case-insensitive hex decode pass to the normalisation pipeline",
    ),
    "hex_escaped_bytes": (
        r"Sensitive values bypassed detection via \xNN escape sequence encoding (e.g. \x34\x35\x33\x32)",
        r"Add a \xNN escape sequence decode pass: replace /\\x([0-9a-fA-F]{2})/ with chr(int(m,16))"
        " in the normalisation pipeline",
    ),
    "hex_0x_integer": (
        "Sensitive values bypassed detection via 0x-prefixed hex integer encoding",
        "Add a 0x-prefixed hex integer decode pass to the normalisation pipeline",
    ),
    "hex_spaced_bytes": (
        "Sensitive values bypassed detection via space-separated hex bytes (e.g. 34 35 33 32)",
        "Add a spaced hex byte decode pass (match /(?:[0-9a-fA-F]{2} )+/) to the normalisation pipeline",
    ),
    "rot13": (
        "Sensitive values bypassed detection after ROT13 encoding",
        "Add a ROT13 decode pass to the normalisation pipeline",
    ),
    "reversed_full": (
        "Sensitive values bypassed detection after full string reversal",
        "Add a string-reversal decode pass to the normalisation pipeline",
    ),
    "reversed_within_groups": (
        "Sensitive values bypassed detection after within-delimiter-group digit reversal",
        "Add a within-group reversal decode pass to the normalisation pipeline",
    ),
    "reversed_group_order": (
        "Sensitive values bypassed detection after reversing the order of delimiter-separated groups",
        "Add a group-order reversal decode pass to the normalisation pipeline",
    ),
    "double_url_encoding": (
        "Sensitive values bypassed detection via double URL-encoding (%2534 for %34…)",
        "Apply URL-decode twice before pattern matching to handle double-encoded values",
    ),
    # ── Delimiter variation ───────────────────────────────────────────────────
    "no_delimiter": (
        "Sensitive values bypassed detection when all delimiters were removed",
        "Ensure patterns match values with no delimiter"
        " (e.g. use \\d{3}[-. ]?\\d{2}[-. ]?\\d{4} style optional separators)",
    ),
    "space_delimiter": (
        "Sensitive values bypassed detection when space was used as a delimiter",
        "Ensure patterns allow space as a delimiter between digit groups",
    ),
    "hyphen_delimiter": (
        "Sensitive values bypassed detection when hyphens replaced the standard delimiter",
        "Ensure patterns allow hyphen as a delimiter between digit groups",
    ),
    "dot_delimiter": (
        "Sensitive values bypassed detection when dot was used as a delimiter",
        "Ensure patterns allow dot as a delimiter between digit groups",
    ),
    "slash_delimiter": (
        "Sensitive values bypassed detection when forward slash was used as a delimiter",
        "Ensure patterns allow forward slash as a delimiter between digit groups",
    ),
    "tab_delimiter": (
        "Sensitive values bypassed detection when tab character was used as a delimiter",
        "Ensure patterns allow tab (\\t) as a delimiter between digit groups, or normalise"
        " tabs to spaces before scanning",
    ),
    "newline_delimiter": (
        "Sensitive values bypassed detection when newline was used as a delimiter between digit groups",
        "Normalise newlines to spaces before pattern matching, or extend patterns to allow \\n"
        " as a delimiter between digit groups",
    ),
    "mixed_delimiter": (
        "Sensitive values bypassed detection when different delimiter characters were mixed"
        " between digit groups",
        "Use a flexible delimiter character class in patterns: [-. \\t/\\\\_ \\u2013\\u2014\\u00a0]?"
        " to match any common separator",
    ),
    "excessive_delimiter": (
        "Sensitive values bypassed detection via excessive/repeated delimiters between digit groups",
        "Collapse repeated delimiters before pattern matching:"
        " normalise /[\\-\\s]{2,}/ to a single separator",
    ),
    "plus_delimiter": (
        "Sensitive values bypassed detection when plus sign was used as a delimiter",
        "Ensure patterns allow plus sign as a delimiter between digit groups",
    ),
    "comma_delimiter": (
        "Sensitive values bypassed detection when comma was used as a delimiter",
        "Ensure patterns allow comma as a delimiter between digit groups",
    ),
    "underscore_delimiter": (
        "Sensitive values bypassed detection when underscore was used as a delimiter",
        "Ensure patterns allow underscore as a delimiter between digit groups",
    ),
    # ── Invisible separators (soft hyphen / word joiner) ─────────────────────
    "shy_group_boundaries": (
        "Sensitive values bypassed detection via soft hyphens (U+00AD) injected at digit group boundaries",
        "Strip U+00AD (Soft Hyphen) from input in the normalisation pipeline before pattern matching",
    ),
    "shy_2char_boundaries": (
        "Sensitive values bypassed detection via soft hyphens (U+00AD) injected every 2 characters",
        "Strip U+00AD (Soft Hyphen) from input in the normalisation pipeline",
    ),
    "shy_between_every_char": (
        "Sensitive values bypassed detection via soft hyphens (U+00AD) inserted between every character",
        "Strip U+00AD (Soft Hyphen) from input in the normalisation pipeline",
    ),
    "wj_group_boundaries": (
        "Sensitive values bypassed detection via Word Joiners (U+2060) injected at digit group boundaries",
        "Strip U+2060 (Word Joiner) from input in the normalisation pipeline",
    ),
    "wj_between_every_char": (
        "Sensitive values bypassed detection via Word Joiners (U+2060) inserted between every character",
        "Strip U+2060 (Word Joiner) from input in the normalisation pipeline",
    ),
    "mixed_shy_wj": (
        "Sensitive values bypassed detection via alternating soft hyphens (U+00AD) and word joiners (U+2060)",
        "Strip both U+00AD (Soft Hyphen) and U+2060 (Word Joiner) from input in the normalisation pipeline",
    ),
    # ── Bidirectional text ────────────────────────────────────────────────────
    "rlo_wrap": (
        "Sensitive values bypassed detection when wrapped in Unicode Right-to-Left Override (U+202E)",
        "Strip Unicode bidi control characters"
        " (U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) from input before scanning",
    ),
    "lro_wrap": (
        "Sensitive values bypassed detection when wrapped in Unicode Left-to-Right Override (U+202D)",
        "Strip Unicode bidi control characters"
        " (U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) from input before scanning",
    ),
    "rle_embed": (
        "Sensitive values bypassed detection when embedded in a Right-to-Left Embedding (U+202B)",
        "Strip Unicode bidi control characters from input before scanning",
    ),
    "mid_rlo_inject": (
        "Sensitive values bypassed detection with a Right-to-Left Override (U+202E) injected mid-value",
        "Strip Unicode bidi control characters from input before scanning",
    ),
    "rli_isolate": (
        "Sensitive values bypassed detection via Right-to-Left Isolate (U+2067)",
        "Strip Unicode bidi control characters from input before scanning",
    ),
    "alm_between_chars": (
        "Sensitive values bypassed detection via Arabic Letter Mark (U+061C) inserted between characters",
        "Strip U+061C (Arabic Letter Mark) and other Unicode formatting characters"
        " (category Cf) from input before scanning",
    ),
    # ── Unicode whitespace ────────────────────────────────────────────────────
    "unicode_nbsp": (
        "Sensitive values bypassed detection when spaces were replaced with non-breaking spaces (U+00A0)",
        "Normalise U+00A0 (NBSP) to regular ASCII space before pattern matching",
    ),
    "unicode_en_space": (
        "Sensitive values bypassed detection when spaces were replaced with en-spaces (U+2002)",
        "Normalise Unicode space variants (U+2002, U+2003, U+2009, etc.) to regular ASCII space"
        " before pattern matching",
    ),
    "unicode_em_space": (
        "Sensitive values bypassed detection when spaces were replaced with em-spaces (U+2003)",
        "Normalise Unicode space variants to regular ASCII space before pattern matching",
    ),
    "unicode_thin_space": (
        "Sensitive values bypassed detection when spaces were replaced with thin spaces (U+2009)",
        "Normalise Unicode space variants to regular ASCII space before pattern matching",
    ),
    "unicode_figure_space": (
        "Sensitive values bypassed detection when spaces were replaced with figure spaces (U+2007)",
        "Normalise Unicode space variants to regular ASCII space before pattern matching",
    ),
    "unicode_narrow_nbsp": (
        "Sensitive values bypassed detection when spaces were replaced with narrow no-break spaces (U+202F)",
        "Normalise U+202F (Narrow No-Break Space) and other Unicode space variants to regular ASCII space",
    ),
    "unicode_ideographic_space": (
        "Sensitive values bypassed detection when spaces were replaced with ideographic spaces (U+3000)",
        "Normalise U+3000 (Ideographic Space) to regular ASCII space before pattern matching",
    ),
    "unicode_mixed_spaces": (
        "Sensitive values bypassed detection via mixed Unicode whitespace character variants",
        "Normalise all Unicode whitespace variants to regular ASCII space before pattern matching"
        r" (apply re.sub(r'[\s\u00A0\u2000-\u200A\u202F\u3000]+', ' ', text))",
    ),
    # ── Morse code ───────────────────────────────────────────────────────────
    "morse_space_sep": (
        "Sensitive values bypassed detection after morse code encoding with space-separated symbols"
        " (e.g. '....' '-.-.' for digits)",
        "Add a morse code decode pass to the normalisation pipeline;"
        " decode International Morse sequences back to digits before scanning",
    ),
    "morse_slash_sep": (
        "Sensitive values bypassed detection after morse code encoding with slash-separated symbols"
        " (e.g. '..../-.-.')",
        "Add a morse code decode pass to the normalisation pipeline;"
        " handle slash-separated morse word boundaries",
    ),
    "morse_no_sep": (
        "Sensitive values bypassed detection after concatenated morse code encoding"
        " (no separator between symbols)",
        "Add a morse code decode pass that handles ambiguous concatenated sequences",
    ),
    "morse_newline_sep": (
        "Sensitive values bypassed detection after morse code encoding with newline-separated symbols",
        "Add a morse code decode pass to the normalisation pipeline;"
        " strip newlines and decode morse sequences before scanning",
    ),
    # ── Leetspeak ─────────────────────────────────────────────────────────────
    "minimal_leet": (
        "Sensitive values bypassed detection via minimal leetspeak digit substitution"
        " (0→O, 1→I/L, 3→E, etc.)",
        "Add a leetspeak normalisation pass: replace 0→O, 1→I/L, 3→E, 4→A, 5→S, 7→T"
        " before pattern matching",
    ),
    # ── Context injection ─────────────────────────────────────────────────────
    "email_body": (
        "Sensitive values bypassed detection when embedded inside an email body template",
        "Scan the complete message body for sensitive patterns, not just structured/named fields",
    ),
    "email_header_body": (
        "Sensitive values bypassed detection when embedded across email headers and body",
        "Scan the full email text (headers + body) for sensitive patterns,"
        " not just the structured envelope fields",
    ),
    "json_record": (
        "Sensitive values bypassed detection when embedded as a JSON field value",
        "Extract and scan individual JSON field values, not just the raw JSON string",
    ),
    "xml_record": (
        "Sensitive values bypassed detection when embedded inside XML element content",
        "Strip XML markup and scan element text content individually",
    ),
    "csv_record": (
        "Sensitive values bypassed detection when embedded as a CSV field",
        "Scan each CSV field value individually after parsing",
    ),
    "log_line": (
        "Sensitive values bypassed detection when embedded inside a structured log line",
        "Scan log field values individually; strip log prefixes (timestamps, log levels)"
        " before pattern matching",
    ),
    "multiline_form": (
        "Sensitive values bypassed detection when embedded in a multiline form-like text block",
        "Scan each line and each field value independently within multiline input",
    ),
    "audit_note": (
        "Sensitive values bypassed detection when embedded inside an audit note template",
        "Scan the full text body of audit notes for sensitive patterns,"
        " not just structured fields",
    ),
    "sentence_payment_request": (
        "Sensitive values bypassed detection when embedded in a payment request sentence",
        "Scan free-form sentence content for sensitive patterns,"
        " not just structured/labelled fields",
    ),
    "sentence_reference": (
        "Sensitive values bypassed detection when embedded in a reference sentence",
        "Scan free-form sentence content for sensitive patterns,"
        " not just structured/labelled fields",
    ),
    "confidential_header": (
        "Sensitive values bypassed detection when embedded under a confidential header block",
        "Scan content below confidential headers; do not skip sections based on header labels",
    ),
    # ── Splitting ─────────────────────────────────────────────────────────────
    "mid_line_break": (
        "Sensitive values bypassed detection when split across two lines with a mid-value line break",
        "Normalise line breaks within candidate token spans before pattern matching,"
        " or use multi-line regex mode with newline ignored inside digit groups",
    ),
    "html_comment_injection": (
        "Sensitive values bypassed detection when split by an injected HTML comment (<!-- -->)",
        "Strip HTML comment tags (<!-- ... -->) before scanning, then scan the resulting text",
    ),
    "css_comment_injection": (
        "Sensitive values bypassed detection when split by an injected CSS comment (/* */)",
        "Strip CSS comment tokens (/* ... */) before scanning, then scan the resulting text",
    ),
    "prefix_noise": (
        "Sensitive values bypassed detection when arbitrary noise was prepended to the value",
        "Use patterns that do not require a clean left boundary;"
        " match the sensitive pattern anywhere within the token",
    ),
    "suffix_noise": (
        "Sensitive values bypassed detection when arbitrary noise was appended to the value",
        "Use patterns that do not require a clean right boundary;"
        " match the sensitive pattern anywhere within the token",
    ),
    "json_field_split": (
        "Sensitive values bypassed detection when split across multiple adjacent JSON string fields",
        "Reassemble adjacent string values across JSON field boundaries before scanning",
    ),
    "whitespace_padding": (
        "Sensitive values bypassed detection when padded with leading and trailing whitespace",
        "Trim leading/trailing whitespace from candidate token spans before pattern matching",
    ),
    "xml_tag_injection": (
        "Sensitive values bypassed detection when split by an injected XML tag mid-value",
        "Strip XML tags from text before scanning, or scan the concatenated text content"
        " of adjacent XML text nodes",
    ),
    # ── Structural ────────────────────────────────────────────────────────────
    "left_pad_spaces": (
        "Sensitive values bypassed detection when padded with leading spaces",
        "Trim leading whitespace from candidate token spans before pattern matching",
    ),
    "right_pad_spaces": (
        "Sensitive values bypassed detection when padded with trailing spaces",
        "Trim trailing whitespace from candidate token spans before pattern matching",
    ),
    "left_pad_zeros": (
        "Sensitive values bypassed detection when padded with leading zeros",
        "Ensure patterns tolerate leading zeros before digit groups"
        " (e.g. \\b0*\\d{16}\\b for credit card numbers)",
    ),
    "right_pad_zeros": (
        "Sensitive values bypassed detection when padded with trailing zeros",
        "Ensure patterns tolerate trailing zeros after digit groups",
    ),
    "noise_embedded": (
        "Sensitive values bypassed detection when surrounded by noise characters"
        " (e.g. XXXXXXXXXX4532015112830366XXXXXXXXXX)",
        "Use patterns that anchor on the sensitive value itself rather than the surrounding context;"
        " avoid requiring clean boundaries when the value is embedded in noise",
    ),
    "overlapping_prefix": (
        "Sensitive values bypassed detection when prefixed with a word boundary-breaking string"
        " (e.g. test_value_4532015112830366)",
        "Ensure patterns allow the sensitive value to be preceded by underscore or alphanumeric"
        " characters, or strip common prefix patterns (test_, id_, ref_) before scanning",
    ),
    "partial_first_half": (
        "Sensitive values bypassed detection when only the first half of the value was present",
        "If partial values are a concern, add a fuzzy/partial-match rule for truncated patterns"
        " and flag them at lower confidence",
    ),
    "partial_last_half": (
        "Sensitive values bypassed detection when only the last half of the value was present",
        "If partial values are a concern, add a fuzzy/partial-match rule for truncated patterns"
        " and flag them at lower confidence",
    ),
    "partial_minus_one": (
        "Sensitive values bypassed detection when one digit was removed from the value",
        "Add a fuzzy-length variant to patterns that tolerates ±1 digit"
        " (e.g. allow 15–17 digits for a 16-digit credit card)",
    ),
    "repeated": (
        "Sensitive values bypassed detection when the value was repeated twice in sequence",
        "Ensure patterns match within a sliding window;"
        " a doubled value should still be detected",
    ),
}

# Prefix-based fallbacks for technique families.
# Each entry: (prefix, description_fragment, suggested_fix)
# Listed in order of specificity (longer prefixes first to avoid partial matches).
_PREFIX_FIXES: list[tuple[str, str, str]] = [
    (
        "regional_mixed",
        "mixed Unicode digit scripts",
        "Normalise all Unicode digit scripts to ASCII digits before pattern matching:"
        " apply unicodedata.digit(ch, None) or NFKD normalisation across the full input",
    ),
    (
        "regional_",
        "Unicode regional digit script",
        "Normalise Unicode regional digit scripts to ASCII digits before pattern matching:"
        " apply unicodedata.digit(ch, None) for each character, or use NFKD normalisation",
    ),
    (
        "morse_",
        "morse code encoding",
        "Add a morse code decode pass to the normalisation pipeline;"
        " decode International Morse sequences back to digits before scanning",
    ),
    (
        "unicode_",
        "Unicode whitespace variant",
        "Normalise Unicode whitespace variants to regular ASCII space before pattern matching"
        r" (apply re.sub(r'[\u00A0\u2000-\u200A\u202F\u3000]+', ' ', text))",
    ),
    (
        "base64_",
        "base64 encoding variant",
        "Add a base64 decode pass to the normalisation pipeline; scan the decoded content",
    ),
    (
        "base32_",
        "base32 encoding variant",
        "Add a base32 decode pass to the normalisation pipeline",
    ),
    (
        "hex_",
        "hex encoding variant",
        "Add a hex decode pass to the normalisation pipeline",
    ),
]


def _lookup_fix(technique: str) -> tuple[str, str]:
    """Return (description, suggested_fix) for a technique name."""
    if technique in _TECHNIQUE_FIXES:
        return _TECHNIQUE_FIXES[technique]

    for prefix, frag, fix in _PREFIX_FIXES:
        if technique.startswith(prefix):
            return (
                f"Sensitive values bypassed detection via {frag} (technique: {technique})",
                fix,
            )

    # Generic fallback for techniques not in either map
    readable = technique.replace("_", " ")
    return (
        f"Sensitive values bypassed detection via {readable} technique",
        f"Investigate the '{technique}' evasion technique and add a corresponding"
        f" decode/normalise pass to the input pipeline",
    )


def get_suggestions(results: list[ScanResult]) -> list[Suggestion]:
    """Return one Suggestion per unique technique that produced evasions, in encounter order."""
    seen: dict[str, Suggestion] = {}

    for r in results:
        if r.severity != SeverityLevel.FAIL:
            continue
        tech = r.variant.technique
        if tech not in seen:
            desc, fix = _lookup_fix(tech)
            seen[tech] = Suggestion(
                technique=tech,
                generator=r.variant.generator,
                description=desc,
                suggested_fix=fix,
            )

    return list(seen.values())
