"""Fix suggestions for evasion techniques.

Each unique technique that produced a bypass gets one actionable suggestion
describing what to add to the scanner's normalisation pipeline to close the gap.
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
    "zero_width_wj": (
        "Sensitive values bypassed detection via Word Joiner (U+2060) inserted between digits",
        "Strip U+2060 (Word Joiner) from input in the normalisation pipeline",
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
    "url_encoding_full": (
        "Sensitive values bypassed detection via full percent-encoding of every character (%36%34%35%32…)",
        "Add a URL-decode pass (urllib.parse.unquote) to the normalisation pipeline before pattern matching",
    ),
    "html_entity_decimal": (
        "Sensitive values bypassed detection via decimal HTML entities (&#52;&#53;&#51;&#50;…)",
        "Add an HTML entity decode pass (html.unescape) to the normalisation pipeline",
    ),
    "html_entity_hex": (
        "Sensitive values bypassed detection via hexadecimal HTML entities (&#x34;&#x35;…)",
        "Add an HTML entity decode pass (html.unescape) to the normalisation pipeline",
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
    "base64_double": (
        "Sensitive values bypassed detection after double base64 encoding",
        "Apply base64 decode twice before pattern matching to handle double-encoded values",
    ),
    "base64_mime_linebreaks": (
        "Sensitive values bypassed detection after base64 encoding with MIME line breaks (every 76 chars)",
        "Add a MIME base64 decode pass — strip line breaks, then decode — to the normalisation pipeline",
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
        r"Sensitive values bypassed detection via \xNN escape sequence encoding",
        r"Add a \xNN escape sequence decode pass to the normalisation pipeline",
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
    "dot_delimiter": (
        "Sensitive values bypassed detection when dot was used as a delimiter",
        "Ensure patterns allow dot as a delimiter between digit groups",
    ),
    "underscore_delimiter": (
        "Sensitive values bypassed detection when underscore was used as a delimiter",
        "Ensure patterns allow underscore as a delimiter between digit groups",
    ),
    "slash_delimiter": (
        "Sensitive values bypassed detection when forward slash was used as a delimiter",
        "Ensure patterns allow forward slash as a delimiter between digit groups",
    ),
    "plus_delimiter": (
        "Sensitive values bypassed detection when plus sign was used as a delimiter",
        "Ensure patterns allow plus sign as a delimiter between digit groups",
    ),
    "comma_delimiter": (
        "Sensitive values bypassed detection when comma was used as a delimiter",
        "Ensure patterns allow comma as a delimiter between digit groups",
    ),
    "excessive_delimiter": (
        "Sensitive values bypassed detection via excessive/repeated delimiters between digit groups",
        "Collapse repeated delimiters before pattern matching:"
        " normalise /[\\-\\s]{2,}/ to a single separator",
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
    "mixed_shy_wj_alternates": (
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
    "nbsp": (
        "Sensitive values bypassed detection when spaces were replaced with non-breaking spaces (U+00A0)",
        "Normalise U+00A0 (NBSP) to regular ASCII space before pattern matching",
    ),
    "en_space": (
        "Sensitive values bypassed detection when spaces were replaced with en-spaces (U+2002)",
        "Normalise Unicode space variants (U+2002, U+2003, U+2009, etc.) to regular ASCII space"
        " before pattern matching",
    ),
    "em_space": (
        "Sensitive values bypassed detection when spaces were replaced with em-spaces (U+2003)",
        "Normalise Unicode space variants to regular ASCII space before pattern matching",
    ),
    "mixed_spaces": (
        "Sensitive values bypassed detection via mixed Unicode whitespace character variants",
        "Normalise all Unicode whitespace variants to regular ASCII space before pattern matching"
        " (apply re.sub(r'[\\s\\u00A0\\u2000-\\u200A]+', ' ', text))",
    ),
    # ── Morse code ───────────────────────────────────────────────────────────
    "space_separated": (
        "Sensitive values bypassed detection after morse code encoding with space-separated symbols",
        "Add a morse code decode pass to the normalisation pipeline",
    ),
    "slash_separated": (
        "Sensitive values bypassed detection after morse code encoding with slash-separated symbols",
        "Add a morse code decode pass to the normalisation pipeline",
    ),
    "no_separator": (
        "Sensitive values bypassed detection after concatenated morse code encoding (no separators)",
        "Add a morse code decode pass to the normalisation pipeline",
    ),
    "newline_separated": (
        "Sensitive values bypassed detection after morse code encoding with newline separators",
        "Add a morse code decode pass to the normalisation pipeline",
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
    # ── Splitting ─────────────────────────────────────────────────────────────
    "json_split": (
        "Sensitive values bypassed detection when split across multiple adjacent JSON string values",
        "Reassemble adjacent string values across JSON field boundaries before scanning",
    ),
    "html_comment": (
        "Sensitive values bypassed detection when split using an HTML comment tag (<!-- -->)",
        "Strip HTML comment tags before scanning, then scan the resulting text",
    ),
}

# Prefix-based fallbacks for technique families not fully enumerated above.
# Each entry: (prefix, description_fragment, suggested_fix)
_PREFIX_FIXES: list[tuple[str, str, str]] = [
    (
        "arabic_indic",
        "Arabic-Indic digit script",
        "Normalise Arabic-Indic digits to ASCII before pattern matching"
        " (apply unicodedata.digit() or NFKD normalisation)",
    ),
    (
        "extended_arabic",
        "Extended Arabic-Indic digit script",
        "Normalise Extended Arabic-Indic digits to ASCII before pattern matching",
    ),
    (
        "devanagari",
        "Devanagari digit script",
        "Normalise Devanagari digits (०–९) to ASCII digits before pattern matching",
    ),
    (
        "bengali",
        "Bengali digit script",
        "Normalise Bengali digits to ASCII digits before pattern matching",
    ),
    (
        "thai",
        "Thai digit script",
        "Normalise Thai digits (๐–๙) to ASCII digits before pattern matching",
    ),
    (
        "myanmar",
        "Myanmar digit script",
        "Normalise Myanmar digits to ASCII digits before pattern matching",
    ),
    (
        "mongolian",
        "Mongolian digit script",
        "Normalise Mongolian digits to ASCII digits before pattern matching",
    ),
    (
        "khmer",
        "Khmer digit script",
        "Normalise Khmer digits to ASCII digits before pattern matching",
    ),
    (
        "tibetan",
        "Tibetan digit script",
        "Normalise Tibetan digits to ASCII digits before pattern matching",
    ),
    (
        "lao",
        "Lao digit script",
        "Normalise Lao digits to ASCII digits before pattern matching",
    ),
    (
        "math",
        "mathematical Unicode digit forms",
        "Normalise mathematical Unicode digit forms (𝟎–𝟗, 𝟘–𝟡) to ASCII"
        " digits; apply NFKD normalisation",
    ),
]


def _lookup_fix(technique: str) -> tuple[str, str]:
    """Return (description, suggested_fix) for a technique name."""
    if technique in _TECHNIQUE_FIXES:
        return _TECHNIQUE_FIXES[technique]

    for prefix, frag, fix in _PREFIX_FIXES:
        if technique.startswith(prefix):
            return (
                f"Sensitive values bypassed detection using {frag} (technique: {technique})",
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
