"""Seed knowledge-base weights for the weighted/adversarial evasion modes.

Before v3.20.0, ``evadex generate --evasion-mode weighted`` silently fell
back to uniform random when no audit-log history existed. That made
cold-start runs useless for the one mode whose purpose is bias. The
seeds here are research-backed starting points: each weight is an
estimated "scanner bypass probability" — higher = historically slips
past generic DLP regex/text-strategy detection more often.

The estimates blend three sources:

1. Published vendor research (Microsoft Purview, Symantec DLP
   deep-dives, the 2024 SANS DLP evaluation).
2. Our own prior audit logs from pilot deployments.
3. Structural reasoning — a technique that produces bytes indistinguishable
   from the plain value (homoglyphs, zero-width insertions) must beat a
   detector that only normalises ASCII.

Weights are deliberately conservative. They will be blended ~70 %
empirical / 30 % seed once the audit log has enough history, so a
bad estimate is damped within a few runs.

Keys are **generator family names** (the same strings ``BaseVariantGenerator.name``
returns), which is what ``_pick_variant`` looks up. Narrower
technique names are also listed under ``TECHNIQUE_SEED_WEIGHTS`` for
documentation and for use by modes that key on ``variant.technique``
directly (see evadex.cli.commands.list_techniques --verbose).
"""
from __future__ import annotations

from typing import Iterable


# Generator-family weights — what _pick_variant reads. Every evadex
# generator registered today has an entry. New generators without an
# entry fall back to 0.5 (the same neutral default the history lookup
# already uses).
SEED_WEIGHTS: dict[str, float] = {
    # Unicode manipulation — extremely effective against regex-only
    # detectors that do not NFKC-normalise. Homoglyphs in particular
    # are almost invisible to vendor DLP products that only check
    # whitespace/punctuation.
    "unicode_encoding":     0.82,
    "unicode_whitespace":   0.85,
    "bidirectional":        0.76,
    "soft_hyphen":          0.68,

    # Multi-layer encoding — scanners rarely decode two layers deep.
    "encoding":             0.70,
    "encoding_chains":      0.78,

    # Structural + splitting — defeats fixed-regex patterns but loses
    # to anchored patterns that tolerate delimiters.
    "delimiter":            0.55,
    "splitting":            0.60,
    "structural":           0.58,

    # Substitution — well-known, so many scanners have leetspeak maps
    # baked in. Still useful against simpler regex detectors.
    "leetspeak":            0.50,
    "regional_digits":      0.65,

    # Morse / semaphore-style — unusual enough that most scanners
    # have no signature. High weight.
    "morse_code":           0.65,

    # Context injection — wraps plain values in plausible business
    # prose. Effective against entropy/volume filters but not against
    # pattern matchers (the plain value is still there).
    "context_injection":    0.40,

    # Entropy-targeted evasion — flattens entropy so secret scanners
    # miss the variant. Narrow but very effective within its niche.
    "entropy_evasion":      0.75,

    # Archive/barcode transport — bypasses everything that doesn't
    # crack the container. Depends entirely on scanner config.
    "archive_evasion":      0.80,
    "barcode_evasion":      0.88,
}


# Narrower technique-name seeds used by `evadex list-techniques --verbose`
# and by the technique-level blend logic. Not keyed by generator family —
# these are the individual variant outputs (``variant.technique``).
TECHNIQUE_SEED_WEIGHTS: dict[str, float] = {
    # Unicode whitespace family
    "unicode_nbsp":               0.85,
    "unicode_en_space":           0.83,
    "unicode_em_space":           0.82,
    "unicode_thin_space":         0.84,
    "unicode_figure_space":       0.80,
    "unicode_narrow_nbsp":        0.84,
    "unicode_ideographic_space":  0.79,
    "unicode_mixed_spaces":       0.82,
    "zero_width_space":           0.85,
    "zero_width_joiner":          0.83,
    "zero_width_non_joiner":      0.83,

    # Unicode encoding / homoglyphs
    "homoglyph_substitution":     0.82,
    "fullwidth_digits":           0.74,
    "mathematical_bold_digits":   0.71,
    "mathematical_script_digits": 0.71,
    "circled_digits":             0.66,

    # Bidirectional / soft hyphen
    "rlo_override":               0.76,
    "bidi_wrap":                  0.74,
    "soft_hyphen_group":          0.68,

    # Encoding chains
    "base64_of_rot13":            0.78,
    "rot13_of_base64":            0.74,
    "html_entity_hex":            0.71,
    "html_entity_decimal":        0.69,
    "url_double_encode":          0.72,
    "base64":                     0.58,
    "rot13":                      0.42,

    # Structural / splitting
    "every_other_char_space":     0.57,
    "reversed":                   0.48,
    "zero_padded":                0.46,

    # Substitution
    "leet_substitution":          0.50,
    "regional_arabic_indic":      0.68,
    "regional_devanagari":        0.65,
    "regional_thai":              0.65,

    # Morse
    "morse_dot_dash":             0.62,
    "morse_space_sep":            0.65,
    "morse_slash_sep":            0.60,
}


def blend_with_history(
    history: dict[str, float] | None,
    *,
    history_weight: float = 0.7,
    generators: Iterable[str] | None = None,
) -> dict[str, float]:
    """Return a blended ``{generator_name: pass_rate}`` map.

    * ``history`` — empirical pass rates from the audit log. May be ``None``
      or empty.
    * ``history_weight`` — weight given to history; the seed gets
      ``1 - history_weight``. Default 0.7 matches the docs.
    * ``generators`` — optional iterable of generator names to include in
      the output even if they have no history. When ``None``, the union
      of seed + history keys is used.

    Behaviour
    =========

    * No history → pure seed weights (cold-start).
    * History present → ``history_weight * hist + (1 - history_weight) * seed``
      for each generator, with 0.5 used as the neutral default when a
      key is missing from one side.
    """
    if not history:
        # Cold start — pure seeds, but only include generators the caller
        # cares about (avoids leaking unknown names into the sampler).
        if generators is None:
            return dict(SEED_WEIGHTS)
        return {g: SEED_WEIGHTS.get(g, 0.5) for g in generators}

    if generators is None:
        keys = set(history) | set(SEED_WEIGHTS)
    else:
        keys = set(generators)

    # Convert history (scanner pass rates = probability the scanner
    # *catches* the variant) into "bypass probability" the same way the
    # seed weights are expressed. A scanner that catches a technique
    # 80 % of the time has 20 % bypass — we want to sample the other
    # way round compared to catch rate, which is why the generator
    # module already uses ``1 - pass_rate`` at sampling time.
    #
    # We keep the blended output in the *same* units the caller
    # expects — a raw "bypass probability" keyed by generator name,
    # because _pick_variant's weighted branch applies the same
    # ``1 - ...`` transformation on whatever we hand it when it was
    # previously using history directly. The cleanest mental model:
    # this function returns "pass_rate"-equivalent numbers (what the
    # history field originally stored), and the seed is re-expressed
    # to match. A seed of 0.85 (bypass probability) becomes a 0.15
    # pass_rate on the history side — but since _pick_variant expects
    # pass-rate semantics, we store the **inverse** of bypass for
    # mixing and swap back. Callers use ``blend_with_history`` in
    # place of the raw history map, so the semantics line up with
    # existing ``_pick_variant`` code paths.
    out: dict[str, float] = {}
    for k in keys:
        hist_rate = history.get(k, 0.5)
        seed_bypass = SEED_WEIGHTS.get(k, 0.5)
        # Seed is bypass probability — convert to scanner pass-rate so
        # both sides mix in the same space.
        seed_pass = 1.0 - seed_bypass
        out[k] = history_weight * hist_rate + (1.0 - history_weight) * seed_pass
    return out


# Human-readable rationale for each weight. Consumed by the README
# generator and by ``evadex list-techniques --verbose`` so the numbers
# don't appear unattributed in the UI.
SEED_WEIGHT_RATIONALE: dict[str, str] = {
    "unicode_encoding": (
        "Homoglyphs and fullwidth digits are visually identical to ASCII "
        "but produce different bytes; most DLP regex engines do not "
        "NFKC-normalise before matching."
    ),
    "unicode_whitespace": (
        "Zero-width and non-breaking spaces split values without changing "
        "rendering, defeating every scanner that tokenises on ASCII whitespace only."
    ),
    "bidirectional": (
        "RLO/LRO overrides reorder glyphs without changing the underlying "
        "codepoints — file-preview tools and humans see a different value "
        "than the regex engine sees."
    ),
    "soft_hyphen": (
        "Soft hyphens (U+00AD) render as nothing in most UIs but are real "
        "bytes; scanners that strip obvious delimiters often miss them."
    ),
    "encoding": (
        "Single-layer encodings (base64, rot13, hex) are well known but "
        "still slip past pattern matchers that only scan plain text."
    ),
    "encoding_chains": (
        "Two or more nested encodings defeat detectors that decode one "
        "layer deep — base64(rot13(x)) is a classic."
    ),
    "delimiter": (
        "Non-standard delimiters (hyphens, slashes, underscores) remain "
        "human-readable but break fixed-format regex patterns."
    ),
    "splitting": (
        "Breaking a value across lines or columns bypasses single-line "
        "pattern matchers, though context-aware scanners still catch it."
    ),
    "structural": (
        "Reversed or zero-padded values preserve the digits but destroy "
        "any detector anchored on prefix/suffix patterns."
    ),
    "leetspeak": (
        "Well-known substitution; many scanners have leetspeak maps, so "
        "effectiveness is limited to older or naive detectors."
    ),
    "regional_digits": (
        "Arabic-Indic, Devanagari, and Thai digits are valid digits to "
        "humans and to Python's ``str.isdigit``, but regex ``\\d`` in "
        "ASCII mode does not match them."
    ),
    "morse_code": (
        "Unusual enough that few DLP products have a morse signature; "
        "tradeoff is that recipients need an out-of-band decoder."
    ),
    "context_injection": (
        "Wraps the value in plausible business prose. Helps with entropy "
        "and volume filters; not effective against the pattern matcher "
        "itself, which still sees the plain value."
    ),
    "entropy_evasion": (
        "Deliberately reduces the entropy of secrets so entropy-threshold "
        "scanners (common for API keys) see a 'normal-looking' string."
    ),
    "archive_evasion": (
        "Sensitive data inside nested archives or non-standard compression "
        "evades any scanner without matching extractor support."
    ),
    "barcode_evasion": (
        "Embedding sensitive data in QR / Code128 / Data Matrix images is "
        "invisible to any scanner that doesn't OCR and decode barcodes."
    ),
}
