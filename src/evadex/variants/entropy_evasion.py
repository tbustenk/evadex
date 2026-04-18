"""Variant generator that tries to evade entropy-based secret detection.

Siphon's ``scan_high_entropy_tokens`` tokenises input on a fixed delimiter
set (``[\\s,;'"()\\[\\]{}=:]``), enforces a minimum token length of 16
characters, and flags tokens whose per-character Shannon entropy exceeds
4.5 bits/char. The techniques here target those invariants:

- ``entropy_split``       — break the token across a newline so each piece
                            falls below the 16-char minimum.
- ``entropy_comment``     — inject a ``/*...*/`` comment that re-introduces
                            an entropy-scan delimiter mid-token.
- ``entropy_concat``      — split into quoted string fragments joined with
                            ``+``, which is a delimiter for Siphon.
- ``entropy_low_mix``     — pad the token with low-entropy filler so the
                            combined run falls under the 4.5 bits/char bar.
- ``entropy_encode``      — base64-encode the already-high-entropy value
                            (double-encoding), moving entropy around.
- ``entropy_space``       — insert a space every four chars to force the
                            tokenizer to split below the length floor.
"""
import base64
from typing import Iterator

from evadex.core.registry import register_generator
from evadex.core.result import PayloadCategory, Variant
from evadex.variants.base import BaseVariantGenerator


ENTROPY_CATEGORIES = {
    PayloadCategory.RANDOM_API_KEY,
    PayloadCategory.RANDOM_TOKEN,
    PayloadCategory.RANDOM_SECRET,
    PayloadCategory.ENCODED_CREDENTIAL,
    PayloadCategory.ASSIGNMENT_SECRET,
    PayloadCategory.GATED_SECRET,
}


@register_generator("entropy_evasion")
class EntropyEvasionGenerator(BaseVariantGenerator):
    """Generates evasion variants tailored to Shannon-entropy scanners."""

    name = "entropy_evasion"
    applicable_categories = ENTROPY_CATEGORIES

    def generate(self, value: str) -> Iterator[Variant]:
        core = _extract_token(value)
        if not core or len(core) < 4:
            return

        # Use an off-centre split so the first piece is STRICTLY under the
        # 16-char minimum token length — ``len(core)//2`` would leave a
        # 16-char piece on a 32-char input, which Siphon keeps because its
        # cutoff is ``< ENTROPY_MIN_TOKEN_LEN`` (allows exactly 16).
        split_at = max(1, min(len(core) - 1, (len(core) // 2) - 1))
        prefix, suffix = value.split(core, 1) if core in value else ("", "")

        # 1. entropy_split — insert a newline every 15 chars so every piece
        # is strictly under Siphon's 16-char minimum token length. One newline
        # is not enough for long tokens (a 32-char value split in half leaves
        # a 17-char half that still clears the threshold).
        chunk = 15
        split_core = "\n".join(core[i:i + chunk] for i in range(0, len(core), chunk))
        split_value = f"{prefix}{split_core}{suffix}"
        yield self._make_variant(
            split_value, "entropy_split", "Split high-entropy token across newlines every 15 chars"
        )

        # 2. entropy_comment — inject a ``;comment;`` sequence. Siphon's
        # delimiter set includes ``;``, ``"``, ``'``, ``,`` so surrounding
        # the comment with those chops the token into sub-16-char pieces.
        comment_value = (
            f'{prefix}{core[:split_at]}";c";{core[split_at:]}{suffix}'
        )
        yield self._make_variant(
            comment_value,
            "entropy_comment",
            'Insert ";c"; delimiter comment mid-token to break tokenization',
        )

        # 3. entropy_concat — quoted concatenation (``"a" + "b"``) re-splits
        # the high-entropy run into sub-16-char pieces.
        concat_value = f'{prefix}"{core[:split_at]}" + "{core[split_at:]}"{suffix}'
        yield self._make_variant(
            concat_value,
            "entropy_concat",
            'Split into "part1" + "part2" concatenated literals',
        )

        # 4. entropy_low_mix — blend in a long low-entropy run so the
        # per-character Shannon entropy of the combined token drops below
        # the 4.5 bit/char threshold.
        low = "aaaaaaaaaaaaaaaa"  # 16 chars, entropy 0.0
        mix_value = f"{prefix}{core}{low}{suffix}"
        yield self._make_variant(
            mix_value,
            "entropy_low_mix",
            "Append low-entropy padding to dilute per-char entropy",
        )

        # 5. entropy_encode — base64-encode the value again. The result
        # stays high-entropy but the surrounding delimiters change, which
        # can move the match outside of gated/assignment windows.
        try:
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        except Exception:
            encoded = ""
        if encoded:
            yield self._make_variant(
                encoded,
                "entropy_encode",
                "Base64-encode the whole value (double encoding)",
            )

        # 6. entropy_space — insert a space every 4 chars so every sub-run
        # is under the 16-char minimum.
        spaced_core = " ".join(core[i:i + 4] for i in range(0, len(core), 4))
        space_value = f"{prefix}{spaced_core}{suffix}"
        yield self._make_variant(
            space_value,
            "entropy_space",
            "Insert spaces every 4 chars to fall below min token length",
        )


def _extract_token(value: str) -> str:
    """Return the longest run of characters Siphon would treat as one token.

    Siphon's entropy tokeniser splits on ``[\\s,;'"()\\[\\]{}=:]``. Mirroring
    that, we consider anything outside that delimiter set a token character.
    Entropy payloads can be bare (``xK9mP2...``), assignment
    (``KEY=xK9mP2...``) or gated (``api_key: xK9mP2...``). Evasion must
    transform the high-entropy portion, not the keyword/key surrounding it.
    """
    delimiters = set(" \t\n,;'\"()[]{}=:")
    candidate = ""
    current: list = []
    for ch in value:
        if ch in delimiters:
            if len("".join(current)) > len(candidate):
                candidate = "".join(current)
            current = []
        else:
            current.append(ch)
    if len("".join(current)) > len(candidate):
        candidate = "".join(current)
    return candidate
