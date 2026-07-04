"""Adaptive mutation engine — evolves bypassing variants into new ones.

``evadex scan`` regenerates variants from a fixed catalogue of generators.
``evadex replay`` re-runs the *exact* variants from a past scan. ``evadex
mutate`` sits between the two: it reads a past scan, takes the variants that
*bypassed* the scanner (the interesting survivors), and breeds new candidates
from them using four families of transformation:

* **perturbation** — a small tweak to a surviving variant (swap the delimiter,
  shift digits to another script, sprinkle zero-width joiners).
* **intensification** — turn up the evasion pressure on whatever already worked
  (heavier leet map, deeper re-encoding).
* **combination** — chain two encodings on one variant (base64 → hex, …).
* **crossover** — splice two *different* surviving variants together so their
  lineages mix.

The engine is deliberately pure: it takes strings and :class:`MutationCandidate`
objects and returns :class:`MutatedVariant` objects. It never touches a scanner,
the filesystem, or Click — that wiring lives in
``evadex.cli.commands.mutate``. Everything is seeded off a single
:class:`random.Random`, so a given ``(seed, candidate)`` pair always breeds the
same offspring — reproducibility the CLI advertises via ``--seed``.
"""

from __future__ import annotations

import base64
import codecs
from dataclasses import dataclass, field
from typing import Callable, Optional

from evadex.core.result import Payload, PayloadCategory, ScanResult, Variant

# The synthetic generator name stamped onto every bred Variant. Keeping it
# distinct from the real generator names means downstream reports never confuse
# a mutation with a first-class scan variant.
MUTATE_GENERATOR = "mutate"

MUTATION_TYPES = ("perturbation", "intensification", "combination", "crossover")


@dataclass
class MutationCandidate:
    """A surviving (bypassing) variant, wrapped as breeding stock.

    Holds the source :class:`ScanResult` so the original secret
    (``result.payload``) rides along — that payload is what the ``--test`` path
    re-submits the bred value under, and what lets a mutation's lineage span
    generations without losing which secret it descends from.
    """

    result: ScanResult
    generation: int = 0
    techniques_used: list[str] = field(default_factory=list)

    @property
    def value(self) -> str:
        return self.result.variant.value

    @property
    def payload(self) -> Payload:
        return self.result.payload

    @property
    def category(self) -> str:
        return self.result.payload.category.value

    @classmethod
    def from_result(
        cls, result: ScanResult, generation: int = 0
    ) -> "MutationCandidate":
        v = result.variant
        techs = [t for t in (v.technique, v.generator) if t]
        return cls(result=result, generation=generation, techniques_used=techs[:1])

    @classmethod
    def from_mutated(cls, mv: "MutatedVariant") -> "MutationCandidate":
        """Re-wrap a bred variant as a candidate for the next generation.

        The original secret propagates via ``mv.source_payload``; the lineage
        (``parent_techniques`` + this variant's own technique) is carried so
        offspring keep an accurate ancestry list.
        """
        payload = mv.source_payload or Payload(
            value="", category=PayloadCategory.UNKNOWN, label="mutated"
        )
        result = ScanResult(payload=payload, variant=mv.to_variant(), detected=False)
        lineage = list(mv.parent_techniques)
        if mv.base_technique not in lineage:
            lineage.append(mv.base_technique)
        return cls(result=result, generation=mv.generation, techniques_used=lineage)


@dataclass
class MutatedVariant:
    """A new variant produced by mutation."""

    value: str
    category: str
    base_technique: str
    mutation_type: str  # one of MUTATION_TYPES
    generation: int
    parent_techniques: list[str]
    description: str
    # The secret this mutation descends from — carried so the CLI ``--test``
    # path can submit under the right Payload and so lineage survives across
    # generations. Never serialised (it's the *plaintext* secret).
    source_payload: Optional[Payload] = None

    def to_variant(self) -> Variant:
        return Variant(
            value=self.value,
            generator=MUTATE_GENERATOR,
            technique=self.base_technique,
            transform_name=self.description,
            strategy="text",
        )

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "category": self.category,
            "base_technique": self.base_technique,
            "mutation_type": self.mutation_type,
            "generation": self.generation,
            "parent_techniques": list(self.parent_techniques),
            "description": self.description,
        }


def _digits(value: str) -> str:
    """The ASCII digits in ``value``, in order."""
    return "".join(ch for ch in value if ch.isdigit())


def _core(value: str) -> str:
    """The alphanumeric skeleton of ``value`` — the part worth re-encoding.

    Broader than :func:`_digits` so alphanumeric identifiers (driver's
    licences, tickers, ISINs — which dominate real bypass sets) can be mutated,
    not just pure-numeric ones.
    """
    return "".join(ch for ch in value if ch.isalnum())


class MutationEngine:
    """Evolves bypassing variants into new evasion candidates."""

    SEPARATORS = [" ", "-", ".", "/", "|", ",", ":", ";", "_"]

    LEET_MAPS = [
        # Light
        {"0": "O", "1": "l", "3": "E"},
        # Moderate
        {"0": "O", "1": "l", "3": "E", "4": "A", "5": "S", "7": "T"},
        # Heavy
        {
            "0": "O",
            "1": "l",
            "3": "E",
            "4": "A",
            "5": "S",
            "6": "G",
            "7": "T",
            "8": "B",
            "9": "g",
        },
    ]

    ENCODINGS = ["base64", "base32", "hex", "url_percent", "rot13"]

    REGIONAL_SCRIPTS = [
        # (offset from ASCII digit, name)
        (0x0660 - 0x30, "arabic_indic"),
        (0x06F0 - 0x30, "extended_arabic"),
        (0x0E50 - 0x30, "thai"),
        (0x0966 - 0x30, "devanagari"),
        (0x09E6 - 0x30, "bengali"),
    ]

    ZERO_WIDTH = ["​", "‌", "‍", "⁠", "﻿"]

    def __init__(self, seed: int = 42):
        import random

        self.seed = seed
        self.rng = random.Random(seed)
        self._registry: list[
            Callable[[MutationCandidate], Optional[MutatedVariant]]
        ] = [
            self._mutate_separator,
            self._mutate_encoding,
            self._mutate_leet_intensity,
            self._mutate_regional_script,
            self._mutate_zero_width_injection,
            self._mutate_combine_techniques,
            self._mutate_encoding_chain,
            self._mutate_case_variation,
        ]

    # ── Public API ──────────────────────────────────────────────────────────
    def mutate(
        self, candidate: MutationCandidate, n_mutations: int = 5
    ) -> list[MutatedVariant]:
        """Breed up to ``n_mutations`` distinct offspring from ``candidate``.

        Draws ``n`` strategies without replacement, runs each, and keeps the
        ones that (a) actually changed the value and (b) aren't duplicates of a
        sibling produced this call. A strategy that isn't applicable to this
        value (e.g. a digit regroup on a tokenless secret) simply yields nothing.
        """
        out: list[MutatedVariant] = []
        seen: set[str] = {candidate.value}
        n = min(max(n_mutations, 0), len(self._registry))
        for fn in self.rng.sample(self._registry, n):
            try:
                mv = fn(candidate)
            except Exception:
                # A single misbehaving strategy must never sink the batch.
                continue
            if mv is None or mv.value in seen:
                continue
            mv.source_payload = candidate.payload
            seen.add(mv.value)
            out.append(mv)
        return out

    def crossover(
        self, a: MutationCandidate, b: MutationCandidate
    ) -> Optional[MutatedVariant]:
        """Splice two surviving variants into one whose lineage mixes both.

        The result re-encodes ``a``'s skeleton with an encoding keyed off
        ``a``'s technique, then wraps that with a second encoding keyed off
        ``b``'s — so both parents leave a fingerprint. Returns ``None`` when
        ``a`` has no encodable skeleton.
        """
        core = _core(a.value)
        if len(core) < 4:
            return None
        a_tech = (a.techniques_used or ["unknown"])[0]
        b_tech = (b.techniques_used or ["unknown"])[0]
        enc_a = self.ENCODINGS[hash(a_tech) % 3]  # base64 / base32 / hex
        enc_b = self.ENCODINGS[hash(b_tech) % 3]
        value = self._encode(self._encode(core, enc_a), enc_b)
        if value == a.value or value == b.value:
            return None
        parents = list(dict.fromkeys([*a.techniques_used, *b.techniques_used]))
        return MutatedVariant(
            value=value,
            category=a.category,
            base_technique=f"{enc_a}x{enc_b}_crossover",
            mutation_type="crossover",
            generation=max(a.generation, b.generation) + 1,
            parent_techniques=parents,
            description=f"Crossover {a_tech} x {b_tech}: {enc_a} then {enc_b}",
            source_payload=a.payload,
        )

    # ── Encoding helper ─────────────────────────────────────────────────────
    @staticmethod
    def _encode(value: str, enc: str) -> str:
        raw = value.encode("utf-8", "replace")
        if enc == "base64":
            return base64.b64encode(raw).decode("ascii")
        if enc == "base32":
            return base64.b32encode(raw).decode("ascii")
        if enc == "hex":
            return raw.hex()
        if enc == "url_percent":
            return "".join(f"%{b:02X}" for b in raw)
        if enc == "rot13":
            return codecs.encode(value, "rot_13")
        return value

    def _build(
        self,
        c: MutationCandidate,
        *,
        value: str,
        base_technique: str,
        mutation_type: str,
        description: str,
    ) -> MutatedVariant:
        return MutatedVariant(
            value=value,
            category=c.category,
            base_technique=base_technique,
            mutation_type=mutation_type,
            generation=c.generation + 1,
            parent_techniques=list(c.techniques_used),
            description=description,
            source_payload=c.payload,
        )

    # ── Mutation strategies ─────────────────────────────────────────────────
    def _mutate_separator(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """Regroup the digits under a different delimiter."""
        digits = _digits(c.value)
        if len(digits) < 8:
            return None
        sep = self.rng.choice(self.SEPARATORS)
        groups = [digits[i : i + 4] for i in range(0, len(digits), 4)]
        value = sep.join(groups)
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique="delimiter_regroup",
            mutation_type="perturbation",
            description=f"Digits regrouped with {sep!r} separator",
        )

    def _mutate_encoding(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """Re-encode the skeleton with a single different encoding."""
        core = _core(c.value)
        if len(core) < 6:
            return None
        enc = self.rng.choice(self.ENCODINGS)
        value = self._encode(core, enc)
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique=enc,
            mutation_type="intensification",
            description=f"Re-encoded skeleton with {enc}",
        )

    def _mutate_leet_intensity(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """Apply a leet substitution map at one of three intensities."""
        idx = self.rng.randrange(len(self.LEET_MAPS))
        leet = self.LEET_MAPS[idx]
        value = "".join(leet.get(ch, ch) for ch in c.value)
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique="leet",
            mutation_type="intensification",
            description=f"Leet substitution, intensity {idx + 1}/3",
        )

    def _mutate_regional_script(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """Shift the ASCII digits into a non-Latin numeral script."""
        if not any(ch.isdigit() and ch.isascii() for ch in c.value):
            return None
        offset, name = self.rng.choice(self.REGIONAL_SCRIPTS)
        value = "".join(
            chr(ord(ch) + offset) if (ch.isdigit() and ch.isascii()) else ch
            for ch in c.value
        )
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique=f"regional_{name}",
            mutation_type="perturbation",
            description=f"Digits shifted to {name} script",
        )

    def _mutate_zero_width_injection(
        self, c: MutationCandidate
    ) -> Optional[MutatedVariant]:
        """Inject a zero-width char after every N significant characters."""
        zw = self.rng.choice(self.ZERO_WIDTH)
        n = self.rng.choice([1, 2, 4])
        out: list[str] = []
        count = 0
        for ch in c.value:
            out.append(ch)
            if ch.isalnum():
                count += 1
                if count % n == 0:
                    out.append(zw)
        value = "".join(out)
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique="zero_width",
            mutation_type="perturbation",
            description=f"U+{ord(zw):04X} injected every {n} char(s)",
        )

    def _mutate_combine_techniques(
        self, c: MutationCandidate
    ) -> Optional[MutatedVariant]:
        """Chain two byte-preserving encodings on the skeleton."""
        core = _core(c.value)
        if len(core) < 6:
            return None
        enc1, enc2 = self.rng.sample(["base64", "base32", "hex"], 2)
        value = self._encode(self._encode(core, enc1), enc2)
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique=f"{enc1}_{enc2}_chain",
            mutation_type="combination",
            description=f"Chained encodings: {enc1} then {enc2}",
        )

    def _mutate_encoding_chain(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """A fixed triple chain: base64 → ROT13 → hex."""
        core = _core(c.value)
        if len(core) < 6:
            return None
        value = self._encode(self._encode(self._encode(core, "base64"), "rot13"), "hex")
        if value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique="base64_rot13_hex_chain",
            mutation_type="combination",
            description="Triple chain: base64 then ROT13 then hex",
        )

    def _mutate_case_variation(self, c: MutationCandidate) -> Optional[MutatedVariant]:
        """Base64 the skeleton, then randomise the case of each letter."""
        core = _core(c.value)
        if len(core) < 6:
            return None
        b64 = self._encode(core, "base64")
        value = "".join(
            ch.upper() if self.rng.random() > 0.5 else ch.lower() for ch in b64
        )
        if value == b64 or value == c.value:
            return None
        return self._build(
            c,
            value=value,
            base_technique="base64_mixed_case",
            mutation_type="perturbation",
            description="Base64 with randomised character case",
        )
