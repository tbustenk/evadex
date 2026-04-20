"""Synthetic US driver-licence number generator.

There is one ``US_DL`` payload category, but each of the 50 states + DC
uses a different licence-number format. This generator cycles through
all 51 formats so a ``--count N`` run produces a representative spread.
Format definitions are derived from each state's seed payload in
``src/evadex/payloads/builtins.py`` — same source the recogniser team
uses to author patterns, so format coverage stays in sync.

No checksum validation is performed. Most state DL formats are
shape-only; the few that include checksums (e.g. Wisconsin) use
proprietary algorithms outside DLP scanner scope.
"""
from __future__ import annotations

import random
import string
from typing import Iterator, Optional

from evadex.core.result import PayloadCategory
from evadex.synthetic.base import BaseSyntheticGenerator
from evadex.synthetic.registry import register_synthetic


# (state name, format spec). Format spec uses:
#   D = a single decimal digit
#   L = a single uppercase letter
#   X = letter OR digit (alphanumeric, used by Washington-style codes)
#
# Spaces and hyphens are preserved verbatim. To add a state, add one
# row here and add a corresponding seed payload in builtins.py.
_STATE_FORMATS: list[tuple[str, str]] = [
    ("Alabama",         "DDDDDDD"),                # 7 digits
    ("Alaska",          "DDDDDDD"),
    ("Arizona",         "LDDDDDDDD"),              # letter + 8 digits
    ("Arkansas",        "DDDDDDDD"),               # 8 digits
    ("California",      "LDDDDDDD"),               # letter + 7 digits
    ("Colorado",        "DDDDDDDDD"),              # 9 digits
    ("Connecticut",     "DDDDDDDDD"),
    ("DC",              "DDDDDDD"),
    ("Delaware",        "DDDDDDD"),
    ("Florida",         "LDDDDDDDDDDDD"),          # letter + 12 digits
    ("Georgia",         "DDDDDDDD"),
    ("Hawaii",          "LDDDDDDDD"),
    ("Idaho",           "LLDDDDDDL"),              # 2 letters + 6 digits + letter
    ("Illinois",        "LDDDDDDDDDDD"),           # letter + 11 digits
    ("Indiana",         "DDDDDDDDDD"),             # 10 digits
    ("Iowa",            "DDDLLDDDD"),              # 3D + 2L + 4D
    ("Kansas",          "LDDDDDDDD"),
    ("Kentucky",        "LDDDDDDDD"),
    ("Louisiana",       "DDDDDDDDD"),
    ("Maine",           "DDDDDDD"),
    ("Maryland",        "LDDDDDDDDDDDD"),
    ("Massachusetts",   "LDDDDDDDD"),
    ("Michigan",        "LDDDDDDDDDDDD"),
    ("Minnesota",       "LDDDDDDDDDDDD"),
    ("Mississippi",     "DDDDDDDDD"),
    ("Missouri",        "LDDDDDDDD"),
    ("Montana",         "DDDDDDDDDDDDD"),          # 13 digits
    ("Nebraska",        "LDDDDDDDD"),
    ("Nevada",          "DDDDDDDDDD"),
    ("New Hampshire",   "DDLLLDDDDD"),             # 2D + 3L + 5D
    ("New Jersey",      "LDDDDDDDDDDDDDD"),        # letter + 14 digits
    ("New Mexico",      "DDDDDDDDD"),
    ("New York",        "DDDDDDDDD"),
    ("North Carolina",  "DDDDDDDDD"),
    ("North Dakota",    "LLLDDDDDD"),              # 3 letters + 6 digits
    ("Ohio",            "LLDDDDDD"),               # 2 letters + 6 digits
    ("Oklahoma",        "LDDDDDDDDD"),
    ("Oregon",          "DDDDDDDD"),
    ("Pennsylvania",    "DDDDDDDD"),
    ("Rhode Island",    "LDDDDDD"),
    ("South Carolina",  "DDDDDDDD"),
    ("South Dakota",    "DDDDDDDD"),
    ("Tennessee",       "DDDDDDDD"),
    ("Texas",           "DDDDDDDD"),
    ("Utah",            "DDDDDDDD"),
    ("Vermont",         "DDDDDDDD"),
    ("Virginia",        "LDDDDDDDDD"),
    ("Washington",      "LLLLLXXXXX"),             # 5 letters + 5 alphanumeric
    ("West Virginia",   "LDDDDDD"),
    ("Wisconsin",       "LDDDDDDDDDDDDD"),         # letter + 13 digits
    ("Wyoming",         "DDDDDDDDD"),
]

assert len(_STATE_FORMATS) == 51, "Expected 50 states + DC"


def _expand_format(spec: str, rng: random.Random) -> str:
    out: list[str] = []
    for ch in spec:
        if ch == "D":
            out.append(str(rng.randint(0, 9)))
        elif ch == "L":
            out.append(rng.choice(string.ascii_uppercase))
        elif ch == "X":
            out.append(rng.choice(string.ascii_uppercase + string.digits))
        else:
            out.append(ch)
    return "".join(out)


def _generate_one(rng: random.Random) -> str:
    _, spec = rng.choice(_STATE_FORMATS)
    return _expand_format(spec, rng)


@register_synthetic(PayloadCategory.US_DL)
class USDriversLicenceSyntheticGenerator(BaseSyntheticGenerator):
    """Generates structurally-valid US driver-licence numbers, cycling
    through all 50 state + DC formats."""

    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        rng = random.Random(seed)
        return [_generate_one(rng) for _ in range(count)]

    def iter_generate(self, count: int, seed: Optional[int] = None) -> Iterator[str]:
        rng = random.Random(seed)
        for _ in range(count):
            yield _generate_one(rng)
