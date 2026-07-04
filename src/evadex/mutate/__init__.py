"""evadex mutate — adaptive evasion variant generation.

Breeds new evasion candidates from the variants that *survived* a past scan.
See :mod:`evadex.mutate.engine` for the mutation strategies and
``evadex.cli.commands.mutate`` for the CLI wiring.
"""

from evadex.mutate.engine import (
    MUTATE_GENERATOR,
    MUTATION_TYPES,
    MutatedVariant,
    MutationCandidate,
    MutationEngine,
)

__all__ = [
    "MUTATE_GENERATOR",
    "MUTATION_TYPES",
    "MutatedVariant",
    "MutationCandidate",
    "MutationEngine",
]
