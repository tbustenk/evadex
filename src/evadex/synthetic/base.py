"""Base class for synthetic value generators."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class BaseSyntheticGenerator(ABC):
    """ABC for synthetic sensitive-value generators.

    Subclasses produce structurally valid values (correct checksums,
    realistic formats) so DLP scanner detection results are meaningful.

    Usage::

        gen = CreditCardSyntheticGenerator()
        values = gen.generate(count=1000, seed=42)
    """

    @abstractmethod
    def generate(self, count: int, seed: Optional[int] = None) -> list[str]:
        """Generate *count* synthetic values.

        Args:
            count: Number of values to produce.
            seed:  Optional RNG seed for reproducible output.

        Returns:
            List of *count* synthetic value strings.
        """
