from abc import ABC, abstractmethod
from typing import Iterator, Optional
from evadex.core.result import Variant, PayloadCategory


class BaseVariantGenerator(ABC):
    name: str = "base"
    applicable_categories: Optional[set[PayloadCategory]] = None  # None = applies to all
    # When False, the generator is skipped in random-evasion selection and
    # only runs when the user explicitly requests it via --technique-group
    # or --technique-mix. Used for out-of-band evasions (e.g. barcode image
    # transforms) that would otherwise dilute standard text-pipeline output.
    auto_applicable: bool = True

    @abstractmethod
    def generate(self, value: str) -> Iterator[Variant]:
        pass

    def _make_variant(self, value: str, technique: str, transform_name: str) -> Variant:
        return Variant(
            value=value,
            generator=self.name,
            technique=technique,
            transform_name=transform_name,
        )
