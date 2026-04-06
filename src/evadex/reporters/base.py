from abc import ABC, abstractmethod
from evadex.core.result import ScanResult


class BaseReporter(ABC):
    @abstractmethod
    def render(self, results: list[ScanResult]) -> str:
        pass
