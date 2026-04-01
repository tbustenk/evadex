from abc import ABC, abstractmethod
from typing import IO
from evadex.core.result import ScanResult


class BaseReporter(ABC):
    @abstractmethod
    def render(self, results: list[ScanResult]) -> str:
        pass

    def write(self, results: list[ScanResult], destination: IO):
        destination.write(self.render(results))
