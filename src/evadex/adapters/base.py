from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from evadex.core.result import Payload, Variant, ScanResult


class AdapterError(Exception):
    pass


@dataclass
class AdapterConfig:
    base_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    timeout: float = 30.0
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "AdapterConfig":
        extra = {k: v for k, v in d.items() if k not in ("base_url", "api_key", "timeout")}
        return cls(
            base_url=d.get("base_url", "http://localhost:8080"),
            api_key=d.get("api_key"),
            timeout=float(d.get("timeout", 30.0)),
            extra=extra,
        )


class BaseAdapter(ABC):
    name: str = "base"

    def __init__(self, config: "dict | AdapterConfig"):
        if isinstance(config, dict):
            self.config = AdapterConfig.from_dict(config)
        else:
            self.config = config

    @abstractmethod
    async def submit(self, payload: Payload, variant: Variant) -> ScanResult:
        pass

    async def setup(self):
        pass

    async def teardown(self):
        pass

    async def health_check(self) -> bool:
        return True
