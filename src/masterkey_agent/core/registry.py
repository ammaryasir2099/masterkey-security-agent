"""Module protocol and deterministic registry for assessment modules."""
from __future__ import annotations

from typing import Any, Protocol

from .models import ModuleResult
from .target import Target


class DiscoveryModule(Protocol):
    name: str

    def run(self, target: Target, context: dict[str, Any]) -> ModuleResult:
        ...


class ModuleRegistry:
    def __init__(self) -> None:
        self._modules: dict[str, DiscoveryModule] = {}

    def register(self, module: DiscoveryModule) -> None:
        if not module.name:
            raise ValueError("Module name is required")
        if module.name in self._modules:
            raise ValueError(f"Module already registered: {module.name}")
        self._modules[module.name] = module

    def modules(self) -> tuple[DiscoveryModule, ...]:
        return tuple(self._modules[name] for name in sorted(self._modules))
