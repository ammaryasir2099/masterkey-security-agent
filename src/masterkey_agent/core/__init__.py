"""Core orchestration types for Master Security Agent v0.5."""

from .models import Evidence, Finding, ModuleResult, ScanSession
from .registry import DiscoveryModule, ModuleRegistry
from .target import Target, TargetPolicy, normalize_target, validate_target
from .correlation import correlate_results

__all__ = [
    "DiscoveryModule",
    "Evidence",
    "Finding",
    "ModuleResult",
    "ModuleRegistry",
    "ScanSession",
    "Target",
    "TargetPolicy",
    "normalize_target",
    "validate_target",
    "correlate_results",
]
