"""Serializable models shared by v0.4 orchestration and reporting."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from typing import Any


def _safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return _safe(asdict(value))
    if isinstance(value, list):
        return [_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe(item) for key, item in value.items()}
    return value


@dataclass(slots=True)
class Evidence:
    id: str
    source_module: str
    evidence_type: str
    value: str
    target_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = _safe(asdict(self))
        if data.get("target_url"):
            from .evidence import sanitize_url

            data["target_url"] = sanitize_url(str(data["target_url"]))
        return data


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    category: str
    summary: str
    evidence_refs: list[str] = field(default_factory=list)
    recommendation: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass(slots=True)
class ModuleResult:
    module: str
    success: bool
    evidence: list[Evidence] = field(default_factory=list)
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))


@dataclass(slots=True)
class ScanSession:
    session_id: str
    agent_version: str
    started_at: datetime
    target: dict[str, Any]
    policy: dict[str, Any]
    modules: list[ModuleResult] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ended_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return _safe(asdict(self))
