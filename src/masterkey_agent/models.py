"""Typed data models shared by discovery and reporting components."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


def _to_dict(instance: Any) -> dict[str, Any]:
    return asdict(instance)


@dataclass(slots=True)
class SystemInfo:
    os_name: str
    platform: str
    release: str
    hostname: str

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class BrowserInfo:
    name: str
    executable: str
    version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class HTMLField:
    name: str | None = None
    type: str | None = None
    autocomplete: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class HTMLForm:
    method: str = "GET"
    action: str = ""
    fields: list[HTMLField] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class PublicHTML:
    title: str | None = None
    forms: list[HTMLForm] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class NetworkObservation:
    url: str
    scheme: str
    host: str
    status_code: int | None = None
    redirects: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    resolved_addresses: list[str] = field(default_factory=list)
    tls: dict[str, Any] | None = None
    error: str | None = None
    content_type: str | None = None
    public_html: PublicHTML | None = None
    cookie_attributes: list[dict[str, Any]] = field(default_factory=list)
    cors: dict[str, str | bool] = field(default_factory=dict)
    response_size_limited: bool = False

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)


@dataclass(slots=True)
class AuthMap:
    protocols: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    confidence: str = "low"
    evidence: list[str] = field(default_factory=list)
    transport_evidence: list[str] = field(default_factory=list)
    authentication_evidence: list[str] = field(default_factory=list)
    security_controls: list[str] = field(default_factory=list)
    authentication_confidence: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)
