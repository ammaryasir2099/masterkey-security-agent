"""Target normalization and conservative scan policy."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class TargetPolicy:
    timeout_seconds: float = 10.0
    max_response_bytes: int = 512 * 1024
    max_redirects: int = 10
    allow_http: bool = True
    allow_https: bool = True


@dataclass(frozen=True, slots=True)
class Target:
    original_input: str
    url: str
    scheme: str
    hostname: str
    port: int | None
    path: str


def normalize_target(value: str) -> Target:
    original = value.strip()
    if not original:
        raise ValueError("Target URL is empty")

    candidate = original if "://" in original else f"https://{original}"
    parsed = urlparse(candidate)
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Target URL must contain a hostname")

    path = parsed.path or "/"
    normalized = parsed._replace(scheme=scheme, path=path, fragment="").geturl()
    return Target(
        original_input=original,
        url=normalized,
        scheme=scheme,
        hostname=hostname,
        port=parsed.port,
        path=path,
    )


def validate_target(target: Target, policy: TargetPolicy | None = None) -> None:
    active = policy or TargetPolicy()
    if target.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme: {target.scheme}")
    if target.scheme == "http" and not active.allow_http:
        raise ValueError("HTTP targets are disabled by policy")
    if target.scheme == "https" and not active.allow_https:
        raise ValueError("HTTPS targets are disabled by policy")
    if not target.hostname:
        raise ValueError("Target hostname is required")
    if active.timeout_seconds <= 0:
        raise ValueError("Timeout must be positive")
    if active.max_response_bytes <= 0:
        raise ValueError("Maximum response size must be positive")
    if active.max_redirects < 0:
        raise ValueError("Maximum redirects cannot be negative")
