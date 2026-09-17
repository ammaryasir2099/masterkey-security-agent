"""Evidence normalization, redaction, and de-duplication helpers."""
from __future__ import annotations

import json
from urllib.parse import urlsplit, urlunsplit

from .models import Evidence


def sanitize_url(value: str) -> str:
    """Remove query and fragment components from an evidence URL."""
    parsed = urlsplit(value.strip())
    if not parsed.scheme and not parsed.netloc and not parsed.path:
        return value.strip()
    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            parsed.path or "/" if parsed.netloc else parsed.path,
            "",
            "",
        )
    )


def evidence_key(item: Evidence) -> str:
    """Build a deterministic identity for de-duplication."""
    metadata = json.dumps(item.metadata, sort_keys=True, separators=(",", ":"), default=str)
    return "\x1f".join(
        (
            item.source_module,
            item.evidence_type,
            sanitize_url(item.target_url or ""),
            item.value,
            metadata,
        )
    )


def deduplicate_evidence(items: list[Evidence]) -> list[Evidence]:
    """Return first-seen evidence entries with deterministic identity."""
    seen: set[str] = set()
    result: list[Evidence] = []
    for item in items:
        key = evidence_key(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result
