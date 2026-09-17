"""Bounded public-link extraction from already retrieved HTML."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from masterkey_agent.core.evidence import sanitize_url


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "a":
            return
        values = {name.lower(): value or "" for name, value in attrs}
        href = values.get("href", "").strip()
        if href:
            self.hrefs.append(href)


def _safe_public_url(value: str, base_url: str) -> str | None:
    absolute = urljoin(base_url, value)
    parsed = urlsplit(absolute)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None

    hostname = parsed.hostname
    netloc = hostname or ""
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    safe = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    return sanitize_url(safe)


def extract_public_links(html: str, base_url: str) -> list[str]:
    """Extract unique HTTP(S) destinations without userinfo, query, or fragment."""
    parser = _LinkParser()
    parser.feed(html)
    result: list[str] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        normalized = _safe_public_url(href, base_url)
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result
