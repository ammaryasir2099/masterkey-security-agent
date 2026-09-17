"""Bounded parser for public HTML metadata and authentication-surface inputs."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from masterkey_agent.models import HTMLField, HTMLForm, PublicHTML

_SAFE_META_NAMES = {"generator", "robots", "viewport", "referrer"}


def _safe_action(value: str, base_url: str | None = None) -> str:
    if not value:
        return ""
    resolved = urljoin(base_url, value) if base_url else value
    parsed = urlsplit(resolved)
    if parsed.scheme and parsed.username is not None:
        return ""
    netloc = parsed.hostname or parsed.netloc
    if parsed.port and parsed.hostname:
        netloc = f"{parsed.hostname}:{parsed.port}"
    if parsed.scheme or parsed.netloc:
        return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))
    return urlunsplit(("", "", parsed.path or "", "", ""))


def _safe_reference(value: str, base_url: str | None) -> str | None:
    if not value or not base_url:
        return None
    resolved = urljoin(base_url, value)
    parsed = urlsplit(resolved)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    netloc = parsed.hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))


class _PublicHTMLParser(HTMLParser):
    def __init__(self, base_url: str | None = None):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[HTMLForm] = []
        self._current_form: HTMLForm | None = None
        self.links: list[str] = []
        self.meta: dict[str, str] = {}
        self.scripts: list[str] = []
        self.styles: list[str] = []

    def _add_unique(self, values: list[str], value: str | None) -> None:
        if value and value not in values:
            values.append(value)

    def handle_starttag(self, tag: str, attrs) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self._current_form = HTMLForm(
                method=attributes.get("method", "GET").upper(),
                action=_safe_action(attributes.get("action", ""), self.base_url),
            )
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form.fields.append(
                HTMLField(
                    name=attributes.get("name") or None,
                    type=attributes.get("type", "text").lower() or None,
                    autocomplete=attributes.get("autocomplete") or None,
                )
            )
        elif tag == "a":
            self._add_unique(self.links, _safe_reference(attributes.get("href", ""), self.base_url))
        elif tag == "script":
            self._add_unique(self.scripts, _safe_reference(attributes.get("src", ""), self.base_url))
        elif tag == "link" and attributes.get("rel", "").lower().split() and "stylesheet" in attributes.get("rel", "").lower().split():
            self._add_unique(self.styles, _safe_reference(attributes.get("href", ""), self.base_url))
        elif tag == "meta":
            key = (attributes.get("name") or attributes.get("property") or "").strip().lower()
            content = " ".join(attributes.get("content", "").split())
            if key in _SAFE_META_NAMES and content and len(content) <= 256:
                self.meta.setdefault(key, content)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data)


def parse_public_html(html: str, base_url: str | None = None) -> PublicHTML:
    parser = _PublicHTMLParser(base_url=base_url)
    parser.feed(html)
    title = " ".join("".join(parser.title_parts).split()) or None
    return PublicHTML(
        title=title,
        forms=parser.forms,
        links=parser.links,
        meta=parser.meta,
        scripts=parser.scripts,
        styles=parser.styles,
    )
