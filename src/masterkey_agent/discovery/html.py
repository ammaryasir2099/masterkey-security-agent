"""Bounded parser for public HTML metadata used by observation-only analysis."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from masterkey_agent.models import HTMLField, HTMLForm, PublicHTML


def _safe_reference_url(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value.strip())
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", ""))


def _safe_action(value: str) -> str:
    return _safe_reference_url(value)


class _PublicHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[HTMLForm] = []
        self._current_form: HTMLForm | None = None
        self.external_script_count = 0
        self.external_style_count = 0
        self.canonical_url: str | None = None
        self.security_meta: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        attributes = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self._current_form = HTMLForm(
                method=attributes.get("method", "GET").upper(),
                action=_safe_action(attributes.get("action", "")),
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
        elif tag == "script" and attributes.get("src"):
            self.external_script_count += 1
        elif tag == "link":
            rel_tokens = {item.lower() for item in attributes.get("rel", "").split()}
            if "stylesheet" in rel_tokens and attributes.get("href"):
                self.external_style_count += 1
            if "canonical" in rel_tokens and self.canonical_url is None:
                self.canonical_url = _safe_reference_url(attributes.get("href", "")) or None
        elif tag == "meta":
            key = (attributes.get("name") or attributes.get("http-equiv") or "").lower().strip()
            if key in {"referrer", "content-security-policy", "permissions-policy"}:
                content = " ".join(attributes.get("content", "").split())
                if content:
                    self.security_meta[key] = content[:512]

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self.in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def parse_public_html(html: str) -> PublicHTML:
    parser = _PublicHTMLParser()
    parser.feed(html)
    title = " ".join("".join(parser.title_parts).split()) or None
    return PublicHTML(
        title=title,
        forms=parser.forms,
        external_script_count=parser.external_script_count,
        external_style_count=parser.external_style_count,
        canonical_url=parser.canonical_url,
        security_meta=parser.security_meta,
    )
