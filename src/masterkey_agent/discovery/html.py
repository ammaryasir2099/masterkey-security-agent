"""Bounded parser for public HTML authentication-surface metadata."""
from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urlsplit, urlunsplit

from masterkey_agent.models import HTMLField, HTMLForm, PublicHTML


def _safe_action(value: str) -> str:
    parsed = urlsplit(value)
    if not value:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


class _PublicHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.forms: list[HTMLForm] = []
        self._current_form: HTMLForm | None = None

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
    return PublicHTML(title=title, forms=parser.forms)
