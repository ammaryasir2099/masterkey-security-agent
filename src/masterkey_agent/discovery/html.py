"""Bounded parser for public HTML authentication-surface metadata."""
from __future__ import annotations
from html.parser import HTMLParser
from masterkey_agent.models import HTMLField, HTMLForm, PublicHTML

class _PublicHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.title_parts=[]; self.in_title=False; self.forms=[]; self._current_form=None
    def handle_starttag(self, tag, attrs):
        a={n.lower():v or "" for n,v in attrs}; tag=tag.lower()
        if tag=="title": self.in_title=True
        elif tag=="form":
            self._current_form=HTMLForm(method=a.get("method","GET").upper(), action=a.get("action","")); self.forms.append(self._current_form)
        elif tag=="input" and self._current_form is not None:
            self._current_form.fields.append(HTMLField(name=a.get("name") or None,type=a.get("type","text").lower() or None,autocomplete=a.get("autocomplete") or None))
    def handle_endtag(self, tag):
        tag=tag.lower()
        if tag=="title": self.in_title=False
        elif tag=="form": self._current_form=None
    def handle_data(self,data):
        if self.in_title: self.title_parts.append(data)

def parse_public_html(html: str) -> PublicHTML:
    parser=_PublicHTMLParser(); parser.feed(html)
    title=" ".join("".join(parser.title_parts).split()) or None
    return PublicHTML(title=title, forms=parser.forms)
