"""Passive web metadata analysis over an already-collected public HTML snapshot."""
from __future__ import annotations

from typing import Any

from masterkey_agent.core.models import Evidence, ModuleResult
from masterkey_agent.models import NetworkObservation


class WebMetadataModule:
    name = "web_metadata"

    def run(self, target, context: dict[str, Any]) -> ModuleResult:
        observation: NetworkObservation | None = context.get("network")
        if observation is None:
            return ModuleResult(self.name, False, error="network observation missing")

        html = observation.public_html
        if html is None:
            return ModuleResult(
                self.name,
                True,
                observations={
                    "form_count": 0,
                    "field_count": 0,
                    "external_script_count": 0,
                    "external_style_count": 0,
                    "canonical_present": False,
                    "security_meta_keys": [],
                },
            )

        evidence: list[Evidence] = []
        evidence.append(
            Evidence(
                "webmeta-page-1",
                self.name,
                "content.page_metadata",
                "Public HTML metadata analyzed",
                target.url,
                metadata={
                    "title_present": bool(html.title),
                    "form_count": len(html.forms),
                    "field_count": sum(len(form.fields) for form in html.forms),
                },
            )
        )
        if html.external_script_count:
            evidence.append(
                Evidence(
                    "webmeta-scripts-1",
                    self.name,
                    "content.external_scripts",
                    f"{html.external_script_count} external script reference(s) observed",
                    target.url,
                )
            )
        if html.external_style_count:
            evidence.append(
                Evidence(
                    "webmeta-styles-1",
                    self.name,
                    "content.external_styles",
                    f"{html.external_style_count} external stylesheet reference(s) observed",
                    target.url,
                )
            )
        if html.canonical_url:
            evidence.append(
                Evidence(
                    "webmeta-canonical-1",
                    self.name,
                    "content.canonical",
                    "Canonical link metadata observed",
                    target.url,
                    metadata={"path": html.canonical_url},
                )
            )
        if html.security_meta:
            evidence.append(
                Evidence(
                    "webmeta-security-meta-1",
                    self.name,
                    "content.security_meta",
                    "Security-related HTML meta metadata observed",
                    target.url,
                    metadata={"keys": sorted(html.security_meta)},
                )
            )

        return ModuleResult(
            self.name,
            True,
            evidence=evidence,
            observations={
                "form_count": len(html.forms),
                "field_count": sum(len(form.fields) for form in html.forms),
                "external_script_count": html.external_script_count,
                "external_style_count": html.external_style_count,
                "canonical_present": bool(html.canonical_url),
                "security_meta_keys": sorted(html.security_meta),
            },
        )
