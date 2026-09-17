"""Observation-only security-header and cookie-attribute analysis."""
from __future__ import annotations

from http.cookies import SimpleCookie
from typing import Any

from masterkey_agent.core.models import Evidence, Finding, ModuleResult
from masterkey_agent.models import NetworkObservation

SAFE_COOKIE_ATTRIBUTES = {
    "secure",
    "httponly",
    "samesite",
    "path",
    "domain",
    "max-age",
    "expires",
}


def parse_set_cookie_attributes(header_value: str) -> dict[str, str | bool]:
    """Return safe cookie attributes without retaining cookie names or values."""
    cookie = SimpleCookie()
    try:
        cookie.load(header_value)
    except Exception:
        return {}

    parsed: dict[str, str | bool] = {}
    for morsel in cookie.values():
        for key in SAFE_COOKIE_ATTRIBUTES:
            value = morsel[key]
            if key in {"secure", "httponly"}:
                if value != "":
                    parsed[key] = True
            elif value:
                parsed[key] = value
    return parsed


class SecurityControlsModule:
    name = "security_controls"

    _HEADER_MAP = {
        "strict-transport-security": ("header.hsts", "HSTS header observed"),
        "content-security-policy": ("header.csp", "CSP header observed"),
        "x-content-type-options": (
            "header.x_content_type_options",
            "X-Content-Type-Options header observed",
        ),
        "referrer-policy": ("header.referrer_policy", "Referrer-Policy header observed"),
        "permissions-policy": (
            "header.permissions_policy",
            "Permissions-Policy header observed",
        ),
        "x-frame-options": ("header.x_frame_options", "X-Frame-Options header observed"),
    }

    def run(self, target, context: dict[str, Any]) -> ModuleResult:
        observation: NetworkObservation | None = context.get("network")
        if observation is None:
            return ModuleResult(self.name, False, error="network observation missing")

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        headers = {key.lower(): value for key, value in observation.headers.items()}

        for header, (kind, description) in self._HEADER_MAP.items():
            if header in headers:
                evidence_id = f"{kind.replace('.', '-')}-1"
                evidence.append(
                    Evidence(evidence_id, self.name, kind, description, target.url)
                )
                findings.append(
                    Finding(
                        id=f"finding-{evidence_id}",
                        title=description,
                        severity="info",
                        category="security_headers",
                        summary=description,
                        evidence_refs=[evidence_id],
                        recommendation="Review the observed control against the application's security requirements.",
                        confidence="high",
                    )
                )

        if target.scheme == "https" and "strict-transport-security" not in headers:
            evidence_id = "security-missing-hsts-1"
            evidence.append(
                Evidence(
                    evidence_id,
                    self.name,
                    "header.hsts_absent",
                    "HSTS header not observed on the HTTPS response",
                    target.url,
                )
            )
            findings.append(
                Finding(
                    "finding-security-missing-hsts",
                    "HSTS header not observed",
                    "low",
                    "security_headers",
                    "The HTTPS response did not expose an HSTS header in the observed response.",
                    [evidence_id],
                    "Consider enabling HSTS after confirming that all intended application endpoints are HTTPS-capable.",
                    "high",
                )
            )

        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" in csp.lower():
            evidence_id = "header-csp-frame-ancestors-1"
            evidence.append(
                Evidence(
                    evidence_id,
                    self.name,
                    "header.csp_frame_ancestors",
                    "CSP frame-ancestors directive observed",
                    target.url,
                )
            )

        cors = observation.cors
        if cors.get("allow_origin") == "*":
            evidence_id = "security-cors-wildcard-1"
            allow_credentials = bool(cors.get("allow_credentials", False))
            severity = "low" if allow_credentials else "info"
            summary = (
                "Wildcard CORS origin observed together with credential support."
                if allow_credentials
                else "Wildcard CORS origin observed in the response."
            )
            evidence.append(
                Evidence(
                    evidence_id,
                    self.name,
                    "cors.wildcard_origin",
                    "CORS allows wildcard origin",
                    target.url,
                    metadata={"allow_credentials": allow_credentials},
                )
            )
            findings.append(
                Finding(
                    "finding-security-cors-wildcard",
                    "Wildcard CORS origin observed",
                    severity,
                    "security_headers",
                    summary,
                    [evidence_id],
                    "Review whether wildcard cross-origin access is required and whether credentialed cross-origin access is appropriate.",
                    "high",
                )
            )

        for index, attrs in enumerate(observation.cookie_attributes, start=1):
            for attribute in ("secure", "httponly", "samesite"):
                if attribute in attrs:
                    evidence_id = f"cookie-{attribute}-{index}"
                    value = attrs[attribute]
                    evidence.append(
                        Evidence(
                            evidence_id,
                            self.name,
                            f"cookie.{attribute}_attribute",
                            "present" if value is True else str(value),
                            target.url,
                        )
                    )

        return ModuleResult(
            self.name,
            True,
            evidence=evidence,
            observations={
                "security_headers_observed": len(
                    [e for e in evidence if e.evidence_type.startswith("header.")]
                ),
                "cookies_observed": len(observation.cookie_attributes),
                "cors_observed": bool(cors),
            },
            findings=findings,
        )


def observe_security_controls(observation: NetworkObservation, target) -> ModuleResult:
    """Compatibility helper for direct use outside the module registry."""
    return SecurityControlsModule().run(target, {"network": observation})
