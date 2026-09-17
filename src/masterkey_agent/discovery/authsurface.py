"""Evidence-only authentication surface analysis for public responses."""
from __future__ import annotations

from typing import Any

from masterkey_agent.core.models import Evidence, Finding, ModuleResult
from masterkey_agent.core.target import Target
from masterkey_agent.models import NetworkObservation


def _has_marker(value: str, markers: tuple[str, ...]) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in markers)


_REDIRECT_MARKERS = (
    (("/oauth", "/authorize", "openid", "oidc"), "OAuth/OIDC-like"),
    (("saml", "samlrequest", "samlresponse"), "SAML-like"),
    (("/sso", "single-sign-on", "single_sign_on"), "SSO-like"),
    (
        ("login.microsoftonline.com", "accounts.google.com", "okta.com", "auth0.com", "onelogin.com"),
        "Identity-provider-like",
    ),
)


class AuthSurfaceModule:
    name = "auth_surface"

    def run(self, target: Target, context: dict[str, Any]) -> ModuleResult:
        observation: NetworkObservation | None = context.get("network")
        if observation is None:
            return ModuleResult(self.name, False, error="network observation missing")

        evidence: list[Evidence] = []
        findings: list[Finding] = []
        candidate_protocols: list[str] = []

        def add_protocol(value: str) -> None:
            if value not in candidate_protocols:
                candidate_protocols.append(value)

        for index, redirect in enumerate(observation.redirects, start=1):
            for markers, label in _REDIRECT_MARKERS:
                if _has_marker(redirect, markers):
                    evidence_suffix = label.lower().replace("/", "-").replace(" ", "-")
                    evidence.append(
                        Evidence(
                            f"auth-redirect-marker-{index}-{evidence_suffix}",
                            self.name,
                            "auth.redirect_marker",
                            f"{label} redirect marker observed",
                            target.url,
                            metadata={"marker_group": label},
                        )
                    )
                    add_protocol(label)

        challenge = observation.headers.get("www-authenticate", "")
        if challenge:
            schemes = []
            for token in challenge.replace(",", " ").split():
                if "=" in token:
                    continue
                normalized = token.strip().lower()
                if normalized in {"basic", "digest", "bearer", "negotiate", "ntlm", "mutual"}:
                    title = normalized.upper() if normalized == "ntlm" else normalized.title()
                    scheme = f"HTTP {title}"
                    if scheme not in schemes:
                        schemes.append(scheme)
                        add_protocol(scheme)
            evidence.append(
                Evidence(
                    "auth-www-1",
                    self.name,
                    "auth.www_authenticate",
                    "WWW-Authenticate challenge observed",
                    target.url,
                    {"candidate_schemes": schemes},
                )
            )

        html = observation.public_html
        if html:
            for index, form in enumerate(html.forms, start=1):
                has_password = any(
                    field.type == "password"
                    or field.autocomplete in {"current-password", "new-password"}
                    for field in form.fields
                )
                has_identity = any(
                    (field.name or "").lower()
                    in {"email", "username", "user", "identifier", "login"}
                    or (field.autocomplete or "").lower() == "username"
                    for field in form.fields
                )
                login_action = _has_marker(
                    form.action,
                    ("/login", "/signin", "/sign-in", "/auth", "/sso"),
                )

                if has_password:
                    evidence.append(
                        Evidence(
                            f"auth-password-{index}",
                            self.name,
                            "auth.password_field",
                            "Public form exposes password-field metadata",
                            target.url,
                        )
                    )
                    add_protocol("Form-based authentication")
                if has_identity:
                    evidence.append(
                        Evidence(
                            f"auth-identity-{index}",
                            self.name,
                            "auth.identity_field",
                            "Public form exposes identity-field metadata",
                            target.url,
                        )
                    )
                if login_action:
                    evidence.append(
                        Evidence(
                            f"auth-form-{index}",
                            self.name,
                            "auth.login_form",
                            "Public form action appears authentication-oriented",
                            target.url,
                        )
                    )

        if html and html.title and _has_marker(
            html.title,
            ("sign in", "signin", "log in", "login", "sso"),
        ):
            evidence.append(
                Evidence(
                    "auth-title-1",
                    self.name,
                    "auth.login_title",
                    "Public page title is authentication-oriented",
                    target.url,
                )
            )

        if evidence:
            findings.append(
                Finding(
                    id="finding-auth-surface-observed",
                    title="Authentication surface indicators observed",
                    severity="info",
                    category="authentication",
                    summary="Public response metadata contains authentication-related indicators.",
                    evidence_refs=[item.id for item in evidence],
                    recommendation="Review the exposed authentication surface and its controls within the authorized application context.",
                    confidence="high" if len(evidence) >= 4 else "medium",
                )
            )

        return ModuleResult(
            self.name,
            True,
            evidence=evidence,
            observations={
                "evidence_count": len(evidence),
                "candidate_protocols": candidate_protocols,
            },
            findings=findings,
        )


def analyze_auth_surface(observation: NetworkObservation, target: Target) -> ModuleResult:
    """Compatibility helper for direct analysis outside the registry."""
    return AuthSurfaceModule().run(target, {"network": observation})
