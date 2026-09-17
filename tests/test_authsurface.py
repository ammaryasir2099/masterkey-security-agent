from masterkey_agent.core.target import normalize_target
from masterkey_agent.discovery.authsurface import analyze_auth_surface
from masterkey_agent.models import HTMLField, HTMLForm, NetworkObservation, PublicHTML


def test_auth_surface_correlates_login_form_and_oauth_redirect():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        redirects=["https://id.example.com/oauth/authorize?client_id=demo"],
        public_html=PublicHTML(
            title="Sign in",
            forms=[
                HTMLForm(
                    method="POST",
                    action="/login",
                    fields=[
                        HTMLField(name="username", type="text"),
                        HTMLField(name="password", type="password"),
                    ],
                )
            ],
        ),
    )
    result = analyze_auth_surface(observation, target)
    kinds = {item.evidence_type for item in result.evidence}
    assert "auth.redirect_marker" in kinds
    assert "auth.password_field" in kinds
    assert "auth.login_form" in kinds
    assert "auth.login_title" in kinds
    assert "OAuth/OIDC-like" in result.observations["candidate_protocols"]


def test_auth_surface_recognizes_http_auth_challenge():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        headers={"www-authenticate": "Bearer realm=example"},
    )
    result = analyze_auth_surface(observation, target)
    assert any(item.evidence_type == "auth.www_authenticate" for item in result.evidence)
    assert result.observations["candidate_protocols"] == ["HTTP Bearer"]


def test_auth_surface_recognizes_sso_and_identity_provider_markers():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        redirects=["https://login.microsoftonline.com/common/sso"],
    )
    result = analyze_auth_surface(observation, target)
    protocols = result.observations["candidate_protocols"]
    assert "SSO-like" in protocols
    assert "Identity-provider-like" in protocols
    kinds = {item.evidence_type for item in result.evidence}
    assert "auth.redirect_marker" in kinds


def test_auth_surface_never_records_field_values():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        public_html=PublicHTML(
            title="Login",
            forms=[
                HTMLForm(
                    method="POST",
                    action="/login",
                    fields=[HTMLField(name="password", type="password")],
                )
            ],
        ),
    )
    result = analyze_auth_surface(observation, target)
    assert "super-secret" not in str(result.to_dict())
