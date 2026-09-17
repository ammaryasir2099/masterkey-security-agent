from masterkey_agent.core.target import normalize_target
from masterkey_agent.discovery.security import observe_security_controls
from masterkey_agent.models import NetworkObservation


def test_security_controls_report_structured_presence_and_frame_ancestors():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        headers={
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
            "x-frame-options": "DENY",
        },
        cookie_attributes=[{"secure": True, "httponly": True, "samesite": "Strict"}],
    )

    result = observe_security_controls(observation, target)

    assert result.observations["controls"] == {
        "strict-transport-security": True,
        "content-security-policy": True,
        "x-content-type-options": True,
        "referrer-policy": True,
        "permissions-policy": True,
        "x-frame-options": True,
    }
    assert result.observations["frame_ancestors"] is True
    assert result.observations["cookies_observed"] == 1
    assert any(item.evidence_type == "header.csp_frame_ancestors" for item in result.evidence)
    assert "session-secret" not in str(result.to_dict())


def test_security_controls_distinguish_absent_control_without_claiming_exploitability():
    target = normalize_target("https://example.com/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        headers={"content-security-policy": "default-src 'self'"},
    )

    result = observe_security_controls(observation, target)

    assert result.observations["controls"]["content-security-policy"] is True
    assert result.observations["controls"]["strict-transport-security"] is False
    assert result.findings == [
        finding for finding in result.findings
        if finding.category == "security_headers"
    ]
    assert all("vulnerability" not in finding.title.lower() for finding in result.findings)
