from datetime import datetime, timezone

from masterkey_agent.core.models import Evidence, Finding, ModuleResult, ScanSession


def test_evidence_serializes_structured_metadata():
    evidence = Evidence(
        id="ev-1",
        source_module="security",
        evidence_type="header.hsts",
        value="present",
        target_url="https://example.com/",
        metadata={"max_age": "31536000"},
    )
    data = evidence.to_dict()
    assert data["evidence_type"] == "header.hsts"
    assert data["metadata"]["max_age"] == "31536000"


def test_finding_contains_explicit_evidence_refs():
    finding = Finding(
        id="finding-1",
        title="Content-Security-Policy observed",
        severity="info",
        category="security_headers",
        summary="A CSP header was observed.",
        evidence_refs=["ev-1"],
        recommendation="Review the policy for application-specific requirements.",
        confidence="high",
    )
    assert finding.to_dict()["evidence_refs"] == ["ev-1"]


def test_scan_session_serializes_without_secret_cookie_values():
    session = ScanSession(
        session_id="s-1",
        agent_version="0.4.0",
        started_at=datetime.now(timezone.utc),
        target={"url": "https://example.com/"},
        policy={"max_response_bytes": 512000},
        modules=[ModuleResult(module="security", success=True)],
        evidence=[Evidence("ev-1", "security", "cookie.secure_attribute", "present")],
    )
    data = session.to_dict()
    assert data["agent_version"] == "0.4.0"
    assert "session_secret" not in str(data).lower()
    assert "cookie-value" not in str(data)
