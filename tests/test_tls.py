from datetime import datetime, timezone

from masterkey_agent.discovery.tls import TLSIntelligenceModule, normalize_tls_metadata
from masterkey_agent.models import NetworkObservation
from masterkey_agent.core.target import Target


def _target() -> Target:
    return Target(
        original_input="https://example.com/",
        url="https://example.com/",
        scheme="https",
        hostname="example.com",
        port=443,
        path="/",
    )


def _certificate_fixture() -> dict:
    return {
        "version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "subject": ((('commonName', 'example.com'),),),
        "issuer": ((('commonName', 'Example CA'),),),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
        "not_before": "Jan  1 00:00:00 2025 GMT",
        "not_after": "Jan  1 00:00:00 2030 GMT",
    }


def test_normalize_tls_metadata_exposes_certificate_identity_and_sans():
    result = normalize_tls_metadata(
        _certificate_fixture(),
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result["version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["subject"] == ["commonName=example.com"]
    assert result["issuer"] == ["commonName=Example CA"]
    assert result["san"] == ["example.com", "www.example.com"]
    assert result["validity_state"] == "valid"


def test_tls_module_reports_certificate_observations_without_cookie_or_request_data():
    observation = NetworkObservation(
        url="https://example.com/",
        scheme="https",
        host="example.com",
        tls=_certificate_fixture(),
    )

    result = TLSIntelligenceModule().run(_target(), {"network": observation})

    assert result.success is True
    kinds = {item.evidence_type for item in result.evidence}
    assert "tls.version" in kinds
    assert "tls.cipher" in kinds
    assert "tls.subject" in kinds
    assert "tls.issuer" in kinds
    assert "tls.san" in kinds
    assert "tls.validity" in kinds
    assert "SUPERSECRET" not in str(result.to_dict())


def test_tls_module_handles_missing_tls_metadata_gracefully():
    observation = NetworkObservation(
        url="https://example.com/",
        scheme="https",
        host="example.com",
        tls=None,
    )

    result = TLSIntelligenceModule().run(_target(), {"network": observation})

    assert result.success is True
    assert result.evidence == []
    assert result.observations["available"] is False
