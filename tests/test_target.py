import pytest

from masterkey_agent.core.target import TargetPolicy, normalize_target, validate_target


def test_normalize_adds_https_to_bare_host():
    target = normalize_target("example.com")
    assert target.url == "https://example.com/"
    assert target.scheme == "https"
    assert target.hostname == "example.com"
    assert target.path == "/"


def test_normalize_preserves_explicit_port_and_path():
    target = normalize_target("http://localhost:8000/login")
    assert target.url == "http://localhost:8000/login"
    assert target.port == 8000
    assert target.path == "/login"


def test_validation_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        target = normalize_target("ftp://example.com/")
        validate_target(target)


def test_validation_rejects_missing_hostname():
    with pytest.raises(ValueError, match="hostname"):
        target = normalize_target("https:///broken")
        validate_target(target)


def test_validation_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="credentials"):
        target = normalize_target("https://alice:secret@example.com/")
        validate_target(target)


def test_default_policy_is_bounded():
    policy = TargetPolicy()
    assert policy.timeout_seconds > 0
    assert policy.max_response_bytes <= 1024 * 1024
    assert policy.max_redirects <= 10
    assert policy.allow_http is True
    assert policy.allow_https is True
