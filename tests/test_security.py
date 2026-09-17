from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

from masterkey_agent.core.target import normalize_target
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.discovery.security import SecurityControlsModule, parse_set_cookie_attributes
from masterkey_agent.models import NetworkObservation


def test_cookie_parser_discards_cookie_value():
    parsed = parse_set_cookie_attributes(
        "session=super-secret; Secure; HttpOnly; SameSite=Lax; Path=/"
    )
    assert "session" not in parsed
    assert "super-secret" not in str(parsed)
    assert parsed["secure"] is True
    assert parsed["httponly"] is True
    assert parsed["samesite"] == "Lax"
    assert parsed["path"] == "/"


def test_cookie_parser_handles_attribute_only_flags():
    parsed = parse_set_cookie_attributes("x=1; Secure; HttpOnly")
    assert parsed["secure"] is True
    assert parsed["httponly"] is True


def test_network_cookie_metadata_contains_attributes_not_values():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"ok"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=SUPERSECRET; Secure; HttpOnly; SameSite=Strict")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert observation.headers["set-cookie"] == "[redacted]"
    assert observation.cookie_attributes
    assert observation.cookie_attributes[0]["secure"] is True
    assert observation.cookie_attributes[0]["httponly"] is True
    assert observation.cookie_attributes[0]["samesite"] == "Strict"
    assert "SUPERSECRET" not in str(observation.to_dict())


def test_missing_hsts_on_https_is_low_hardening_finding():
    target = normalize_target("https://example.test/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        headers={},
    )
    result = SecurityControlsModule().run(target, {"network": observation})
    finding_ids = {item.id for item in result.findings}
    assert "finding-security-missing-hsts" in finding_ids
    finding = next(item for item in result.findings if item.id == "finding-security-missing-hsts")
    assert finding.severity == "low"
    assert finding.evidence_refs == ["security-missing-hsts-1"]


def test_missing_hsts_is_not_reported_for_http_target():
    target = normalize_target("http://example.test/")
    observation = NetworkObservation(url=target.url, scheme="http", host=target.hostname)
    result = SecurityControlsModule().run(target, {"network": observation})
    assert "finding-security-missing-hsts" not in {item.id for item in result.findings}


def test_cors_wildcard_is_observation_not_exploit_claim():
    target = normalize_target("https://example.test/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        cors={"allow_origin": "*", "allow_credentials": True},
    )
    result = SecurityControlsModule().run(target, {"network": observation})
    finding = next(item for item in result.findings if item.id == "finding-security-cors-wildcard")
    assert finding.severity == "low"
    assert "exploit" not in finding.summary.lower()


def test_cors_wildcard_without_credentials_is_info():
    target = normalize_target("https://example.test/")
    observation = NetworkObservation(
        url=target.url,
        scheme="https",
        host=target.hostname,
        cors={"allow_origin": "*"},
    )
    result = SecurityControlsModule().run(target, {"network": observation})
    finding = next(item for item in result.findings if item.id == "finding-security-cors-wildcard")
    assert finding.severity == "info"
