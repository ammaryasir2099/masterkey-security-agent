import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from masterkey_agent.core.engine import ScanEngine, build_default_registry
from masterkey_agent.core.models import ModuleResult
from masterkey_agent.core.registry import ModuleRegistry
from masterkey_agent.core.target import TargetPolicy
from masterkey_agent.models import NetworkObservation


class Good:
    name = "good"

    def run(self, target, context):
        return ModuleResult(self.name, True, observations={"ran": True})


class Bad:
    name = "bad"

    def run(self, target, context):
        raise RuntimeError("synthetic module failure")


def test_default_registry_has_expected_modules():
    registry = build_default_registry()
    assert [module.name for module in registry.modules()] == [
        "auth_surface",
        "security_controls",
    ]


def test_engine_continues_after_module_failure(monkeypatch):
    registry = ModuleRegistry()
    registry.register(Good())
    registry.register(Bad())
    monkeypatch.setattr(
        "masterkey_agent.core.engine.inspect_url",
        lambda *args, **kwargs: NetworkObservation(
            url="https://example.com/", scheme="https", host="example.com"
        ),
    )

    session = ScanEngine(registry, TargetPolicy()).scan("https://example.com/")
    by_name = {item.module: item for item in session.modules}
    assert by_name["bad"].success is False
    assert by_name["good"].success is True
    assert any("synthetic module failure" in item["message"] for item in session.errors)


def test_engine_rejects_invalid_target_before_network(monkeypatch):
    registry = ModuleRegistry()
    registry.register(Good())
    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("network should not run")

    monkeypatch.setattr("masterkey_agent.core.engine.inspect_url", fail_if_called)
    with pytest.raises(ValueError, match="Unsupported URL scheme"):
        ScanEngine(registry, TargetPolicy()).scan("ftp://example.com/")
    assert called is False


def test_engine_session_records_target_and_end_time(monkeypatch):
    monkeypatch.setattr(
        "masterkey_agent.core.engine.inspect_url",
        lambda *args, **kwargs: NetworkObservation(
            url="http://127.0.0.1:8000/", scheme="http", host="127.0.0.1"
        ),
    )
    session = ScanEngine(ModuleRegistry(), TargetPolicy()).scan("http://127.0.0.1:8000/")
    assert session.target["url"] == "http://127.0.0.1:8000/"
    assert session.started_at is not None
    assert session.ended_at is not None


def test_full_scan_runs_builtin_modules_against_local_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/start":
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://127.0.0.1:{server.server_port}/login",
                )
                self.end_headers()
                return

            body = (
                b"<html><head><title>Sign in</title></head><body>"
                b"<form method='post' action='/login'>"
                b"<input name='username' type='text' autocomplete='username' value='do-not-store'>"
                b"<input name='password' type='password' autocomplete='current-password' value='do-not-store'>"
                b"</form></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header(
                "Set-Cookie",
                "session=SUPERSECRET; Secure; HttpOnly; SameSite=Strict",
            )
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin")
            self.send_header("Permissions-Policy", "geolocation=()")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        engine = ScanEngine(build_default_registry(), TargetPolicy())
        session = engine.scan(f"http://127.0.0.1:{server.server_port}/start")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert not session.errors
    assert any(item.module == "network_discovery" and item.success for item in session.modules)
    assert any(item.module == "auth_surface" and item.success for item in session.modules)
    assert any(item.module == "security_controls" and item.success for item in session.modules)
    assert any(item.evidence_type == "auth.password_field" for item in session.evidence)
    assert any(item.evidence_type == "cookie.httponly_attribute" for item in session.evidence)
    assert "SUPERSECRET" not in str(session.to_dict())
    assert "do-not-store" not in str(session.to_dict())
