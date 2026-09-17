from masterkey_agent.discovery.network import normalize_url


def _start_server(handler_cls):
    from http.server import HTTPServer
    import threading

    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop_server(server, thread):
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com/"


def test_normalize_url_preserves_http():
    assert normalize_url("http://127.0.0.1:8080/path") == "http://127.0.0.1:8080/path"


def test_normalize_url_rejects_embedded_credentials():
    import pytest

    with pytest.raises(ValueError, match="credentials"):
        normalize_url("https://alice:secret@example.com/")


def test_inspect_url_reports_connection_error(monkeypatch):
    from masterkey_agent.discovery import network

    monkeypatch.setattr(
        network.urllib.request.OpenerDirector,
        "open",
        lambda *a, **k: (_ for _ in ()).throw(network.urllib.error.URLError("blocked")),
    )
    monkeypatch.setattr(network, "_resolve_addresses", lambda _host: ["127.0.0.1"])
    observation = network.inspect_url("http://example.test/")
    assert observation.status_code is None
    assert observation.error and "blocked" in observation.error


def test_inspect_url_captures_local_server_metadata():
    from http.server import BaseHTTPRequestHandler
    from masterkey_agent.discovery.network import inspect_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.end_headers()

        def log_message(self, *a):
            pass

    server, thread = _start_server(Handler)
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/")
    finally:
        _stop_server(server, thread)
    assert observation.status_code == 200
    assert observation.headers["strict-transport-security"].startswith("max-age=")
    assert "127.0.0.1" in observation.resolved_addresses


def test_inspect_url_parses_public_html_auth_metadata_and_redacts_cookie():
    from http.server import BaseHTTPRequestHandler
    from masterkey_agent.discovery.network import inspect_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'''<html><head><title>Login</title></head><body><form method="post" action="/signin"><input name="email" type="email" autocomplete="username" value="secret@example.test"><input name="password" type="password" autocomplete="current-password" value="do-not-store"></form></body></html>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=SUPERSECRET; HttpOnly")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server, thread = _start_server(Handler)
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/")
    finally:
        _stop_server(server, thread)
    assert observation.public_html and observation.public_html.title == "Login"
    assert observation.public_html.forms[0].action == "/signin"
    assert observation.headers["set-cookie"] == "[redacted]"
    serialized = str(observation.to_dict())
    assert "SUPERSECRET" not in serialized
    assert "do-not-store" not in serialized


def test_redirects_strip_query_and_fragment_data():
    from http.server import BaseHTTPRequestHandler
    from masterkey_agent.discovery.network import inspect_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{server.server_port}/login?code=SUPERSECRET#fragment-secret",
            )
            self.end_headers()

        def log_message(self, *a):
            pass

    server, thread = _start_server(Handler)
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/start")
    finally:
        _stop_server(server, thread)

    assert observation.redirects == [
        f"http://127.0.0.1:{server.server_port}/login"
    ]
    assert "SUPERSECRET" not in str(observation.to_dict())
    assert "fragment-secret" not in str(observation.to_dict())


def test_network_observation_records_cors_headers():
    from http.server import BaseHTTPRequestHandler
    from masterkey_agent.discovery.network import inspect_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()

        def log_message(self, *a):
            pass

    server, thread = _start_server(Handler)
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/")
    finally:
        _stop_server(server, thread)

    assert observation.cors["allow_origin"] == "*"
    assert observation.cors["allow_credentials"] is True


def test_network_observation_reports_response_size_limit():
    from http.server import BaseHTTPRequestHandler
    from masterkey_agent.discovery.network import inspect_url

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"x" * 128
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server, thread = _start_server(Handler)
    try:
        observation = inspect_url(f"http://127.0.0.1:{server.server_port}/", max_bytes=32)
    finally:
        _stop_server(server, thread)

    assert observation.response_size_limited is True
    assert observation.public_html is None


def test_network_observation_serializes_cors_without_sensitive_headers():
    from masterkey_agent.models import NetworkObservation

    observation = NetworkObservation(
        url="https://example.test/",
        scheme="https",
        host="example.test",
        headers={"authorization": "[redacted]", "set-cookie": "[redacted]"},
        cors={"allow_origin": "*", "allow_credentials": True},
    )
    text = str(observation.to_dict())
    assert "[redacted]" in text
    assert "Bearer secret" not in text
