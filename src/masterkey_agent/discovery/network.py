"""Low-impact network metadata inspection for explicitly supplied URLs."""
from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from masterkey_agent.discovery.html import parse_public_html
from masterkey_agent.discovery.security import parse_set_cookie_attributes
from masterkey_agent.models import NetworkObservation

_ALLOWED_SCHEMES = {"http", "https"}
_MAX_HTML_BYTES = 512 * 1024
_MAX_REDIRECTS = 10
_SENSITIVE_HEADERS = {"set-cookie", "authorization", "proxy-authorization"}
_URL_HEADERS = {"location", "content-location", "refresh"}


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("URL cannot be empty")
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise ValueError("Only http and https URLs are supported")
    if not parsed.netloc:
        raise ValueError("URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs with embedded credentials are not supported")
    return urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, "")
    )


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", ""))


def _resolve_addresses(host: str) -> list[str]:
    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({item[4][0] for item in results if item[4]})


def _tls_metadata(host: str, port: int, timeout: float) -> dict | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                return {
                    "version": sock.version(),
                    "cipher": cipher[0] if cipher else None,
                    "subject": cert.get("subject", []),
                    "issuer": cert.get("issuer", []),
                    "subjectAltName": cert.get("subjectAltName", []),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except (OSError, ssl.SSLError):
        return None


class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, max_redirects: int) -> None:
        super().__init__()
        self.redirects: list[str] = []
        self.max_redirects = max_redirects

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_new_url = _safe_url(newurl)
        if len(self.redirects) >= self.max_redirects or safe_new_url in self.redirects:
            return None
        self.redirects.append(safe_new_url)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _header_pairs(headers) -> list[tuple[str, str]]:
    raw_items = getattr(headers, "raw_items", None)
    if callable(raw_items):
        return [(str(key), str(value)) for key, value in raw_items()]
    return [(str(key), str(value)) for key, value in headers.items()]


def _sanitize_headers(headers) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in _header_pairs(headers):
        name = key.lower()
        if name in _SENSITIVE_HEADERS:
            sanitized[name] = "[redacted]"
        elif name in _URL_HEADERS:
            sanitized[name] = _safe_url(value)
        else:
            sanitized[name] = value
    return sanitized


def _read_bounded_body(response, max_bytes: int) -> bytes:
    value = response.headers.get("Content-Length")
    try:
        declared = int(value) if value else None
    except ValueError:
        declared = None
    if declared is not None and declared > max_bytes:
        return b""
    data = response.read(max_bytes + 1)
    return data if len(data) <= max_bytes else data[:max_bytes]


def _safe_cookie_attributes(headers) -> list[dict[str, str | bool]]:
    get_all = getattr(headers, "get_all", None)
    raw_headers = get_all("Set-Cookie") if callable(get_all) else None
    if not raw_headers:
        combined = headers.get("Set-Cookie")
        raw_headers = [combined] if combined else []

    safe: list[dict[str, str | bool]] = []
    for raw in raw_headers:
        parsed = parse_set_cookie_attributes(raw)
        if parsed:
            safe.append(parsed)
    return safe


def inspect_url(
    url: str,
    timeout: float = 5.0,
    *,
    max_bytes: int = _MAX_HTML_BYTES,
    max_redirects: int = _MAX_REDIRECTS,
) -> NetworkObservation:
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    if max_redirects < 0:
        raise ValueError("max_redirects cannot be negative")

    normalized = normalize_url(url)
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    handler = _RecordingRedirectHandler(max_redirects)
    opener = urllib.request.build_opener(handler)
    request = urllib.request.Request(
        normalized,
        method="GET",
        headers={
            "User-Agent": "MasterSecurityAgent/0.5",
            "Accept": "text/html, */*",
        },
    )

    status_code = None
    headers: dict[str, str] = {}
    error = None
    content_type = None
    public_html = None
    cookie_attributes: list[dict[str, str | bool]] = []

    try:
        with opener.open(request, timeout=timeout) as response:
            status_code = response.status
            cookie_attributes = _safe_cookie_attributes(response.headers)
            headers = _sanitize_headers(response.headers)
            content_type = headers.get("content-type")
            if content_type and "text/html" in content_type.lower():
                body = _read_bounded_body(response, max_bytes)
                if body:
                    public_html = parse_public_html(
                        body.decode("utf-8", errors="replace"),
                        base_url=normalized,
                    )
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        cookie_attributes = _safe_cookie_attributes(exc.headers)
        headers = _sanitize_headers(exc.headers)
        content_type = headers.get("content-type")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        error = str(exc)
        headers = {"x-masterkey-error": error}

    port = parts.port or (443 if parts.scheme == "https" else 80)
    return NetworkObservation(
        url=normalized,
        scheme=parts.scheme,
        host=host,
        status_code=status_code,
        redirects=handler.redirects,
        headers=headers,
        resolved_addresses=_resolve_addresses(host),
        tls=_tls_metadata(host, port, timeout) if parts.scheme == "https" else None,
        error=error,
        content_type=content_type,
        public_html=public_html,
        cookie_attributes=cookie_attributes,
    )
