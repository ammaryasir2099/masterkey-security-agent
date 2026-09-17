"""Low-impact network metadata inspection for explicitly supplied URLs."""
from __future__ import annotations
import socket, ssl, urllib.error, urllib.request
from urllib.parse import urlsplit, urlunsplit
from masterkey_agent.discovery.html import parse_public_html
from masterkey_agent.models import NetworkObservation
_ALLOWED_SCHEMES={"http","https"}; _MAX_HTML_BYTES=512*1024; _SENSITIVE_HEADERS={"set-cookie","authorization","proxy-authorization"}

def normalize_url(value):
    value=value.strip()
    if not value: raise ValueError("URL cannot be empty")
    if "://" not in value: value="https://"+value
    p=urlsplit(value)
    if p.scheme.lower() not in _ALLOWED_SCHEMES: raise ValueError("Only http and https URLs are supported")
    if not p.netloc: raise ValueError("URL must include a host")
    return urlunsplit((p.scheme.lower(),p.netloc,p.path or "/",p.query,""))

def _resolve_addresses(host):
    try: results=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except OSError: return []
    return sorted({x[4][0] for x in results if x[4]})

def _tls_metadata(host,port,timeout):
    context=ssl.create_default_context()
    try:
        with socket.create_connection((host,port),timeout=timeout) as raw:
            with context.wrap_socket(raw,server_hostname=host) as s:
                cert=s.getpeercert(); cipher=s.cipher()
                return {"version":s.version(),"cipher":cipher[0] if cipher else None,"subject":cert.get("subject",[]),"issuer":cert.get("issuer",[]),"not_before":cert.get("notBefore"),"not_after":cert.get("notAfter")}
    except (OSError,ssl.SSLError): return None

class _RecordingRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self): super().__init__(); self.redirects=[]
    def redirect_request(self,req,fp,code,msg,headers,newurl): self.redirects.append(newurl); return super().redirect_request(req,fp,code,msg,headers,newurl)

def _sanitize_headers(headers):
    return {str(k).lower():("[redacted]" if str(k).lower() in _SENSITIVE_HEADERS else str(v)) for k,v in headers.items()}

def _read_bounded_body(response):
    value=response.headers.get("Content-Length")
    try: declared=int(value) if value else None
    except ValueError: declared=None
    if declared is not None and declared>_MAX_HTML_BYTES: return b""
    return response.read(_MAX_HTML_BYTES+1)

def inspect_url(url,timeout=5.0):
    normalized=normalize_url(url); parts=urlsplit(normalized); host=parts.hostname or ""; handler=_RecordingRedirectHandler(); opener=urllib.request.build_opener(handler)
    request=urllib.request.Request(normalized,method="GET",headers={"User-Agent":"MasterSecurityAgent/0.3","Accept":"text/html, */*"})
    status_code=None; headers={}; error=None; content_type=None; public_html=None
    try:
        with opener.open(request,timeout=timeout) as response:
            status_code=response.status; headers=_sanitize_headers(response.headers); content_type=headers.get("content-type")
            if content_type and "text/html" in content_type.lower():
                body=_read_bounded_body(response)
                if body: public_html=parse_public_html(body.decode("utf-8",errors="replace"))
    except urllib.error.HTTPError as exc:
        status_code=exc.code; headers=_sanitize_headers(exc.headers); content_type=headers.get("content-type")
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        error=str(exc); headers={"x-masterkey-error":error}
    port=parts.port or (443 if parts.scheme=="https" else 80)
    return NetworkObservation(url=normalized,scheme=parts.scheme,host=host,status_code=status_code,redirects=handler.redirects,headers=headers,resolved_addresses=_resolve_addresses(host),tls=_tls_metadata(host,port,timeout) if parts.scheme=="https" else None,error=error,content_type=content_type,public_html=public_html)
