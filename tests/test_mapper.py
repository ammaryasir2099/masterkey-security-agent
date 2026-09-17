from masterkey_agent.authmap.mapper import build_auth_map
from masterkey_agent.models import NetworkObservation

def test_mapper_identifies_tls_and_oauth():
    obs=NetworkObservation(url="https://accounts.example.test/login",scheme="https",host="accounts.example.test",redirects=["https://id.example.test/oauth2/authorize"],headers={"strict-transport-security":"max-age=31536000"})
    amap=build_auth_map(obs); assert "HTTPS/TLS" in amap.protocols; assert "OAuth/OIDC-like redirect" in amap.indicators

def test_mapper_low_confidence_for_sparse_observation():
    obs=NetworkObservation(url="http://localhost/",scheme="http",host="localhost"); assert build_auth_map(obs).confidence=="low"

def test_mapper_separates_authentication_evidence_from_security_headers():
    from masterkey_agent.models import HTMLField,HTMLForm,PublicHTML
    obs=NetworkObservation(url="https://accounts.example.test/login",scheme="https",host="accounts.example.test",headers={"strict-transport-security":"max-age=31536000","content-security-policy":"default-src 'self'"},public_html=PublicHTML(title="Sign in",forms=[HTMLForm(method="POST",action="/login",fields=[HTMLField(name="password",type="password",autocomplete="current-password")])]))
    amap=build_auth_map(obs); assert any("password field" in x.lower() for x in amap.authentication_evidence); assert "HSTS header" in amap.security_controls; assert "CSP header" in amap.security_controls; assert amap.authentication_confidence=="medium"

def test_mapper_does_not_upgrade_auth_confidence_for_only_hsts_and_csp():
    obs=NetworkObservation(url="https://example.test/",scheme="https",host="example.test",headers={"strict-transport-security":"max-age=31536000","content-security-policy":"default-src 'self'"}); amap=build_auth_map(obs); assert amap.authentication_confidence=="low"; assert amap.confidence=="low"
