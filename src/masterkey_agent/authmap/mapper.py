"""Translate network observations into evidence-based auth labels."""
from __future__ import annotations
from masterkey_agent.models import AuthMap, NetworkObservation

def build_auth_map(observation: NetworkObservation) -> AuthMap:
    protocols=[]; indicators=[]; evidence=[]; transport=[]; auth=[]; controls=[]
    def add(seq,item):
        if item not in seq: seq.append(item)
    if observation.scheme=="https": add(protocols,"HTTPS/TLS"); add(transport,"HTTPS/TLS"); evidence.append("Target URL uses HTTPS")
    text=" ".join(observation.redirects).lower()
    if any(x in text for x in ("/oauth","/authorize","openid","oidc")):
        add(protocols,"OAuth/OIDC-like"); add(indicators,"OAuth/OIDC-like redirect"); add(auth,"OAuth/OIDC-like redirect"); evidence.append("Observed redirect contains OAuth/OIDC-like markers")
    if any(x in text for x in ("saml","samlrequest","samlresponse")):
        add(protocols,"SAML-like"); add(indicators,"SAML-like redirect"); add(auth,"SAML-like redirect"); evidence.append("Observed redirect contains SAML-like markers")
    if "www-authenticate" in observation.headers:
        add(indicators,"WWW-Authenticate header"); add(auth,"HTTP authentication challenge"); evidence.append("WWW-Authenticate response header observed")
        challenge=observation.headers["www-authenticate"].lower()
        for scheme in ("basic","digest","bearer"):
            if scheme in challenge: add(protocols,f"HTTP {scheme.title()}")
    if "strict-transport-security" in observation.headers: add(indicators,"HSTS header"); add(controls,"HSTS header"); evidence.append("Strict-Transport-Security response header observed")
    if "content-security-policy" in observation.headers: add(indicators,"CSP header"); add(controls,"CSP header"); evidence.append("Content-Security-Policy response header observed")
    html=observation.public_html
    if html:
        for form in html.forms:
            pw=[f for f in form.fields if f.type=="password" or f.autocomplete in {"current-password","new-password"}]
            user=[f for f in form.fields if (f.name or "").lower() in {"email","username","user","identifier","login"} or (f.autocomplete or "").lower()=="username"]
            if pw: add(protocols,"Form-based authentication"); add(indicators,"Password input field"); add(auth,"Public HTML form contains a password field"); evidence.append("Public HTML form exposes password-field metadata")
            if user: add(indicators,"Username/email input field"); add(auth,"Public HTML form contains username/email-oriented field metadata"); evidence.append("Public HTML form exposes username/email field metadata")
            if any(x in form.action.lower() for x in ("/login","/signin","/sign-in","/auth")): add(indicators,"Authentication-oriented form action"); add(auth,"Public HTML form action appears authentication-oriented"); evidence.append("Public HTML form action contains a login/sign-in/auth marker")
        if html.title and any(x in html.title.lower() for x in ("sign in","signin","log in","login")): add(indicators,"Authentication-oriented page title"); add(auth,"Authentication-oriented page title"); evidence.append("Public HTML title contains a sign-in/login marker")
    confidence="low" if not auth else ("high" if len(auth)>=4 else "medium")
    return AuthMap(protocols=protocols,indicators=indicators,confidence=confidence,evidence=evidence,transport_evidence=transport,authentication_evidence=auth,security_controls=controls,authentication_confidence=confidence)
