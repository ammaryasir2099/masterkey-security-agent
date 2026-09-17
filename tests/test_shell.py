from masterkey_agent.shell import dispatch

def test_dispatch_help(): assert "inspect <url>" in dispatch("help",{})
def test_dispatch_local_populates_state(monkeypatch):
    from masterkey_agent.models import SystemInfo
    import masterkey_agent.shell as shell
    monkeypatch.setattr(shell,"collect_system_info",lambda:SystemInfo("Windows","win32","10","lab")); monkeypatch.setattr(shell,"detect_browsers",lambda:[])
    state={}; result=dispatch("local",state); assert "Windows" in result; assert state["local"]["os_name"]=="Windows"
def test_dispatch_inspect_auth_reports_separated_categories(monkeypatch):
    import masterkey_agent.shell as shell
    from masterkey_agent.models import AuthMap,NetworkObservation
    monkeypatch.setattr(shell,"inspect_url",lambda _url:NetworkObservation(url="https://example.test/",scheme="https",host="example.test")); monkeypatch.setattr(shell,"build_auth_map",lambda _obs:AuthMap(authentication_confidence="low",transport_evidence=["HTTPS/TLS"]))
    assert "Authentication confidence: low" in dispatch("inspect-auth https://example.test/",{})
def test_dispatch_inspect_public_html_handles_no_forms(monkeypatch):
    import masterkey_agent.shell as shell
    from masterkey_agent.models import NetworkObservation,PublicHTML
    monkeypatch.setattr(shell,"inspect_url",lambda _url:NetworkObservation(url="https://example.test/",scheme="https",host="example.test",public_html=PublicHTML(title="Home")))
    result=dispatch("inspect-public-html https://example.test/",{}); assert "Title: Home" in result; assert "Forms: 0" in result
