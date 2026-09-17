from pathlib import Path

from masterkey_agent.shell import dispatch


def test_scan_command_stores_session(monkeypatch):
    class FakeSession:
        session_id = "s-1"
        target = {"url": "https://example.com/"}
        modules = []
        evidence = []
        findings = []
        errors = []

    class FakeEngine:
        def scan(self, url):
            assert url == "https://example.com/"
            return FakeSession()

    monkeypatch.setattr("masterkey_agent.shell.build_default_registry", lambda: object())
    monkeypatch.setattr("masterkey_agent.shell.ScanEngine", lambda registry: FakeEngine())
    state = {}
    output = dispatch("scan https://example.com/", state)
    assert "Scan session: s-1" in output
    assert state["scan_session"].session_id == "s-1"


def test_scan_report_uses_structured_writer(monkeypatch, tmp_path):
    class FakeSession:
        session_id = "s-2"
        target = {"url": "https://example.com/"}

    captured = {}

    def fake_write(path, session):
        captured["path"] = Path(path)
        captured["session"] = session

    monkeypatch.setattr("masterkey_agent.shell.write_scan_report", fake_write)
    state = {"scan_session": FakeSession()}
    output = dispatch(f"report {tmp_path / 'scan.json'}", state)
    assert output.startswith("Report written:")
    assert captured["path"].name == "scan.json"
    assert captured["session"].session_id == "s-2"


def test_help_mentions_scan():
    assert "scan <url>" in dispatch("help", {})
