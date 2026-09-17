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
        warnings = []
        started_at = None
        ended_at = None

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

    def fake_write(path, session, format=None):
        captured["path"] = Path(path)
        captured["session"] = session
        captured["format"] = format

    monkeypatch.setattr("masterkey_agent.shell.write_scan_report", fake_write)
    state = {"scan_session": FakeSession()}
    output = dispatch(f"report {tmp_path / 'scan.json'}", state)
    assert output.startswith("Report written:")
    assert captured["path"].name == "scan.json"
    assert captured["session"].session_id == "s-2"


def test_scan_reports_invalid_target_without_exiting_shell():
    output = dispatch("scan ftp://example.com/", {})
    assert output.startswith("Scan error:")
    assert "Unsupported URL scheme" in output


def test_help_mentions_scan_options():
    help_text = dispatch("help", {})
    assert "scan <url>" in help_text
    assert "--format markdown" in help_text
    assert "modules" in help_text


def test_version_command():
    output = dispatch("version", {})
    assert "Master Security Agent" in output
    assert output.split()[-1].count(".") == 2


def test_modules_command_lists_default_modules():
    output = dispatch("modules", {})
    assert "auth_surface" in output
    assert "security_controls" in output
    assert "web_metadata" in output


def test_scan_output_option_passes_report_format(monkeypatch, tmp_path):
    class FakeSession:
        session_id = "s-3"
        target = {"url": "https://example.com/"}
        modules = []
        evidence = []
        findings = []
        errors = []
        warnings = []
        started_at = None
        ended_at = None

    class FakeEngine:
        def scan(self, url):
            return FakeSession()

    captured = {}

    def fake_write(path, session, format=None):
        captured["path"] = Path(path)
        captured["format"] = format

    monkeypatch.setattr("masterkey_agent.shell.build_default_registry", lambda: object())
    monkeypatch.setattr("masterkey_agent.shell.ScanEngine", lambda registry: FakeEngine())
    monkeypatch.setattr("masterkey_agent.shell.write_scan_report", fake_write)

    dispatch(
        f"scan https://example.com/ --output {tmp_path / 'report.md'} --format markdown",
        {},
    )
    assert captured["path"].name == "report.md"
    assert captured["format"] == "markdown"


def test_scan_rejects_unknown_option():
    output = dispatch("scan https://example.com/ --bogus", {})
    assert output.startswith("Scan error:")
    assert "Unknown scan option" in output
