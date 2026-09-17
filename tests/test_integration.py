from datetime import datetime, timezone

from masterkey_agent.core.engine import ScanEngine, build_default_registry
from masterkey_agent.core.models import NetworkObservation, ScanSession
from masterkey_agent.report import write_scan_markdown_report, write_scan_report
from masterkey_agent.reporting.markdown import render_markdown


def test_default_registry_contains_expanded_v05_modules():
    names = [module.name for module in build_default_registry().modules()]
    assert names == ["auth_surface", "security_controls", "tls_intelligence"]


def test_both_report_formats_render_from_same_session(tmp_path):
    session = ScanSession(
        session_id="integration-1",
        agent_version="0.5.0",
        started_at=datetime.now(timezone.utc),
        ended_at=datetime.now(timezone.utc),
        target={"url": "https://example.com/"},
        policy={
            "timeout_seconds": 10.0,
            "max_response_bytes": 512 * 1024,
            "max_redirects": 10,
            "allow_http": True,
            "allow_https": True,
        },
    )

    json_path = tmp_path / "scan.json"
    md_path = tmp_path / "scan.md"
    write_scan_report(json_path, session)
    write_scan_markdown_report(md_path, session)

    assert "integration-1" in json_path.read_text(encoding="utf-8")
    markdown = md_path.read_text(encoding="utf-8")
    assert markdown == render_markdown(session)
    assert "Observation-only scope" in markdown


def test_scan_report_redacts_query_values(monkeypatch, tmp_path):
    target_input = "https://example.com/?token=SECRET123&password=MYSECRET"
    observation = NetworkObservation(
        url=target_input,
        scheme="https",
        host="example.com",
    )
    monkeypatch.setattr(
        "masterkey_agent.core.engine.inspect_url",
        lambda *args, **kwargs: observation,
    )

    session = ScanEngine(build_default_registry(), agent_version="0.5.0").scan(target_input)
    json_path = tmp_path / "sanitized.json"
    md_path = tmp_path / "sanitized.md"
    write_scan_report(json_path, session)
    write_scan_markdown_report(md_path, session)

    assert session.target["url"] == "https://example.com/"
    assert session.target["original_input"] == "https://example.com/"
    json_report = json_path.read_text(encoding="utf-8")
    markdown_report = md_path.read_text(encoding="utf-8")
    assert "SECRET123" not in json_report
    assert "MYSECRET" not in json_report
    assert "SECRET123" not in markdown_report
    assert "MYSECRET" not in markdown_report
