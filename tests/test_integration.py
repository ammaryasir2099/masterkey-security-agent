from datetime import datetime, timezone

from masterkey_agent.core.engine import build_default_registry
from masterkey_agent.core.models import ScanSession
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
