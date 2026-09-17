from datetime import datetime, timezone

from masterkey_agent.core.models import Evidence, Finding, ModuleResult, ScanSession
from masterkey_agent.report import render_markdown_report, write_markdown_report, write_scan_report


def _session() -> ScanSession:
    return ScanSession(
        session_id="s-markdown",
        agent_version="0.5.0",
        started_at=datetime(2026, 9, 17, tzinfo=timezone.utc),
        ended_at=datetime(2026, 9, 17, 0, 0, 1, tzinfo=timezone.utc),
        target={"url": "https://example.com/"},
        policy={"max_workers": 4},
        modules=[ModuleResult(module="security", success=True)],
        evidence=[Evidence("e1", "security", "transport.https", "present")],
        findings=[
            Finding(
                "f1",
                "Example finding",
                "low",
                "security_headers",
                "Observed safely",
                ["e1"],
                "Review the control.",
                "high",
            )
        ],
    )


def test_markdown_report_contains_summary_sections(tmp_path):
    path = tmp_path / "report.md"
    write_markdown_report(path, _session())
    text = path.read_text(encoding="utf-8")
    assert "# Master Security Agent Report" in text
    assert "## Findings" in text
    assert "## Evidence" in text
    assert "## Module Results" in text
    assert "Example finding" in text


def test_report_extension_selects_markdown(tmp_path):
    path = tmp_path / "report.md"
    write_scan_report(path, _session())
    assert path.read_text(encoding="utf-8").startswith("# Master Security Agent Report")


def test_markdown_report_redacts_query_and_fragment_from_urls(tmp_path):
    session = _session()
    session.target["url"] = "https://example.test/login?token=SUPERSECRET#fragment"
    session.evidence[0].target_url = session.target["url"]
    path = tmp_path / "report.md"
    write_markdown_report(path, session)
    text = path.read_text(encoding="utf-8")
    assert "SUPERSECRET" not in text
    assert "fragment" not in text
    assert "https://example.test/login" in text


def test_markdown_report_escapes_table_delimiters():
    session = _session()
    session.findings[0].title = "value | with `markdown`"
    text = render_markdown_report(session)
    assert "value \\| with \\`markdown\\`" in text
