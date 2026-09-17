from datetime import datetime, timezone

from masterkey_agent.core.models import Evidence, Finding, ModuleResult, ScanSession
from masterkey_agent.report import write_scan_markdown_report
from masterkey_agent.reporting.markdown import render_markdown


def _session() -> ScanSession:
    return ScanSession(
        session_id="session-1",
        agent_version="0.5.0",
        started_at=datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 9, 17, 12, 0, 1, tzinfo=timezone.utc),
        target={"url": "https://example.com/", "scheme": "https", "hostname": "example.com"},
        policy={"timeout_seconds": 5, "max_response_bytes": 524288, "max_redirects": 2},
        modules=[ModuleResult("security_controls", True, observations={"controls": {"hsts": True}})],
        evidence=[
            Evidence("e1", "security_controls", "header.hsts", "HSTS header observed", "https://example.com/?token=SECRET"),
        ],
        findings=[
            Finding(
                "f1",
                "HSTS header observed",
                "info",
                "security_headers",
                "The response included HSTS.",
                ["e1"],
                "Review the control against requirements.",
                "high",
            )
        ],
        warnings=["Example warning"],
    )


def test_render_markdown_contains_deterministic_sections_and_safety_scope():
    output = render_markdown(_session())

    assert output.startswith("# Master Security Agent Assessment")
    assert "## Target" in output
    assert "## Policy" in output
    assert "## Modules" in output
    assert "## Evidence" in output
    assert "## Findings" in output
    assert "## Warnings" in output
    assert "Observation-only scope" in output
    assert "SECRET" not in output
    assert "?token=" not in output


def test_write_scan_markdown_report_creates_file(tmp_path):
    path = tmp_path / "scan.md"
    write_scan_markdown_report(path, _session())
    assert path.exists()
    assert "session-1" in path.read_text(encoding="utf-8")
