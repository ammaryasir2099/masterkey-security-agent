import json
from datetime import datetime, timezone

from masterkey_agent.core.models import Evidence, ScanSession
from masterkey_agent.report import write_report, write_scan_report


def test_write_report_retains_generic_v03_behavior(tmp_path):
    path = tmp_path / "report.json"
    write_report(path, {"status": "ok"})
    assert json.loads(path.read_text(encoding="utf-8")) == {"status": "ok"}


def test_write_scan_report_has_v04_shape(tmp_path):
    session = ScanSession(
        session_id="s-1",
        agent_version="0.4.0",
        started_at=datetime.now(timezone.utc),
        target={"url": "https://example.com/"},
        policy={},
        evidence=[Evidence("e1", "test", "transport.https", "present")],
    )
    path = tmp_path / "scan.json"
    write_scan_report(path, session)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert set(data) == {
        "agent_version",
        "session",
        "target",
        "modules",
        "evidence",
        "findings",
        "errors",
        "warnings",
    }
    assert data["agent_version"] == "0.4.0"
    assert data["session"]["session_id"] == "s-1"
