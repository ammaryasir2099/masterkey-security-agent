"""JSON and Markdown report output for structured scan sessions."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from masterkey_agent.core.models import ScanSession
from masterkey_agent.reporting.markdown import write_scan_markdown_report


def write_report(path: str | Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_scan_report(path: str | Path, session: ScanSession) -> None:
    data = session.to_dict()
    payload = {
        "agent_version": data["agent_version"],
        "session": {
            "session_id": data["session_id"],
            "started_at": data["started_at"],
            "ended_at": data["ended_at"],
            "policy": data["policy"],
        },
        "target": data["target"],
        "modules": data["modules"],
        "evidence": data["evidence"],
        "findings": data["findings"],
        "errors": data["errors"],
        "warnings": data["warnings"],
    }
    write_report(path, payload)


__all__ = ["write_report", "write_scan_report", "write_scan_markdown_report"]
