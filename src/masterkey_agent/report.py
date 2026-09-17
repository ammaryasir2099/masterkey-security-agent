"""JSON and Markdown report output for scan sessions and legacy state."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from masterkey_agent.core.models import ScanSession


def write_report(path: str | Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _safe_url(value: Any) -> str:
    if not isinstance(value, str):
        return str(value)
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", "", ""))


def _scan_payload(session: ScanSession) -> dict[str, Any]:
    data = session.to_dict()
    target = dict(data["target"])
    if "url" in target:
        target["url"] = _safe_url(target["url"])
    evidence = []
    for item in data["evidence"]:
        safe_item = dict(item)
        if safe_item.get("target_url"):
            safe_item["target_url"] = _safe_url(safe_item["target_url"])
        evidence.append(safe_item)
    return {
        "agent_version": data["agent_version"],
        "session": {
            "session_id": data["session_id"],
            "started_at": data["started_at"],
            "ended_at": data["ended_at"],
            "policy": data["policy"],
        },
        "target": target,
        "modules": data["modules"],
        "evidence": evidence,
        "findings": data["findings"],
        "errors": data["errors"],
        "warnings": data["warnings"],
    }


def _md(value: Any) -> str:
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


def render_markdown_report(session: ScanSession) -> str:
    payload = _scan_payload(session)
    lines = [
        "# Master Security Agent Report",
        "",
        f"**Agent version:** `{_md(payload['agent_version'])}`  ",
        f"**Session:** `{_md(payload['session']['session_id'])}`  ",
        f"**Target:** `{_md(payload['target'].get('url', ''))}`",
        "",
        "## Scan Summary",
        "",
        f"- Started: `{_md(payload['session']['started_at'])}`",
        f"- Ended: `{_md(payload['session']['ended_at'])}`",
        f"- Modules: {len(payload['modules'])}",
        f"- Evidence: {len(payload['evidence'])}",
        f"- Findings: {len(payload['findings'])}",
        f"- Errors: {len(payload['errors'])}",
        f"- Warnings: {len(payload['warnings'])}",
        "",
        "## Policy",
        "",
        "```json",
        json.dumps(payload["session"]["policy"], indent=2, sort_keys=True),
        "```",
        "",
        "## Findings",
        "",
    ]
    if payload["findings"]:
        lines.append("| Severity | Category | Finding | Confidence | Evidence |")
        lines.append("|---|---|---|---|---|")
        for finding in payload["findings"]:
            lines.append(
                f"| {_md(finding['severity'])} | {_md(finding['category'])} | "
                f"{_md(finding['title'])} | {_md(finding.get('confidence', ''))} | "
                f"{_md(', '.join(finding.get('evidence_refs', [])))} |"
            )
            lines.extend([
                "",
                f"**Summary:** {_md(finding.get('summary', ''))}  ",
                f"**Recommendation:** {_md(finding.get('recommendation', ''))}",
                "",
            ])
    else:
        lines.append("No findings were generated.")
        lines.append("")

    lines.extend(["## Evidence", ""])
    if payload["evidence"]:
        lines.append("| ID | Module | Type | Value |")
        lines.append("|---|---|---|---|")
        for item in payload["evidence"]:
            lines.append(
                f"| {_md(item['id'])} | {_md(item['source_module'])} | "
                f"{_md(item['evidence_type'])} | {_md(item['value'])} |"
            )
    else:
        lines.append("No evidence was generated.")
    lines.extend(["", "## Module Results", ""])
    lines.append("| Module | Status | Error |")
    lines.append("|---|---|---|")
    for item in payload["modules"]:
        lines.append(
            f"| {_md(item['module'])} | {'success' if item['success'] else 'failed'} | "
            f"{_md(item.get('error', '') or '')} |"
        )
    lines.extend(["", "## Errors", ""])
    if payload["errors"]:
        for error in payload["errors"]:
            lines.append(
                f"- **{_md(error.get('module', ''))} / {_md(error.get('stage', ''))}:** "
                f"{_md(error.get('message', ''))}"
            )
    else:
        lines.append("None.")
    lines.extend(["", "## Warnings", ""])
    if payload["warnings"]:
        lines.extend(f"- {_md(item)}" for item in payload["warnings"])
    else:
        lines.append("None.")
    lines.append("")
    return "\n".join(lines)


def write_markdown_report(path: str | Path, session: ScanSession) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown_report(session), encoding="utf-8")


def _selected_format(path: str | Path, format: str | None) -> str:
    if format:
        normalized = format.lower().lstrip(".")
        if normalized in {"json", "markdown", "md"}:
            return "markdown" if normalized in {"markdown", "md"} else "json"
        raise ValueError(f"Unsupported report format: {format}")
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    raise ValueError("Report path must end in .json, .md, or .markdown when format is omitted")


def write_scan_report(
    path: str | Path,
    session: ScanSession,
    format: str | None = None,
) -> None:
    selected = _selected_format(path, format)
    if selected == "markdown":
        write_markdown_report(path, session)
        return
    write_report(path, _scan_payload(session))
