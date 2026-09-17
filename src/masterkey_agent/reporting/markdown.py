"""Human-readable Markdown reporting for observation-only assessments."""
from __future__ import annotations

import json
from pathlib import Path

from masterkey_agent.core.models import ScanSession

_SCOPE = (
    "Observation-only scope: this report is based on bounded, unauthenticated "
    "HTTP(S) GET inspection. It does not perform credential use, form submission, "
    "token harvesting, brute force, exploitation, persistence, destructive actions, "
    "or arbitrary-range scanning."
)


def _json(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def render_markdown(session: ScanSession) -> str:
    data = session.to_dict()
    lines = [
        "# Master Security Agent Assessment",
        "",
        f"**Agent version:** `{data['agent_version']}`  ",
        f"**Session:** `{data['session_id']}`  ",
        f"**Started:** `{data['started_at']}`  ",
        f"**Ended:** `{data['ended_at']}`",
        "",
        _SCOPE,
        "",
        "## Target",
        "",
        "```json",
        _json(data["target"]),
        "```",
        "",
        "## Policy",
        "",
        "```json",
        _json(data["policy"]),
        "```",
        "",
        "## Modules",
        "",
        "| Module | Success | Evidence | Findings | Error |",
        "|---|---:|---:|---:|---|",
    ]

    for module in data["modules"]:
        error = str(module.get("error") or "").replace("|", "\\|")
        lines.append(
            f"| `{module['module']}` | {'yes' if module['success'] else 'no'} | "
            f"{len(module.get('evidence', []))} | {len(module.get('findings', []))} | {error or '—'} |"
        )

    lines.extend(["", "## Evidence", ""])
    if session.evidence:
        for evidence in session.evidence:
            lines.append(f"### `{evidence.id}`")
            lines.append("")
            lines.append("```json")
            lines.append(_json(evidence.to_dict()))
            lines.append("```")
            lines.append("")
    else:
        lines.append("No evidence records were produced.")
        lines.append("")

    lines.extend(["## Findings", ""])
    if session.findings:
        for finding in session.findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"**Severity:** `{finding.severity}`  ",
                    f"**Category:** `{finding.category}`  ",
                    f"**Confidence:** `{finding.confidence}`",
                    "",
                    finding.summary,
                    "",
                    f"**Evidence:** {', '.join(f'`{ref}`' for ref in finding.evidence_refs) or 'none'}",
                    "",
                    f"**Recommendation:** {finding.recommendation}",
                    "",
                ]
            )
    else:
        lines.append("No findings were produced.")
        lines.append("")

    lines.extend(["## Errors", ""])
    if data["errors"]:
        for error in data["errors"]:
            lines.append(f"- `{error.get('module', 'unknown')}`: {error.get('message', '')}")
    else:
        lines.append("No errors were recorded.")
    lines.append("")

    lines.extend(["## Warnings", ""])
    if data["warnings"]:
        lines.extend(f"- {warning}" for warning in data["warnings"])
    else:
        lines.append("No warnings were recorded.")
    lines.append("")

    return "\n".join(lines)


def write_scan_markdown_report(path: str | Path, session: ScanSession) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_markdown(session), encoding="utf-8")
