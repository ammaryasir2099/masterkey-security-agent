"""Interactive command shell for the discovery and assessment agent."""
from __future__ import annotations

import shlex
from datetime import datetime
from typing import Any

from masterkey_agent import __version__
from masterkey_agent.authmap.mapper import build_auth_map
from masterkey_agent.core.engine import ScanEngine, build_default_registry
from masterkey_agent.discovery.local import collect_system_info, detect_browsers
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.report import write_report, write_scan_report

_HELP = f"""Commands:
  help                         Show this help.
  version                      Show the agent version.
  modules                      List registered assessment modules.
  local                        Collect safe local OS/browser metadata.
  inspect <url>                Inspect URL/network metadata without credentials.
  map <url>                    Inspect URL and build an evidence-based auth map.
  discover <url>               Run network inspection and summarize auth evidence.
  inspect-auth <url>           Show authentication evidence and confidence.
  inspect-redirects <url>      Show observed public redirect destinations.
  inspect-headers <url>        Show safe response headers.
  inspect-public-html <url>    Show public HTML title/form metadata only.
  scan <url>                   Run the modular v{__version__} observation-only assessment.
  scan <url> --format json     Run scan and select JSON report format.
  scan <url> --format markdown Run scan and select Markdown report format.
  scan <url> --output path     Run scan and write a report to path.
  report <path>                Write the current state or latest scan based on path extension.
  exit                         Quit.
"""

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _format_public_html(observation) -> str:
    html = observation.public_html
    if html is None:
        return "Public HTML: none"
    forms = []
    for index, form in enumerate(html.forms, start=1):
        fields = []
        for field in form.fields:
            value = field.name or "<unnamed>"
            value += f":{field.type or 'text'}"
            if field.autocomplete:
                value += f":autocomplete={field.autocomplete}"
            fields.append(value)
        forms.append(
            f"  FORM {index}: method={form.method} "
            f"action={form.action or 'same-document'} fields={','.join(fields)}"
        )
    return (
        f"Title: {html.title or 'none'}\n"
        f"Forms: {len(html.forms)}\n"
        f"External scripts: {html.external_script_count}\n"
        f"External styles: {html.external_style_count}\n"
        f"Canonical: {html.canonical_url or 'none'}\n"
        + "\n".join(forms)
    )


def _duration_seconds(session) -> float | None:
    if not session.started_at or not session.ended_at:
        return None
    if isinstance(session.started_at, datetime) and isinstance(session.ended_at, datetime):
        return max(0.0, (session.ended_at - session.started_at).total_seconds())
    return None


def _format_scan(session) -> str:
    duration = _duration_seconds(session)
    lines = [
        f"Scan session: {session.session_id}",
        f"Target: {session.target['url']}",
        f"Elapsed: {duration:.3f}s" if duration is not None else "Elapsed: unavailable",
        f"Modules: {len(session.modules)}",
        f"Evidence: {len(session.evidence)}",
        f"Findings: {len(session.findings)}",
        f"Errors: {len(session.errors)}",
        f"Warnings: {len(session.warnings)}",
        "Module status:",
    ]
    for result in session.modules:
        status = "OK" if result.success else "FAILED"
        suffix = f" — {result.error}" if result.error else ""
        lines.append(f"  [{status}] {result.module}{suffix}")
    lines.append("Findings by severity:")
    for finding in sorted(session.findings, key=lambda item: (_SEVERITY_ORDER[item.severity], item.id)):
        lines.append(f"  [{finding.severity.upper()}] {finding.title}")
    return "\n".join(lines)


def _parse_report_path(command: str) -> str | None:
    prefix = command.lstrip()[:6].lower()
    if prefix != "report":
        return None
    remainder = command.lstrip()[6:]
    if not remainder or not remainder[0].isspace():
        return None
    path = remainder.strip()
    if len(path) >= 2 and path[0] == path[-1] and path[0] in {"'", '"'}:
        path = path[1:-1]
    return path or None


def _parse_scan_options(parts: list[str]) -> tuple[str, str | None, str | None]:
    if not parts or parts[0].lower() != "scan":
        raise ValueError("not a scan command")
    args = parts[1:]
    url: str | None = None
    report_format: str | None = None
    output: str | None = None
    index = 0
    while index < len(args):
        token = args[index]
        if token.startswith("--"):
            if token in {"--format", "--output"}:
                if index + 1 >= len(args) or args[index + 1].startswith("--"):
                    raise ValueError(f"{token} requires a value")
                value = args[index + 1]
                if token == "--format":
                    report_format = value
                else:
                    output = value
                index += 2
                continue
            raise ValueError(f"Unknown scan option: {token}")
        if url is not None:
            raise ValueError("scan accepts exactly one target URL")
        url = token
        index += 1
    if not url:
        raise ValueError("scan requires a target URL")
    if report_format:
        normalized = report_format.lower().lstrip(".")
        if normalized == "md":
            normalized = "markdown"
        if normalized not in {"json", "markdown"}:
            raise ValueError(f"Unsupported report format: {report_format}")
        report_format = normalized
    return url, report_format, output


def dispatch(command: str, state: dict[str, Any]) -> str:
    report_path = _parse_report_path(command)
    if report_path is not None:
        session = state.get("scan_session")
        if session is not None:
            write_scan_report(report_path, session)
        else:
            write_report(report_path, state)
        return f"Report written: {report_path}"

    parts = shlex.split(command)
    if not parts:
        return ""

    action = parts[0].lower()
    if action == "help" and len(parts) == 1:
        return _HELP.strip()
    if action == "version" and len(parts) == 1:
        return f"Master Security Agent {__version__}"
    if action == "modules" and len(parts) == 1:
        return "Registered modules:\n" + "\n".join(
            f"  - {name}" for name in build_default_registry().names()
        )
    if action in {"exit", "quit"} and len(parts) == 1:
        return "__EXIT__"

    if action == "local" and len(parts) == 1:
        info = collect_system_info()
        browsers = detect_browsers()
        state["local"] = info.to_dict() | {
            "browsers": [browser.to_dict() for browser in browsers]
        }
        return (
            f"OS: {info.os_name} {info.release}\n"
            f"Hostname: {info.hostname}\n"
            f"Browsers detected: {len(browsers)}"
        )

    if action == "scan":
        try:
            url, report_format, output = _parse_scan_options(parts)
            engine = ScanEngine(build_default_registry())
            session = engine.scan(url)
            state["scan_session"] = session
            if output:
                write_scan_report(output, session, format=report_format)
            elif report_format:
                state["scan_format"] = report_format
            return _format_scan(session)
        except (ValueError, OSError) as exc:
            return f"Scan error: {exc}"

    if len(parts) == 2 and action in {
        "inspect",
        "map",
        "discover",
        "inspect-auth",
        "inspect-redirects",
        "inspect-headers",
        "inspect-public-html",
    }:
        observation = inspect_url(parts[1])
        state["network"] = observation.to_dict()

        if action == "inspect":
            return (
                f"URL: {observation.url}\n"
                f"Status: {observation.status_code if observation.status_code is not None else 'unavailable'}\n"
                f"Error: {observation.error or 'none'}\n"
                f"Resolved: {', '.join(observation.resolved_addresses) or 'none'}\n"
                f"Redirects: {len(observation.redirects)}"
            )

        if action in {"map", "discover"}:
            auth_map = build_auth_map(observation)
            state["auth_map"] = auth_map.to_dict()
            return (
                f"Transport evidence: {', '.join(auth_map.transport_evidence) or 'none'}\n"
                f"Authentication confidence: {auth_map.authentication_confidence}\n"
                f"Authentication evidence: {', '.join(auth_map.authentication_evidence) or 'none'}\n"
                f"Security controls: {', '.join(auth_map.security_controls) or 'none'}"
            )

        if action == "inspect-auth":
            auth_map = build_auth_map(observation)
            state["auth_map"] = auth_map.to_dict()
            protocols = [item for item in auth_map.protocols if item != "HTTPS/TLS"]
            return (
                f"Authentication confidence: {auth_map.authentication_confidence}\n"
                f"Authentication evidence: {', '.join(auth_map.authentication_evidence) or 'none'}\n"
                f"Candidate protocols: {', '.join(protocols) or 'none'}"
            )

        if action == "inspect-redirects":
            return (
                "Redirects:\n" + "\n".join(f"  {item}" for item in observation.redirects)
                if observation.redirects
                else "Redirects: none"
            )

        if action == "inspect-headers":
            lines = [f"{key}: {value}" for key, value in sorted(observation.headers.items())]
            return "Headers:\n" + "\n".join(lines) if lines else "Headers: none"

        return _format_public_html(observation)

    return "Unknown command or arguments. Type 'help'."


def main() -> None:
    print(f"Master Security Agent {__version__} — discovery mode")
    print("No credentials are collected or submitted. Type 'help' for commands.")
    state: dict[str, Any] = {}
    while True:
        try:
            command = input("MK> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        result = dispatch(command, state)
        if result == "__EXIT__":
            break
        if result:
            print(result)


if __name__ == "__main__":
    main()
