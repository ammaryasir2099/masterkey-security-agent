"""Interactive command shell for the discovery and assessment agent."""
from __future__ import annotations

import shlex
from typing import Any

from masterkey_agent.authmap.mapper import build_auth_map
from masterkey_agent.core.engine import ScanEngine, build_default_registry
from masterkey_agent.discovery.local import collect_system_info, detect_browsers
from masterkey_agent.discovery.network import inspect_url
from masterkey_agent.report import write_report, write_scan_report

_HELP = """Commands:
  help                         Show this help.
  local                        Collect safe local OS/browser metadata.
  inspect <url>                Inspect URL/network metadata without credentials.
  map <url>                    Inspect URL and build an evidence-based auth map.
  discover <url>               Run network inspection and summarize auth evidence.
  inspect-auth <url>           Show authentication evidence and confidence.
  inspect-redirects <url>      Show observed public redirect destinations.
  inspect-headers <url>        Show safe response headers.
  inspect-public-html <url>    Show public HTML metadata only.
  scan <url>                   Run the modular v0.5 observation-only assessment.
  report <path>                Write the current state or latest scan as JSON.
  exit                         Quit.
"""


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
    links = len(html.links)
    return (
        f"Title: {html.title or 'none'}\n"
        f"Forms: {len(html.forms)}\n"
        f"Public links: {links}\n"
        f"Scripts: {len(html.scripts)}\n"
        f"Styles: {len(html.styles)}\n"
        + "\n".join(forms)
    )


def _format_scan(session) -> str:
    lines = [
        f"Scan session: {session.session_id}",
        f"Target: {session.target['url']}",
        f"Modules: {len(session.modules)}",
        f"Evidence: {len(session.evidence)}",
        f"Findings: {len(session.findings)}",
        f"Errors: {len(session.errors)}",
    ]
    for finding in session.findings:
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
    if action == "help":
        return _HELP.strip()
    if action in {"exit", "quit"}:
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

    if action == "scan" and len(parts) == 2:
        try:
            engine = ScanEngine(build_default_registry())
            session = engine.scan(parts[1])
        except ValueError as exc:
            return f"Scan error: {exc}"
        state["scan_session"] = session
        return _format_scan(session)

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
    print("Master Security Agent 0.5 — discovery mode")
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