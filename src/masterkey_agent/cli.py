"""Safe non-interactive command-line interface."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from . import __version__
from .core.engine import ScanEngine, build_default_registry
from .core.target import TargetPolicy
from .report import write_scan_markdown_report, write_scan_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="masterkey-agent",
        description="Master Security Agent observation-only assessment toolkit",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a bounded observation-only scan")
    scan.add_argument("target", help="Explicit HTTP(S) target URL")
    scan.add_argument("--profile", choices=("safe",), default="safe")
    scan.add_argument("--output", required=True, help="JSON or Markdown report path")
    scan.add_argument("--format", choices=("auto", "json", "markdown"), default="auto")
    return parser


def infer_format(output: str | Path, requested: str | None) -> str:
    if requested and requested != "auto":
        return requested
    suffix = Path(output).suffix.lower()
    if suffix in {".md", ".markdown"}:
        return "markdown"
    return "json"


def safe_policy() -> TargetPolicy:
    return TargetPolicy(
        timeout_seconds=10.0,
        max_response_bytes=512 * 1024,
        max_redirects=10,
        allow_http=True,
        allow_https=True,
    )


def run_scan(args: argparse.Namespace) -> int:
    policy = safe_policy()
    try:
        engine = ScanEngine(
            build_default_registry(),
            policy=policy,
            agent_version=__version__,
        )
        session = engine.scan(args.target)
    except ValueError as exc:
        print(f"Scan error: {exc}")
        return 2

    output_format = infer_format(args.output, args.format)
    if output_format == "markdown":
        write_scan_markdown_report(args.output, session)
    else:
        write_scan_report(args.output, session)

    print(f"Scan session: {session.session_id}")
    print(f"Target: {session.target['url']}")
    print(f"Profile: {args.profile}")
    print(f"Modules: {len(session.modules)}")
    print(f"Evidence: {len(session.evidence)}")
    print(f"Findings: {len(session.findings)}")
    print(f"Errors: {len(session.errors)}")
    print(f"Report: {args.output}")
    return 0 if not session.errors else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    return 2
