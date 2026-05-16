from __future__ import annotations

import argparse
import sys

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.parsers import parse_paths
from honeypot_ai.report import analyze_events, report_to_json, report_to_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze honeypot and network-security JSON logs.")
    parser.add_argument("paths", nargs="+", help="NDJSON files or directories to analyze")
    parser.add_argument("--source", choices=("cowrie", "dionaea", "suricata", "zeek", "generic"), help="Override source detection")
    parser.add_argument("--format", choices=("markdown", "json", "misp"), default="markdown", help="Output format")
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "analyze":
        argv = argv[1:]
    args = build_parser().parse_args(argv)
    try:
        events = parse_paths(args.paths, source_hint=args.source)
        report = analyze_events(events)
    except (OSError, ValueError) as exc:
        print(f"honeypot-ai: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(report_to_json(report))
    elif args.format == "misp":
        print(report_to_misp_attributes(report))
    else:
        print(report_to_markdown(report), end="")
    return 0
