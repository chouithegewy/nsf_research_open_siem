from __future__ import annotations

import argparse
import os
import sys

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.parsers import parse_paths
from honeypot_ai.report import analyze_events, report_to_json, report_to_markdown
from honeypot_ai.splunk import report_to_splunk_hec_events, report_to_splunk_ndjson, send_to_splunk_hec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze honeypot and network-security JSON logs.")
    parser.add_argument("paths", nargs="+", help="NDJSON files or directories to analyze")
    parser.add_argument(
        "--source",
        choices=("cowrie", "dionaea", "suricata", "zeek", "tpot", "generic"),
        help="Override source detection",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "misp", "splunk"),
        default="markdown",
        help="Output format",
    )
    parser.add_argument("--splunk-hec-url", default=os.getenv("SPLUNK_HEC_URL"), help="Splunk HEC base URL")
    parser.add_argument("--splunk-token", default=os.getenv("SPLUNK_HEC_TOKEN"), help="Splunk HEC token")
    parser.add_argument("--splunk-index", default=os.getenv("SPLUNK_INDEX"), help="Splunk target index")
    parser.add_argument(
        "--splunk-source",
        default=os.getenv("SPLUNK_SOURCE", "honeypot-ai"),
        help="Splunk source value",
    )
    parser.add_argument(
        "--splunk-sourcetype",
        default=os.getenv("SPLUNK_SOURCETYPE", "honeypot:analysis"),
        help="Splunk sourcetype prefix",
    )
    parser.add_argument(
        "--splunk-host",
        default=os.getenv("SPLUNK_HOST", "honeypot-ai"),
        help="Fallback Splunk host value",
    )
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
    elif args.format == "splunk":
        splunk_options = {
            "index": args.splunk_index,
            "source": args.splunk_source,
            "sourcetype": args.splunk_sourcetype,
            "host": args.splunk_host,
        }
        if args.splunk_hec_url or args.splunk_token:
            if not args.splunk_hec_url or not args.splunk_token:
                print("honeypot-ai: Splunk HEC URL and token are both required", file=sys.stderr)
                return 2
            try:
                sent = send_to_splunk_hec(
                    args.splunk_hec_url,
                    args.splunk_token,
                    report_to_splunk_hec_events(report, **splunk_options),
                )
            except RuntimeError as exc:
                print(f"honeypot-ai: {exc}", file=sys.stderr)
                return 2
            print(f"Sent {sent} events to Splunk HEC", file=sys.stderr)
        else:
            print(report_to_splunk_ndjson(report, **splunk_options), end="")
    else:
        print(report_to_markdown(report), end="")
    return 0
