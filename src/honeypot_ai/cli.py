from __future__ import annotations

import argparse
import json
import os
import sys

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.ml import (
    DEFAULT_TARGET_ALERTS_PER_DAY,
    DEFAULT_TARGET_FPR,
    SCORER_AUTO,
    SCORER_ISOLATION_LOG1P,
    SCORER_ISOLATION_RAW,
    SCORER_RIVER,
    SUPPORTED_THRESHOLD_OBJECTIVES,
    THRESHOLD_OBJECTIVE_BEST_F1,
)
from honeypot_ai.parsers import parse_paths
from honeypot_ai.report import analyze_events, report_to_json, report_to_markdown
from honeypot_ai.splunk import report_to_splunk_hec_events, report_to_splunk_ndjson, send_to_splunk_hec
from honeypot_ai.wazuh import ml_alerts_to_wazuh_ndjson, report_to_wazuh_ndjson


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze honeypot, network-security, and endpoint ML signals.")
    subparsers = parser.add_subparsers(dest="command")
    _add_analyze_parser(subparsers.add_parser("analyze", help="Analyze honeypot and network-security logs"))
    _add_dataset_parser(subparsers.add_parser("dataset", help="Build endpoint-window ML datasets"))
    _add_train_parser(subparsers.add_parser("train", help="Train endpoint-window ML models"))
    _add_score_parser(subparsers.add_parser("score", help="Score endpoint-window datasets with a saved model"))
    _add_evaluate_parser(subparsers.add_parser("evaluate", help="Evaluate endpoint ML scorers with temporal splits"))
    _add_tune_parser(subparsers.add_parser("tune", help="Tune endpoint ML thresholds with train/calibration/test splits"))
    _add_live_sensor_parser(subparsers.add_parser("live-sensor", help="Score live or replayed packet/log traffic"))
    _add_misp_push_parser(subparsers.add_parser("misp-push", help="Push extracted IOCs into a MISP event"))
    _add_misp_pull_parser(subparsers.add_parser("misp-pull", help="Pull MISP indicators into Wazuh CDB lists"))
    _add_wazuh_preview_parser(subparsers.add_parser("wazuh-preview", help="Render a local Wazuh dashboard preview"))
    _add_wazuh_stream_parser(subparsers.add_parser("wazuh-stream", help="Tail logs into a Wazuh alert stream"))
    _add_splunk_stream_parser(subparsers.add_parser("splunk-stream", help="Tail logs into a Splunk HEC event stream"))
    _add_llm_summarize_parser(subparsers.add_parser("llm-summarize", help="Summarize events using the research-server LLM"))
    return parser


def _add_common_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source",
        choices=("cowrie", "dionaea", "suricata", "zeek", "tpot", "ebpf", "generic"),
        help="Override source detection",
    )


def _add_window_args(parser: argparse.ArgumentParser, *, default_seconds: int) -> None:
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=default_seconds,
        help=f"Endpoint rolling-window size in seconds. Defaults to {default_seconds}.",
    )
    parser.add_argument(
        "--protected-cidr",
        action="append",
        default=[],
        help="Protected endpoint CIDR to score. Can be repeated. If omitted, endpoints are inferred.",
    )


def _add_analyze_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="NDJSON files or directories to analyze")
    _add_common_source_args(parser)
    parser.add_argument(
        "--format",
        choices=("markdown", "json", "misp", "splunk", "wazuh"),
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


def _add_dataset_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="Log files or directories to parse")
    _add_common_source_args(parser)
    _add_window_args(parser, default_seconds=60)
    parser.add_argument("--output", "-o", help="Dataset output path. Defaults to stdout.")
    parser.add_argument("--format", choices=("json", "csv"), default="json", help="Dataset output format")
    parser.add_argument("--db", help="Optional DuckDB path for storing endpoint windows")


def _add_train_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("dataset", help="Endpoint-window dataset JSON or CSV")
    parser.add_argument(
        "--model-dir",
        default="data/models/current",
        help="Directory for model.joblib and metadata.json",
    )
    parser.add_argument("--threshold-quantile", type=float, default=0.95, help="Training-score quantile for alert threshold")
    parser.add_argument("--seed", type=int, default=42, help="Model seed")
    parser.add_argument(
        "--scorer",
        choices=(SCORER_AUTO, "river", SCORER_RIVER, SCORER_ISOLATION_LOG1P),
        default=SCORER_AUTO,
        help="Model scorer to save. Defaults to auto-selecting the best scorer by weak-label ROC-AUC.",
    )
    parser.add_argument(
        "--threshold-objective",
        choices=SUPPORTED_THRESHOLD_OBJECTIVES,
        help=(
            "Calibrate the deployed threshold on a held-out calibration split using this objective "
            "instead of the training-score quantile."
        ),
    )
    parser.add_argument(
        "--calibration-fraction",
        type=float,
        default=0.2,
        help="Fraction of the most recent windows held out to calibrate the threshold. Defaults to 0.2.",
    )
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=DEFAULT_TARGET_FPR,
        help=f"Maximum calibration false-positive rate for target-fpr calibration. Defaults to {DEFAULT_TARGET_FPR}.",
    )
    parser.add_argument(
        "--target-alerts-per-day",
        type=float,
        default=DEFAULT_TARGET_ALERTS_PER_DAY,
        help=(
            "Maximum calibration alert budget for target-alerts-per-day calibration. "
            f"Defaults to {DEFAULT_TARGET_ALERTS_PER_DAY}."
        ),
    )
    parser.add_argument(
        "--min-year",
        type=int,
        default=2000,
        help="Exclude windows before this year when calibrating. Defaults to 2000.",
    )
    parser.add_argument("--db", help="Optional DuckDB path for storing model metadata")


def _add_score_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("dataset", help="Endpoint-window dataset JSON or CSV")
    parser.add_argument("--model", default="data/models/current/model.joblib", help="Saved model artifact")
    parser.add_argument("--threshold", type=float, help="Override saved model threshold")
    parser.add_argument("--include-below-threshold", action="store_true", help="Emit scores for all windows")
    parser.add_argument("--format", choices=("json", "wazuh"), default="json", help="Alert output format")
    parser.add_argument("--output", "-o", help="Alert JSON output path. Defaults to stdout.")
    parser.add_argument("--db", help="Optional DuckDB path for storing alerts")


def _add_evaluate_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("dataset", help="Endpoint-window dataset JSON or CSV")
    parser.add_argument(
        "--train-fraction",
        type=float,
        default=0.7,
        help="Fraction of earliest windows used for training. Defaults to 0.7.",
    )
    parser.add_argument("--threshold-quantile", type=float, default=0.95, help="Training-score quantile for alert threshold")
    parser.add_argument("--seed", type=int, default=42, help="Model seed")
    parser.add_argument(
        "--min-year",
        type=int,
        default=2000,
        help="Exclude windows before this year as likely placeholder timestamps. Defaults to 2000.",
    )
    parser.add_argument(
        "--exclude-rule-features",
        action="store_true",
        help="Exclude weak-label-defining features from the model input to measure leakage-free behavioral detection.",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Evaluation output format")
    parser.add_argument("--output", "-o", help="Optional evaluation output path")


def _add_tune_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("dataset", help="Endpoint-window dataset JSON or CSV")
    parser.add_argument(
        "--train-fraction",
        type=float,
        default=0.6,
        help="Fraction of earliest windows used for training. Defaults to 0.6.",
    )
    parser.add_argument(
        "--calibration-fraction",
        type=float,
        default=0.2,
        help="Fraction of windows after training used to tune thresholds. Defaults to 0.2.",
    )
    parser.add_argument("--threshold-quantile", type=float, default=0.95, help="Fallback training-score quantile")
    parser.add_argument(
        "--threshold-objective",
        choices=SUPPORTED_THRESHOLD_OBJECTIVES,
        default=THRESHOLD_OBJECTIVE_BEST_F1,
        help="Calibration objective for selecting thresholds. Defaults to best-f1.",
    )
    parser.add_argument(
        "--target-fpr",
        type=float,
        default=DEFAULT_TARGET_FPR,
        help=f"Maximum calibration false-positive rate for target-fpr tuning. Defaults to {DEFAULT_TARGET_FPR}.",
    )
    parser.add_argument(
        "--target-alerts-per-day",
        type=float,
        default=DEFAULT_TARGET_ALERTS_PER_DAY,
        help=(
            "Maximum calibration alert budget for target-alerts-per-day tuning. "
            f"Defaults to {DEFAULT_TARGET_ALERTS_PER_DAY}."
        ),
    )
    parser.add_argument("--seed", type=int, default=42, help="Model seed")
    parser.add_argument(
        "--min-year",
        type=int,
        default=2000,
        help="Exclude windows before this year as likely placeholder timestamps. Defaults to 2000.",
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Tuning output format")
    parser.add_argument("--output", "-o", help="Optional tuning output path")


def _add_live_sensor_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="*", help="Optional log files/directories to replay through the live scorer")
    _add_common_source_args(parser)
    _add_window_args(parser, default_seconds=1)
    parser.add_argument("--model", default="data/models/current/model.joblib", help="Saved model artifact")
    parser.add_argument("--pcap", help="Replay packets from a pcap file")
    parser.add_argument("--interface", help="Capture packets from a Linux network interface")
    parser.add_argument("--limit", type=int, help="Maximum packets/windows to process")
    parser.add_argument("--threshold", type=float, help="Override saved model threshold")
    parser.add_argument("--include-below-threshold", action="store_true", help="Emit scores for all windows")
    parser.add_argument("--format", choices=("json", "wazuh"), default="json", help="Alert output format")
    parser.add_argument("--output", "-o", help="Alert JSON output path. Defaults to stdout.")
    parser.add_argument("--db", default=os.getenv("HONEYPOT_WEB_DB"), help="DuckDB path for storing alerts")


def _add_misp_push_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="NDJSON files or directories to analyze and export to MISP")
    _add_common_source_args(parser)
    parser.add_argument("--misp-url", default=os.getenv("MISP_URL"), help="MISP base URL")
    parser.add_argument(
        "--misp-key",
        default=os.getenv("MISP_API_KEY") or os.getenv("MISP_KEY"),
        help="MISP automation/API key",
    )
    parser.add_argument("--event-info", default="Honeypot AI IOC export", help="MISP event info/title")
    parser.add_argument("--distribution", default="0", help="MISP event distribution. Defaults to 0.")
    parser.add_argument("--threat-level-id", default="2", help="MISP threat_level_id. Defaults to 2.")
    parser.add_argument("--analysis", default="0", help="MISP analysis value. Defaults to 0.")
    parser.add_argument("--tag", action="append", default=[], help="MISP tag name to attach to the event. Can be repeated.")
    parser.add_argument("--dry-run", action="store_true", help="Print the MISP event payload instead of sending it")


def _add_misp_pull_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--misp-url", default=os.getenv("MISP_URL"), help="MISP base URL")
    parser.add_argument(
        "--misp-key",
        default=os.getenv("MISP_API_KEY") or os.getenv("MISP_KEY"),
        help="MISP automation/API key",
    )
    parser.add_argument(
        "--output-dir",
        default="deploy/wazuh/cdb-lists/generated",
        help="Directory for Wazuh CDB list files. Defaults to deploy/wazuh/cdb-lists/generated.",
    )
    parser.add_argument("--include-non-ids", action="store_true", help="Include MISP attributes where to_ids is false")


def _add_wazuh_preview_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="Wazuh-format NDJSON files to preview")
    parser.add_argument(
        "--spec",
        default="deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json",
        help="Dashboard spec JSON. Defaults to deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="build/wazuh-preview/index.html",
        help="Preview HTML output path. Defaults to build/wazuh-preview/index.html.",
    )
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=5,
        help="Browser auto-refresh interval for the preview HTML. Use 0 to disable. Defaults to 5.",
    )


def _add_wazuh_stream_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="Raw NDJSON or Wazuh-format NDJSON files to tail")
    _add_common_source_args(parser)
    parser.add_argument(
        "--input-format",
        choices=("raw", "wazuh"),
        default="raw",
        help="Input format. raw parses source logs and emits Wazuh alerts; wazuh passes through validated alerts.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="build/wazuh-live/alerts.ndjson",
        help="Wazuh alert stream output path. Defaults to build/wazuh-live/alerts.ndjson.",
    )
    parser.add_argument("--state-file", help="Offset state file. Defaults to <output>.state.json.")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="Polling interval for continuous mode.")
    parser.add_argument("--once", action="store_true", help="Process current appended lines once and exit.")
    parser.add_argument(
        "--preview-output",
        help="Optional local dashboard preview HTML to regenerate after each batch.",
    )
    parser.add_argument(
        "--preview-spec",
        default="deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json",
        help="Dashboard spec JSON for preview rendering.",
    )
    parser.add_argument(
        "--refresh-seconds",
        type=int,
        default=5,
        help="Browser auto-refresh interval for generated preview HTML. Use 0 to disable. Defaults to 5.",
    )


def _add_splunk_stream_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("paths", nargs="+", help="Raw NDJSON files to tail")
    _add_common_source_args(parser)
    parser.add_argument(
        "--output",
        "-o",
        default="build/splunk-live/events.ndjson",
        help="Splunk HEC-format NDJSON output path for file-monitor ingestion. Defaults to build/splunk-live/events.ndjson.",
    )
    parser.add_argument("--state-file", help="Offset state file. Defaults to <output>.state.json.")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="Polling interval for continuous mode.")
    parser.add_argument("--once", action="store_true", help="Process current appended lines once and exit.")
    parser.add_argument(
        "--splunk-hec-url",
        default=os.getenv("SPLUNK_HEC_URL"),
        help="Optional Splunk HEC base URL. When set with --splunk-token, events are also pushed to HEC.",
    )
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


COMMANDS = {
    "analyze",
    "dataset",
    "train",
    "score",
    "evaluate",
    "tune",
    "live-sensor",
    "misp-push",
    "misp-pull",
    "wazuh-preview",
    "wazuh-stream",
    "splunk-stream",
    "llm-summarize",
}


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] not in COMMANDS and argv[0] not in {"-h", "--help"}:
        argv = ["analyze", *argv]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "dataset":
        return _dataset(args)
    if args.command == "train":
        return _train(args)
    if args.command == "score":
        return _score(args)
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "tune":
        return _tune(args)
    if args.command == "live-sensor":
        return _live_sensor(args)
    if args.command == "misp-push":
        return _misp_push(args)
    if args.command == "misp-pull":
        return _misp_pull(args)
    if args.command == "wazuh-preview":
        return _wazuh_preview(args)
    if args.command == "wazuh-stream":
        return _wazuh_stream(args)
    if args.command == "splunk-stream":
        return _splunk_stream(args)
    if args.command == "llm-summarize":
        return _llm_summarize(args)
    if args.command in {None, "analyze"}:
        if args.command is None:
            parser.print_help()
            return 2
        return _analyze(args)
    return 2




def _analyze(args: argparse.Namespace) -> int:
    try:
        events = parse_paths(args.paths, source_hint=args.source)

        # Wire LLM summary if enabled
        from honeypot_ai.llm import LLMClient
        client = LLMClient()
        llm_summary = None
        if client.is_enabled() and events:
            raw_dicts = []
            for e in events:
                if e.raw:
                    raw_dicts.append(e.raw)
                else:
                    event_dict = {
                        "source": e.source,
                        "event_type": e.event_type,
                        "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                        "src_ip": e.src_ip,
                        "src_port": e.src_port,
                        "dest_ip": e.dest_ip,
                        "dest_port": e.dest_port,
                        "protocol": e.protocol,
                        "username": e.username,
                        "password": e.password,
                        "command": e.command,
                        "url": e.url,
                        "domain": e.domain,
                        "filename": e.filename,
                    }
                    raw_dicts.append({k: v for k, v in event_dict.items() if v is not None})
            llm_summary = client.summarize_events(raw_dicts[:100])

        report = analyze_events(events, llm_summary=llm_summary)
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
    elif args.format == "wazuh":
        print(report_to_wazuh_ndjson(report), end="")
    else:
        print(report_to_markdown(report), end="")
    return 0


def _dataset(args: argparse.Namespace) -> int:
    from honeypot_ai.endpoint import build_endpoint_windows, write_windows
    from honeypot_ai.ml_store import insert_endpoint_windows

    try:
        events = parse_paths(args.paths, source_hint=args.source)
        windows = build_endpoint_windows(
            events,
            window_seconds=args.window_seconds,
            protected_cidrs=args.protected_cidr,
        )
        output = write_windows(windows, args.output, fmt=args.format)
        if output is not None:
            print(output, end="")
        if args.db:
            inserted = insert_endpoint_windows(args.db, windows)
            print(f"Stored {inserted} endpoint windows in {args.db}", file=sys.stderr)
    except (OSError, ValueError) as exc:
        print(f"honeypot-ai dataset: {exc}", file=sys.stderr)
        return 2
    return 0


def _train(args: argparse.Namespace) -> int:
    from honeypot_ai.endpoint import read_windows
    from honeypot_ai.ml import metadata_record, train_calibrated_model, train_model
    from honeypot_ai.ml_store import insert_model_metadata

    try:
        windows = read_windows(args.dataset)
        if args.threshold_objective:
            result = train_calibrated_model(
                windows,
                args.model_dir,
                threshold_objective=args.threshold_objective,
                calibration_fraction=args.calibration_fraction,
                threshold_quantile=args.threshold_quantile,
                target_fpr=args.target_fpr,
                target_alerts_per_day=args.target_alerts_per_day,
                seed=args.seed,
                scorer=args.scorer,
                min_year=args.min_year,
            )
        else:
            result = train_model(
                windows,
                args.model_dir,
                threshold_quantile=args.threshold_quantile,
                seed=args.seed,
                scorer=args.scorer,
            )
        metadata = metadata_record(result)
        if args.db:
            insert_model_metadata(args.db, metadata)
        print(
            f"Trained {result.model_id} with {result.selected_scorer} on {result.training_rows} window(s); "
            f"threshold={result.threshold:.6f} ({result.metrics.get('threshold_source', 'training_quantile')}); "
            f"model={result.model_path}"
        )
        print(f"Metadata: {result.metadata_path}")
    except (OSError, ValueError, ImportError) as exc:
        print(f"honeypot-ai train: {exc}", file=sys.stderr)
        return 2
    return 0


def _score(args: argparse.Namespace) -> int:
    from honeypot_ai.endpoint import read_windows
    from honeypot_ai.ml import load_model, score_windows, write_alerts
    from honeypot_ai.ml_store import insert_ml_alerts

    try:
        windows = read_windows(args.dataset)
        artifact = load_model(args.model)
        alerts = score_windows(
            windows,
            artifact,
            threshold=args.threshold,
            include_below_threshold=args.include_below_threshold,
        )
        output = _write_alert_output(alerts, args.output, args.format, write_alerts)
        if output is not None:
            print(output, end="")
        if args.db:
            inserted = insert_ml_alerts(args.db, alerts)
            print(f"Stored {inserted} ML alert(s) in {args.db}", file=sys.stderr)
    except (OSError, ValueError, ImportError) as exc:
        print(f"honeypot-ai score: {exc}", file=sys.stderr)
        return 2
    return 0


def _evaluate(args: argparse.Namespace) -> int:
    from pathlib import Path

    from honeypot_ai.endpoint import read_windows
    from honeypot_ai.ml import behavioral_feature_names, evaluate_temporal_split

    try:
        windows = read_windows(args.dataset)
        result = evaluate_temporal_split(
            windows,
            train_fraction=args.train_fraction,
            threshold_quantile=args.threshold_quantile,
            seed=args.seed,
            min_year=args.min_year,
            feature_names=behavioral_feature_names() if args.exclude_rule_features else None,
        )
        if args.format == "json":
            output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        else:
            output = evaluation_to_markdown(result)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except (OSError, ValueError, ImportError) as exc:
        print(f"honeypot-ai evaluate: {exc}", file=sys.stderr)
        return 2
    return 0


def _tune(args: argparse.Namespace) -> int:
    from pathlib import Path

    from honeypot_ai.endpoint import read_windows
    from honeypot_ai.ml import tune_temporal_split

    try:
        windows = read_windows(args.dataset)
        result = tune_temporal_split(
            windows,
            train_fraction=args.train_fraction,
            calibration_fraction=args.calibration_fraction,
            threshold_quantile=args.threshold_quantile,
            threshold_objective=args.threshold_objective,
            target_fpr=args.target_fpr,
            target_alerts_per_day=args.target_alerts_per_day,
            seed=args.seed,
            min_year=args.min_year,
        )
        if args.format == "json":
            output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        else:
            output = tuning_to_markdown(result)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except (OSError, ValueError, ImportError) as exc:
        print(f"honeypot-ai tune: {exc}", file=sys.stderr)
        return 2
    return 0


def _live_sensor(args: argparse.Namespace) -> int:
    from honeypot_ai.endpoint import build_endpoint_windows, build_endpoint_windows_from_packets
    from honeypot_ai.ml import load_model, score_windows, write_alerts
    from honeypot_ai.ml_store import insert_ml_alerts
    from honeypot_ai.packets import iter_interface, iter_pcap

    try:
        artifact = load_model(args.model)
        if args.pcap:
            packets = _limit(iter_pcap(args.pcap), args.limit)
            windows = build_endpoint_windows_from_packets(
                packets,
                window_seconds=args.window_seconds,
                protected_cidrs=args.protected_cidr,
            )
        elif args.interface:
            packets = iter_interface(args.interface, limit=args.limit)
            windows = build_endpoint_windows_from_packets(
                packets,
                window_seconds=args.window_seconds,
                protected_cidrs=args.protected_cidr,
            )
        elif args.paths:
            events = parse_paths(args.paths, source_hint=args.source)
            windows = build_endpoint_windows(
                events,
                window_seconds=args.window_seconds,
                protected_cidrs=args.protected_cidr,
            )
            if args.limit is not None:
                windows = windows[: args.limit]
        else:
            print("honeypot-ai live-sensor: provide --pcap, --interface, or replay paths", file=sys.stderr)
            return 2
        alerts = score_windows(
            windows,
            artifact,
            threshold=args.threshold,
            include_below_threshold=args.include_below_threshold,
        )
        output = _write_alert_output(alerts, args.output, args.format, write_alerts)
        if output is not None:
            print(output, end="")
        if args.db:
            inserted = insert_ml_alerts(args.db, alerts)
            print(f"Stored {inserted} live ML alert(s) in {args.db}", file=sys.stderr)
    except PermissionError as exc:
        print(f"honeypot-ai live-sensor: packet capture requires root or CAP_NET_RAW: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, ImportError) as exc:
        print(f"honeypot-ai live-sensor: {exc}", file=sys.stderr)
        return 2
    return 0


def _misp_push(args: argparse.Namespace) -> int:
    from honeypot_ai.misp import build_misp_event_payload, push_misp_event

    try:
        events = parse_paths(args.paths, source_hint=args.source)
        report = analyze_events(events)
        payload = build_misp_event_payload(
            report,
            info=args.event_info,
            distribution=args.distribution,
            threat_level_id=args.threat_level_id,
            analysis=args.analysis,
            tags=args.tag,
        )
        if args.dry_run:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        if not args.misp_url or not args.misp_key:
            print("honeypot-ai misp-push: MISP URL and key are required unless --dry-run is used", file=sys.stderr)
            return 2
        response = push_misp_event(args.misp_url, args.misp_key, payload)
        print(json.dumps(response, indent=2, sort_keys=True))
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"honeypot-ai misp-push: {exc}", file=sys.stderr)
        return 2
    return 0


def _misp_pull(args: argparse.Namespace) -> int:
    from honeypot_ai.misp import pull_misp_attributes, write_wazuh_cdb_lists

    if not args.misp_url or not args.misp_key:
        print("honeypot-ai misp-pull: MISP URL and key are required", file=sys.stderr)
        return 2
    try:
        attributes = pull_misp_attributes(args.misp_url, args.misp_key, to_ids_only=not args.include_non_ids)
        counts = write_wazuh_cdb_lists(attributes, args.output_dir, include_non_ids=args.include_non_ids)
        total = sum(counts.values())
        print(f"Wrote {total} Wazuh CDB indicator(s) to {args.output_dir}: {counts}", file=sys.stderr)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"honeypot-ai misp-pull: {exc}", file=sys.stderr)
        return 2
    return 0


def _wazuh_preview(args: argparse.Namespace) -> int:
    from honeypot_ai.wazuh_preview import write_dashboard_preview

    try:
        summary = write_dashboard_preview(
            args.paths,
            args.output,
            spec_path=args.spec,
            refresh_seconds=max(0, args.refresh_seconds),
        )
    except ValueError as exc:
        print(f"honeypot-ai wazuh-preview: {exc}", file=sys.stderr)
        return 2
    print(
        "Rendered Wazuh dashboard preview to {} "
        "(events={}, high_confidence={}, misp_matches={}, ebpf_events={})".format(
            args.output,
            summary["events"],
            summary["high_confidence"],
            summary["misp_matches"],
            summary["ebpf_events"],
        ),
        file=sys.stderr,
    )
    return 0


def _wazuh_stream(args: argparse.Namespace) -> int:
    from honeypot_ai.realtime import stream_forever, stream_once

    try:
        if args.once:
            result = stream_once(
                args.paths,
                output_path=args.output,
                state_path=args.state_file,
                source_hint=args.source,
                input_format=args.input_format,
                preview_output=args.preview_output,
                preview_spec=args.preview_spec,
                refresh_seconds=max(0, args.refresh_seconds),
            )
            print(
                "Processed {} raw line(s), {} parsed event(s), {} Wazuh alert event(s) into {}".format(
                    result.raw_lines,
                    result.parsed_events,
                    result.alert_events,
                    args.output,
                ),
                file=sys.stderr,
            )
            return 0

        print(
            f"Streaming {len(args.paths)} path(s) to {args.output}; press Ctrl-C to stop",
            file=sys.stderr,
        )
        stream_forever(
            args.paths,
            output_path=args.output,
            state_path=args.state_file,
            source_hint=args.source,
            input_format=args.input_format,
            preview_output=args.preview_output,
            preview_spec=args.preview_spec,
            refresh_seconds=max(0, args.refresh_seconds),
            poll_seconds=args.poll_seconds,
        )
    except KeyboardInterrupt:
        print("Stopped Wazuh stream", file=sys.stderr)
        return 0
    except ValueError as exc:
        print(f"honeypot-ai wazuh-stream: {exc}", file=sys.stderr)
        return 2
    return 0


def _splunk_stream(args: argparse.Namespace) -> int:
    from honeypot_ai.realtime import splunk_stream_forever, splunk_stream_once

    if bool(args.splunk_hec_url) != bool(args.splunk_token):
        print("honeypot-ai splunk-stream: --splunk-hec-url and --splunk-token are both required", file=sys.stderr)
        return 2

    stream_kwargs = {
        "output_path": args.output,
        "state_path": args.state_file,
        "source_hint": args.source,
        "hec_url": args.splunk_hec_url or None,
        "hec_token": args.splunk_token or None,
        "index": args.splunk_index,
        "source": args.splunk_source,
        "sourcetype": args.splunk_sourcetype,
        "host": args.splunk_host,
    }

    try:
        if args.once:
            result = splunk_stream_once(args.paths, **stream_kwargs)
            print(
                "Processed {} raw line(s), {} parsed event(s), {} Splunk HEC event(s) ({} pushed) into {}".format(
                    result.raw_lines,
                    result.parsed_events,
                    result.hec_events,
                    result.sent_events,
                    args.output,
                ),
                file=sys.stderr,
            )
            return 0

        print(
            f"Streaming {len(args.paths)} path(s) to {args.output}; press Ctrl-C to stop",
            file=sys.stderr,
        )
        splunk_stream_forever(args.paths, poll_seconds=args.poll_seconds, **stream_kwargs)
    except KeyboardInterrupt:
        print("Stopped Splunk stream", file=sys.stderr)
        return 0
    except (ValueError, RuntimeError) as exc:
        print(f"honeypot-ai splunk-stream: {exc}", file=sys.stderr)
        return 2
    return 0


def _write_alert_output(alerts: object, output_path: str | None, fmt: str, json_writer: object) -> str | None:
    if fmt == "wazuh":
        payload = ml_alerts_to_wazuh_ndjson(alerts)  # type: ignore[arg-type]
        if output_path is None:
            return payload
        from pathlib import Path

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        return None
    return json_writer(alerts, output_path)  # type: ignore[operator]


def _limit(iterable, limit: int | None):
    if limit is None:
        yield from iterable
        return
    for index, item in enumerate(iterable):
        if index >= limit:
            return
        yield item


def evaluation_to_markdown(result: dict[str, object]) -> str:
    split = result.get("split", {})
    labels = result.get("labels", {})
    data_quality = result.get("data_quality", {})
    scorers = result.get("scorers", {})
    best = result.get("best_scorers", {})
    if not isinstance(split, dict) or not isinstance(labels, dict) or not isinstance(data_quality, dict) or not isinstance(scorers, dict):
        raise ValueError("evaluation result did not contain the expected mappings")
    lines = [
        "# Endpoint ML Temporal Evaluation",
        "",
        f"- Input rows: {data_quality.get('input_rows')}",
        f"- Evaluated rows: {data_quality.get('evaluated_rows')}",
        f"- Excluded rows: {data_quality.get('excluded_rows')} before min year {data_quality.get('min_year')}",
        f"- Train rows: {split.get('train_rows')} ({split.get('train_start')} to {split.get('train_end')})",
        f"- Fit rows: {split.get('fit_rows')}",
        f"- Test rows: {split.get('test_rows')} ({split.get('test_start')} to {split.get('test_end')})",
        f"- Train fraction: {split.get('train_fraction')}",
        f"- Threshold quantile: {result.get('threshold_quantile')}",
        "",
        "## Labels",
        "",
        "| Split | Benign | Malicious | Unknown |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name in ("train", "fit", "test"):
        counts = labels.get(name, {})
        if not isinstance(counts, dict):
            counts = {}
        lines.append(
            f"| {name} | {counts.get('benign', 0)} | {counts.get('malicious', 0)} | {counts.get('unknown', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Scorers",
            "",
            "| Scorer | ROC-AUC | PR-AUC | Precision | Recall | F1 | Best F1 | Best F1 threshold | FPR | Alerts | High | Medium | Alerts/day |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for scorer in (SCORER_RIVER, SCORER_ISOLATION_RAW, SCORER_ISOLATION_LOG1P):
        raw_metrics = scorers.get(scorer)
        if not isinstance(raw_metrics, dict) or raw_metrics.get("skipped"):
            skipped = raw_metrics.get("skipped") if isinstance(raw_metrics, dict) else "not evaluated"
            lines.append(f"| {scorer} | skipped: {skipped} |  |  |  |  |  |  |  |  |  |  |  |")
            continue
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                scorer,
                _format_metric(raw_metrics.get("roc_auc")),
                _format_metric(raw_metrics.get("pr_auc")),
                _format_metric(raw_metrics.get("precision_at_threshold")),
                _format_metric(raw_metrics.get("recall_at_threshold")),
                _format_metric(raw_metrics.get("f1_at_threshold")),
                _format_metric(raw_metrics.get("best_f1")),
                _format_metric(raw_metrics.get("best_f1_threshold")),
                _format_metric(raw_metrics.get("false_positive_rate")),
                raw_metrics.get("alerts", ""),
                raw_metrics.get("high_alerts", ""),
                raw_metrics.get("medium_alerts", ""),
                _format_metric(raw_metrics.get("alerts_per_day")),
            )
        )
    if isinstance(best, dict):
        lines.extend(
            [
                "",
                "## Best Scorers",
                "",
                f"- PR-AUC: {best.get('pr_auc')}",
                f"- ROC-AUC: {best.get('roc_auc')}",
                f"- F1 at threshold: {best.get('f1_at_threshold')}",
                f"- Best F1 diagnostic: {best.get('best_f1')}",
                f"- Lowest FPR: {best.get('lowest_false_positive_rate')}",
                f"- Lowest alerts/day: {best.get('lowest_alerts_per_day')}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def tuning_to_markdown(result: dict[str, object]) -> str:
    split = result.get("split", {})
    labels = result.get("labels", {})
    data_quality = result.get("data_quality", {})
    scorers = result.get("scorers", {})
    best = result.get("best_scorers", {})
    if not isinstance(split, dict) or not isinstance(labels, dict) or not isinstance(data_quality, dict) or not isinstance(scorers, dict):
        raise ValueError("tuning result did not contain the expected mappings")
    lines = [
        "# Endpoint ML Threshold Tuning",
        "",
        f"- Input rows: {data_quality.get('input_rows')}",
        f"- Evaluated rows: {data_quality.get('evaluated_rows')}",
        f"- Excluded rows: {data_quality.get('excluded_rows')} before min year {data_quality.get('min_year')}",
        f"- Train rows: {split.get('train_rows')} ({split.get('train_start')} to {split.get('train_end')})",
        f"- Fit rows: {split.get('fit_rows')}",
        f"- Calibration rows: {split.get('calibration_rows')} ({split.get('calibration_start')} to {split.get('calibration_end')})",
        f"- Test rows: {split.get('test_rows')} ({split.get('test_start')} to {split.get('test_end')})",
        f"- Train fraction: {split.get('train_fraction')}",
        f"- Calibration fraction: {split.get('calibration_fraction')}",
        f"- Threshold objective: {result.get('threshold_objective')}",
        f"- Target FPR: {result.get('target_fpr')}",
        f"- Target alerts/day: {result.get('target_alerts_per_day')}",
        "",
        "## Labels",
        "",
        "| Split | Benign | Malicious | Unknown |",
        "| --- | ---: | ---: | ---: |",
    ]
    for name in ("train", "fit", "calibration", "test"):
        counts = labels.get(name, {})
        if not isinstance(counts, dict):
            counts = {}
        lines.append(
            f"| {name} | {counts.get('benign', 0)} | {counts.get('malicious', 0)} | {counts.get('unknown', 0)} |"
        )
    lines.extend(
        [
            "",
            "## Held-Out Test Metrics",
            "",
            "| Scorer | Threshold | Source | ROC-AUC | PR-AUC | Precision | Recall | F1 | Best F1 | FPR | Alerts | Alerts/day | High | Medium |",
            "| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for scorer in (SCORER_RIVER, SCORER_ISOLATION_RAW, SCORER_ISOLATION_LOG1P):
        raw_metrics = scorers.get(scorer)
        if not isinstance(raw_metrics, dict) or raw_metrics.get("skipped"):
            skipped = raw_metrics.get("skipped") if isinstance(raw_metrics, dict) else "not evaluated"
            lines.append(f"| {scorer} | skipped: {skipped} |  |  |  |  |  |  |  |  |  |  |  |")
            continue
        test_metrics = raw_metrics.get("test", {})
        if not isinstance(test_metrics, dict):
            test_metrics = {}
        lines.append(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                scorer,
                _format_metric(raw_metrics.get("selected_threshold")),
                raw_metrics.get("threshold_source", ""),
                _format_metric(test_metrics.get("roc_auc")),
                _format_metric(test_metrics.get("pr_auc")),
                _format_metric(test_metrics.get("precision_at_threshold")),
                _format_metric(test_metrics.get("recall_at_threshold")),
                _format_metric(test_metrics.get("f1_at_threshold")),
                _format_metric(test_metrics.get("best_f1")),
                _format_metric(test_metrics.get("false_positive_rate")),
                test_metrics.get("alerts", ""),
                _format_metric(test_metrics.get("alerts_per_day")),
                test_metrics.get("high_alerts", ""),
                test_metrics.get("medium_alerts", ""),
            )
        )
    if isinstance(best, dict):
        lines.extend(
            [
                "",
                "## Best Held-Out Test Scorers",
                "",
                f"- PR-AUC: {best.get('pr_auc')}",
                f"- ROC-AUC: {best.get('roc_auc')}",
                f"- F1 at tuned threshold: {best.get('f1_at_threshold')}",
                f"- Best F1 diagnostic: {best.get('best_f1')}",
                f"- Lowest FPR: {best.get('lowest_false_positive_rate')}",
                f"- Lowest alerts/day: {best.get('lowest_alerts_per_day')}",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def _format_metric(value: object) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, (float, int)):
        return f"{float(value):.4f}"
    return str(value)


def _add_llm_summarize_parser(parser: argparse.ArgumentParser) -> None:
    _add_common_source_args(parser)
    parser.add_argument("paths", nargs="*", default=["-"], help="NDJSON files or directories to analyze, or '-' for stdin")
    parser.add_argument("--output", "-o", help="Write the LLM summary to a file instead of stdout")
    parser.add_argument("--max-events", type=int, default=100, help="Maximum number of events to summarize")
    parser.add_argument("--system-prompt", help="Override the default system prompt")


def _llm_summarize(args: argparse.Namespace) -> int:
    import sys
    from pathlib import Path
    from honeypot_ai.llm import LLMClient

    events = []

    # Read NDJSON lines
    if not args.paths or args.paths == ["-"]:
        if not sys.stdin.isatty():
            for line in sys.stdin:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    events.append(json.loads(stripped))
                except json.JSONDecodeError as exc:
                    print(f"honeypot-ai llm-summarize: error parsing JSON from stdin: {exc}", file=sys.stderr)
        else:
            print("honeypot-ai llm-summarize: no paths provided and stdin is empty / a tty", file=sys.stderr)
            return 2
    else:
        for path_str in args.paths:
            path = Path(path_str)
            if path.is_file():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for line in f:
                            stripped = line.strip()
                            if not stripped or stripped.startswith("#"):
                                continue
                            try:
                                events.append(json.loads(stripped))
                            except json.JSONDecodeError as exc:
                                print(f"honeypot-ai llm-summarize: error parsing JSON in {path_str}: {exc}", file=sys.stderr)
                except OSError as exc:
                    print(f"honeypot-ai llm-summarize: error reading {path_str}: {exc}", file=sys.stderr)
                    return 2
            elif path.is_dir():
                for file_path in sorted(path.rglob("*")):
                    if file_path.is_file():
                        try:
                            with open(file_path, "r", encoding="utf-8") as f:
                                for line in f:
                                    stripped = line.strip()
                                    if not stripped or stripped.startswith("#"):
                                        continue
                                    try:
                                        events.append(json.loads(stripped))
                                    except json.JSONDecodeError:
                                        pass
                        except OSError:
                            pass
            else:
                print(f"honeypot-ai llm-summarize: path not found: {path_str}", file=sys.stderr)
                return 2

    if not events:
        print("honeypot-ai llm-summarize: no events found to summarize", file=sys.stderr)
        return 0

    if args.max_events and len(events) > args.max_events:
        events = events[:args.max_events]

    client = LLMClient()
    if not client.is_enabled():
        print("honeypot-ai llm-summarize: LLM client is disabled or LLM_API_KEY environment variable is not set.", file=sys.stderr)
        return 2

    kwargs = {}
    if args.system_prompt:
        kwargs["system_prompt"] = args.system_prompt

    try:
        summary = client.summarize_events(events, **kwargs)
    except Exception as exc:
        print(f"honeypot-ai llm-summarize: LLM summarization failed: {exc}", file=sys.stderr)
        return 2

    if not summary:
        print("honeypot-ai llm-summarize: received empty summary from LLM", file=sys.stderr)
        return 2

    if args.output:
        try:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(summary, encoding="utf-8")
        except OSError as exc:
            print(f"honeypot-ai llm-summarize: error writing output to {args.output}: {exc}", file=sys.stderr)
            return 2
    else:
        print(summary)

    return 0
