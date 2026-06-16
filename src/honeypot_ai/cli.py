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
    parser.add_argument("--output", "-o", help="Alert JSON output path. Defaults to stdout.")
    parser.add_argument("--db", default=os.getenv("HONEYPOT_WEB_DB"), help="DuckDB path for storing alerts")


COMMANDS = {"analyze", "dataset", "train", "score", "evaluate", "tune", "live-sensor"}


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
    if args.command in {None, "analyze"}:
        if args.command is None:
            parser.print_help()
            return 2
        return _analyze(args)
    return 2


def _analyze(args: argparse.Namespace) -> int:
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
        output = write_alerts(alerts, args.output)
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
        output = write_alerts(alerts, args.output)
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
