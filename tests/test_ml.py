from __future__ import annotations

import importlib.util
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from dataclasses import replace

from honeypot_ai.endpoint import (
    FEATURE_NAMES,
    EndpointWindow,
    build_endpoint_windows,
    build_endpoint_windows_from_packets,
    feature_vector,
    read_windows,
    write_windows,
)
from honeypot_ai.models import Event
from honeypot_ai.packets import iter_pcap, parse_ethernet_frame
from honeypot_ai.parsers import parse_file


ROOT = Path(__file__).resolve().parents[1]
HAS_ML_DEPS = importlib.util.find_spec("river") is not None and importlib.util.find_spec("sklearn") is not None
HAS_DUCKDB = importlib.util.find_spec("duckdb") is not None


class EndpointMLTests(unittest.TestCase):
    def test_endpoint_windows_from_sample_logs(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])

        self.assertEqual(len(windows), 4)
        self.assertEqual({window.endpoint for window in windows}, {"10.0.5.20"})
        labels = {window.label for window in windows}
        self.assertIn("malicious", labels)
        self.assertIn("benign", labels)
        outbound = [window for window in windows if window.role == "outbound"][0]
        self.assertEqual(outbound.features["bytes_in"], 295.0)
        self.assertEqual(outbound.features["bytes_out"], 77.0)

    def test_feature_vector_respects_feature_subset(self) -> None:
        window = _synthetic_temporal_windows()[-1]
        subset = ("event_count", "bytes_in")

        vector = feature_vector(window, subset)

        self.assertEqual(tuple(vector.keys()), subset)
        self.assertEqual(vector["event_count"], window.features["event_count"])
        self.assertNotIn("suricata_alerts", vector)

    def test_endpoint_window_json_round_trip(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "windows.json"
            write_windows(windows, path)
            loaded = read_windows(path)

        self.assertEqual([window.id for window in loaded], [window.id for window in windows])
        self.assertEqual(loaded[0].features["event_count"], windows[0].features["event_count"])

    def test_endpoint_windows_from_ebpf_logs(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "ebpf-events.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])

        self.assertGreaterEqual(len(windows), 1)
        host_window = [window for window in windows if window.endpoint == "sensor-a" and window.role == "host"][0]
        self.assertEqual(host_window.features["ebpf_event_count"], 3.0)
        self.assertEqual(host_window.features["process_execs"], 1.0)
        self.assertEqual(host_window.features["shell_execs"], 2.0)
        self.assertEqual(host_window.features["temp_file_writes"], 1.0)
        self.assertEqual(host_window.features["privilege_changes"], 1.0)
        self.assertEqual(host_window.label, "malicious")
        self.assertIn("eBPF privilege change", host_window.label_reasons)
        outbound = [window for window in windows if window.role == "outbound"][0]
        self.assertEqual(outbound.features["outbound_connects"], 1.0)
        self.assertEqual(outbound.features["download_tool_execs"], 1.0)

    def test_ebpf_shell_history_write_is_not_sensitive_file_write(self) -> None:
        event = Event(
            source="ebpf",
            event_type="ebpf.file_access",
            timestamp=datetime(2026, 6, 16, 10, 53, tzinfo=timezone.utc),
            filename="/home/david/.zsh_history",
            raw={"host": "localhost", "access_type": "write", "comm": "zsh"},
        )

        windows = build_endpoint_windows([event])

        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].features["sensitive_file_writes"], 0.0)
        self.assertEqual(windows[0].label, "benign")

    def test_ebpf_home_ssh_authorized_keys_write_is_sensitive(self) -> None:
        event = Event(
            source="ebpf",
            event_type="ebpf.file_access",
            timestamp=datetime(2026, 6, 16, 10, 53, tzinfo=timezone.utc),
            filename="/home/david/.ssh/authorized_keys",
            raw={"host": "localhost", "access_type": "write", "comm": "sh"},
        )

        windows = build_endpoint_windows([event])

        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].features["sensitive_file_writes"], 1.0)
        self.assertEqual(windows[0].label, "malicious")

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_train_and_score_model(self) -> None:
        from honeypot_ai.ml import SCORER_ISOLATION_LOG1P, SCORER_RIVER, load_model, metadata_record, score_windows, train_model

        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            result = train_model(windows, Path(tmp) / "model")
            artifact = load_model(result.model_path)
            alerts = score_windows(windows, artifact, include_below_threshold=True)
            metadata = metadata_record(result)

        self.assertEqual(len(alerts), len(windows))
        self.assertEqual(alerts[0].model_id, result.model_id)
        self.assertIn(result.selected_scorer, {SCORER_RIVER, SCORER_ISOLATION_LOG1P})
        self.assertGreater(result.high_threshold, result.threshold)
        self.assertEqual(artifact["selected_scorer"], result.selected_scorer)
        self.assertIn("high_threshold", artifact)
        self.assertEqual(metadata["selected_scorer"], result.selected_scorer)
        self.assertIn("high_threshold", metadata)
        self.assertIn("selected_scorer", metadata["metrics"])

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_force_isolation_scorer(self) -> None:
        from honeypot_ai.ml import SCORER_ISOLATION_LOG1P, load_model, score_windows, train_model

        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            result = train_model(windows, Path(tmp) / "model", scorer=SCORER_ISOLATION_LOG1P)
            artifact = load_model(result.model_path)
            alerts = score_windows(windows, artifact, include_below_threshold=True)

        self.assertEqual(result.selected_scorer, SCORER_ISOLATION_LOG1P)
        self.assertEqual(len(alerts), len(windows))
        self.assertTrue(alerts[0].reasons[0].startswith(SCORER_ISOLATION_LOG1P))

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_train_calibrated_model_uses_calibration_threshold(self) -> None:
        from honeypot_ai.ml import (
            THRESHOLD_OBJECTIVE_BEST_F1,
            load_model,
            metadata_record,
            train_calibrated_model,
            train_model,
        )

        windows = _synthetic_temporal_windows()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            calibrated = train_calibrated_model(
                windows,
                root / "calibrated",
                threshold_objective=THRESHOLD_OBJECTIVE_BEST_F1,
                calibration_fraction=0.34,
            )
            baseline = train_model(windows, root / "baseline")
            metadata = metadata_record(calibrated)
            artifact = load_model(calibrated.model_path)

        self.assertEqual(metadata["threshold_source"], "calibration_best_f1")
        self.assertEqual(metadata["metrics"]["threshold_objective"], THRESHOLD_OBJECTIVE_BEST_F1)
        self.assertEqual(artifact["threshold_source"], "calibration_best_f1")
        self.assertEqual(baseline.metrics.get("threshold_source", "training_quantile"), "training_quantile")
        self.assertGreater(calibrated.high_threshold, calibrated.threshold)

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_evaluate_ignores_excluded_features(self) -> None:
        from honeypot_ai.ml import SCORER_RIVER, behavioral_feature_names, evaluate_temporal_split

        feature_names = behavioral_feature_names()
        self.assertNotIn("suricata_alerts", feature_names)
        self.assertNotIn("reverse_shells", feature_names)

        base = _synthetic_temporal_windows()
        # Mutate only the excluded label-defining features; behavioral features unchanged.
        mutated = [
            replace(window, features={**window.features, "suricata_alerts": 42.0, "reverse_shells": 9.0})
            for window in base
        ]

        base_result = evaluate_temporal_split(base, train_fraction=0.5, feature_names=feature_names)
        mutated_result = evaluate_temporal_split(mutated, train_fraction=0.5, feature_names=feature_names)

        self.assertEqual(
            base_result["scorers"][SCORER_RIVER]["roc_auc"],
            mutated_result["scorers"][SCORER_RIVER]["roc_auc"],
        )
        self.assertEqual(base_result["features"]["used"], list(feature_names))
        self.assertIn("suricata_alerts", base_result["features"]["excluded"])

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_temporal_evaluation_metrics(self) -> None:
        from honeypot_ai.ml import (
            SCORER_ISOLATION_LOG1P,
            SCORER_ISOLATION_RAW,
            SCORER_RIVER,
            evaluate_temporal_split,
        )

        windows = _synthetic_temporal_windows()
        result = evaluate_temporal_split(windows, train_fraction=0.5)
        split = result["split"]
        labels = result["labels"]
        data_quality = result["data_quality"]
        scorers = result["scorers"]

        self.assertEqual(data_quality["excluded_rows"], 0)
        self.assertEqual(split["train_rows"], 6)
        self.assertEqual(split["test_rows"], 6)
        self.assertEqual(labels["test"]["benign"], 3)
        self.assertEqual(labels["test"]["malicious"], 3)
        for scorer in (SCORER_RIVER, SCORER_ISOLATION_RAW, SCORER_ISOLATION_LOG1P):
            self.assertIn(scorer, scorers)
            self.assertIn("alerts", scorers[scorer])
            self.assertIn("false_positive_rate", scorers[scorer])
            self.assertIn("best_f1", scorers[scorer])
        self.assertIn("roc_auc", result["best_scorers"])
        self.assertIn("best_f1", result["best_scorers"])
        self.assertIn("lowest_false_positive_rate", result["best_scorers"])
        self.assertIn("lowest_alerts_per_day", result["best_scorers"])

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_temporal_tuning_metrics(self) -> None:
        from honeypot_ai.ml import (
            SCORER_ISOLATION_LOG1P,
            SCORER_ISOLATION_RAW,
            SCORER_RIVER,
            THRESHOLD_OBJECTIVE_BEST_F1,
            tune_temporal_split,
        )

        windows = _synthetic_temporal_windows()
        result = tune_temporal_split(windows, train_fraction=0.4, calibration_fraction=0.3)
        split = result["split"]
        labels = result["labels"]
        scorers = result["scorers"]

        self.assertEqual(split["method"], "temporal_train_calibration_test")
        self.assertEqual(result["threshold_objective"], THRESHOLD_OBJECTIVE_BEST_F1)
        self.assertEqual(split["train_rows"], 4)
        self.assertEqual(split["calibration_rows"], 4)
        self.assertEqual(split["test_rows"], 4)
        self.assertEqual(labels["test"]["malicious"], 3)
        for scorer in (SCORER_RIVER, SCORER_ISOLATION_RAW, SCORER_ISOLATION_LOG1P):
            self.assertIn(scorer, scorers)
            self.assertIn("selected_threshold", scorers[scorer])
            self.assertIn("calibration", scorers[scorer])
            self.assertIn("test", scorers[scorer])
        self.assertIn("f1_at_threshold", result["best_scorers"])
        self.assertIn("lowest_false_positive_rate", result["best_scorers"])
        self.assertIn("lowest_alerts_per_day", result["best_scorers"])

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_temporal_tuning_target_fpr_objective(self) -> None:
        from honeypot_ai.ml import (
            SCORER_ISOLATION_LOG1P,
            SCORER_ISOLATION_RAW,
            SCORER_RIVER,
            THRESHOLD_OBJECTIVE_TARGET_FPR,
            tune_temporal_split,
        )

        windows = _synthetic_mixed_temporal_windows()
        result = tune_temporal_split(
            windows,
            train_fraction=0.34,
            calibration_fraction=0.33,
            threshold_objective=THRESHOLD_OBJECTIVE_TARGET_FPR,
            target_fpr=0.0,
        )
        scorers = result["scorers"]

        self.assertEqual(result["threshold_objective"], THRESHOLD_OBJECTIVE_TARGET_FPR)
        for scorer in (SCORER_RIVER, SCORER_ISOLATION_RAW, SCORER_ISOLATION_LOG1P):
            self.assertEqual(scorers[scorer]["threshold_source"], "calibration_target_fpr")
            calibration = scorers[scorer]["calibration"]
            self.assertEqual(calibration["false_positive_rate"], 0.0)

    @unittest.skipUnless(HAS_ML_DEPS and HAS_DUCKDB, "ML and DuckDB dependencies are not installed")
    def test_duckdb_ml_store(self) -> None:
        import duckdb

        from honeypot_ai.ml import load_model, metadata_record, score_windows, train_model
        from honeypot_ai.ml_store import insert_endpoint_windows, insert_ml_alerts, insert_model_metadata

        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = train_model(windows, root / "model")
            insert_model_metadata(root / "ml.duckdb", metadata_record(result))
            insert_endpoint_windows(root / "ml.duckdb", windows, model_id=result.model_id)
            alerts = score_windows(windows, load_model(result.model_path), include_below_threshold=True)
            insert_ml_alerts(root / "ml.duckdb", alerts)
            conn = duckdb.connect(str(root / "ml.duckdb"))
            try:
                model_count = conn.execute("SELECT COUNT(*) FROM ml_models").fetchone()[0]
                window_count = conn.execute("SELECT COUNT(*) FROM endpoint_windows").fetchone()[0]
            finally:
                conn.close()

        self.assertEqual(model_count, 1)
        self.assertEqual(window_count, len(windows))


class PacketParserTests(unittest.TestCase):
    def test_parse_ethernet_ipv4_tcp_frame(self) -> None:
        frame = _ethernet_ipv4_tcp_frame()
        packet = parse_ethernet_frame(frame)

        self.assertIsNotNone(packet)
        assert packet is not None
        self.assertEqual(packet.src_ip, "10.0.5.20")
        self.assertEqual(packet.dest_ip, "203.0.113.70")
        self.assertEqual(packet.src_port, 46380)
        self.assertEqual(packet.dest_port, 80)
        self.assertEqual(packet.protocol, "tcp")

    def test_pcap_replay_to_endpoint_window(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "traffic.pcap"
            _write_pcap(path, _ethernet_ipv4_tcp_frame())
            packets = list(iter_pcap(path))

        windows = build_endpoint_windows_from_packets(packets, protected_cidrs=["10.0.5.0/24"])
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0].endpoint, "10.0.5.20")
        self.assertEqual(windows[0].role, "outbound")
        self.assertEqual(windows[0].features["packet_count"], 1.0)


def _ethernet_ipv4_tcp_frame() -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        1,
        0,
        64,
        6,
        0,
        bytes([10, 0, 5, 20]),
        bytes([203, 0, 113, 70]),
    )
    tcp_header = struct.pack("!HHIIHHHH", 46380, 80, 0, 0, 0x5000, 0, 0, 0)
    return ethernet + ip_header + tcp_header


def _write_pcap(path: Path, frame: bytes) -> None:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1_778_314_160, 0, len(frame), len(frame)) + frame
    path.write_bytes(header + record)


def _synthetic_temporal_windows() -> list[EndpointWindow]:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    windows: list[EndpointWindow] = []
    for index in range(12):
        malicious = index >= 9
        features = {name: 0.0 for name in FEATURE_NAMES}
        features.update(
            {
                "event_count": 100.0 if malicious else 1.0,
                "bytes_in": 5000.0 if malicious else 50.0,
                "bytes_out": 15000.0 if malicious else 20.0,
                "unique_peers": 10.0 if malicious else 1.0,
                "suricata_alerts": 8.0 if malicious else 0.0,
                "url_count": 5.0 if malicious else 0.0,
            }
        )
        window_start = start + timedelta(minutes=index)
        windows.append(
            EndpointWindow(
                id=f"synthetic-{index}",
                endpoint="10.0.5.20",
                role="inbound",
                window_start=window_start,
                window_end=window_start + timedelta(minutes=1),
                features=features,
                label="malicious" if malicious else "benign",
                label_reasons=("synthetic",),
                source_event_count=int(features["event_count"]),
            )
        )
    return windows


def _synthetic_mixed_temporal_windows() -> list[EndpointWindow]:
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    windows: list[EndpointWindow] = []
    malicious_indexes = {5, 7, 10, 11}
    for index in range(12):
        malicious = index in malicious_indexes
        features = {name: 0.0 for name in FEATURE_NAMES}
        features.update(
            {
                "event_count": 60.0 if malicious else 2.0,
                "bytes_in": 2000.0 if malicious else 60.0,
                "bytes_out": 9000.0 if malicious else 25.0,
                "unique_peers": 8.0 if malicious else 1.0,
                "suricata_alerts": 5.0 if malicious else 0.0,
                "url_count": 3.0 if malicious else 0.0,
            }
        )
        window_start = start + timedelta(minutes=index)
        windows.append(
            EndpointWindow(
                id=f"mixed-{index}",
                endpoint="10.0.5.20",
                role="inbound",
                window_start=window_start,
                window_end=window_start + timedelta(minutes=1),
                features=features,
                label="malicious" if malicious else "benign",
                label_reasons=("synthetic",),
                source_event_count=int(features["event_count"]),
            )
        )
    return windows


if __name__ == "__main__":
    unittest.main()
