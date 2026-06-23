from __future__ import annotations

import contextlib
import importlib.util
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from honeypot_ai.cli import main
from honeypot_ai.endpoint import build_endpoint_windows, write_windows
from honeypot_ai.parsers import parse_file


ROOT = Path(__file__).resolve().parents[1]
HAS_ML_DEPS = importlib.util.find_spec("river") is not None and importlib.util.find_spec("sklearn") is not None


class CliTests(unittest.TestCase):
    def test_legacy_analyze_options_still_work(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["--format", "json", str(ROOT / "sample_logs" / "honeypot.ndjson")])

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["events"]), 17)

    def test_explicit_analyze_subcommand_still_works(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["analyze", "--format", "json", str(ROOT / "sample_logs" / "honeypot.ndjson")])

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(len(payload["events"]), 17)

    def test_analyze_wazuh_format_outputs_ndjson(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(["analyze", "--format", "wazuh", str(ROOT / "sample_logs" / "honeypot.ndjson")])

        self.assertEqual(status, 0)
        lines = stdout.getvalue().splitlines()
        self.assertTrue(lines)
        first = json.loads(lines[0])
        self.assertEqual(first["integration"], "honeypot-ai")
        self.assertIn(first["kind"], {"event", "finding", "actor", "ioc", "session"})

    def test_dataset_subcommand_supports_ebpf_source(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "dataset",
                    "--source",
                    "ebpf",
                    "--protected-cidr",
                    "10.0.5.0/24",
                    str(ROOT / "sample_logs" / "ebpf-events.ndjson"),
                ]
            )

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(any(window["features"]["ebpf_event_count"] > 0 for window in payload))
        self.assertTrue(any(window["label"] == "malicious" for window in payload))

    def test_misp_push_dry_run_outputs_event_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = main(
                [
                    "misp-push",
                    "--dry-run",
                    "--event-info",
                    "test honeypot export",
                    str(ROOT / "sample_logs" / "honeypot.ndjson"),
                ]
            )

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["Event"]["info"], "test honeypot export")
        self.assertTrue(payload["Event"]["Attribute"])

    def test_misp_pull_writes_wazuh_lists(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "response": {
                            "Attribute": [
                                {"type": "ip-src", "value": "8.8.8.8", "uuid": "ip-uuid", "to_ids": True},
                                {"type": "domain", "value": "bad.example.net", "uuid": "domain-uuid", "to_ids": True},
                            ]
                        }
                    }
                ).encode("utf-8")

        with TemporaryDirectory() as tmp:
            with patch("honeypot_ai.misp.urllib.request.urlopen", return_value=FakeResponse()):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    status = main(
                        [
                            "misp-pull",
                            "--misp-url",
                            "https://misp.example",
                            "--misp-key",
                            "secret-key",
                            "--output-dir",
                            tmp,
                        ]
                    )

            self.assertEqual(status, 0)
            self.assertIn("Wrote", stderr.getvalue())
            self.assertEqual((Path(tmp) / "misp-ip").read_text(encoding="utf-8").strip(), "8.8.8.8:misp:ip-src:ip-uuid")
            self.assertEqual(
                (Path(tmp) / "misp-domain").read_text(encoding="utf-8").strip(),
                "bad.example.net:misp:domain:domain-uuid",
            )

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_evaluate_subcommand_json(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "windows.json"
            write_windows(windows, dataset)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(["evaluate", "--format", "json", str(dataset)])

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data_quality"]["excluded_rows"], 0)
        self.assertEqual(payload["split"]["method"], "temporal")
        self.assertIn("river-half-space-trees", payload["scorers"])
        self.assertIn("best_scorers", payload)

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_evaluate_exclude_rule_features_flag(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "windows.json"
            write_windows(windows, dataset)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(["evaluate", "--format", "json", "--exclude-rule-features", str(dataset)])

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertNotIn("suricata_alerts", payload["features"]["used"])
        self.assertIn("suricata_alerts", payload["features"]["excluded"])

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_train_threshold_objective_calibrates(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "windows.json"
            write_windows(windows, dataset)
            model_dir = Path(tmp) / "model"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "train",
                        str(dataset),
                        "--model-dir",
                        str(model_dir),
                        "--threshold-objective",
                        "best-f1",
                        "--calibration-fraction",
                        "0.34",
                    ]
                )
            metadata = json.loads((model_dir / "metadata.json").read_text())

        self.assertEqual(status, 0)
        self.assertIn("threshold_source", metadata)
        self.assertEqual(metadata["metrics"]["threshold_objective"], "best-f1")

    @unittest.skipUnless(HAS_ML_DEPS, "ML dependencies are not installed")
    def test_tune_subcommand_json(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
        with TemporaryDirectory() as tmp:
            dataset = Path(tmp) / "windows.json"
            write_windows(windows, dataset)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(
                    [
                        "tune",
                        "--format",
                        "json",
                        "--train-fraction",
                        "0.5",
                        "--calibration-fraction",
                        "0.25",
                        str(dataset),
                    ]
                )

        self.assertEqual(status, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["split"]["method"], "temporal_train_calibration_test")
        self.assertEqual(payload["threshold_objective"], "best-f1")
        self.assertIn("target_fpr", payload)
        self.assertIn("test", payload["scorers"]["river-half-space-trees"])


if __name__ == "__main__":
    unittest.main()
