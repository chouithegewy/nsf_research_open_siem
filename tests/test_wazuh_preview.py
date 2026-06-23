from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from honeypot_ai.cli import main
from honeypot_ai.wazuh_preview import build_preview_model, render_dashboard_preview, write_dashboard_preview


ROOT = Path(__file__).resolve().parents[1]


class WazuhPreviewTests(unittest.TestCase):
    def test_preview_model_counts_wazuh_shapes(self) -> None:
        events = [
            {
                "timestamp": "2026-06-23T18:30:00+00:00",
                "integration": "honeypot-ai",
                "kind": "finding",
                "rule_name": "honeypot_ai_misp_ip_match",
                "severity": "high",
                "src_ip": "8.8.8.8",
            },
            {
                "timestamp": "2026-06-23T18:31:00+00:00",
                "rule": {"level": 8, "groups": ["honeypot_ai", "honeypot_ai_misp"]},
                "data": {
                    "integration": "honeypot-ai",
                    "kind": "ebpf_event",
                    "event_type": "network_connect",
                    "dest_ip": "203.0.113.9",
                    "comm": "curl",
                },
            },
            {
                "timestamp": "2026-06-23T18:32:00+00:00",
                "integration": "other",
                "kind": "finding",
            },
        ]

        model = build_preview_model(events)

        self.assertEqual(model["total_events"], 2)
        self.assertEqual(model["high_confidence"], 1)
        self.assertEqual(model["misp_matches"], 2)
        self.assertEqual(model["ebpf_events"], 1)
        self.assertEqual(model["ebpf_event_types"]["network_connect"], 1)

    def test_preview_html_escapes_event_values(self) -> None:
        html = render_dashboard_preview(
            [
                {
                    "timestamp": "2026-06-23T18:30:00+00:00",
                    "integration": "honeypot-ai",
                    "kind": "ml_alert",
                    "rule_name": "<script>alert(1)</script>",
                    "severity": "high",
                }
            ],
            {"name": "Test Dashboard", "data_view": "wazuh-alerts-*"},
            refresh_seconds=3,
        )

        self.assertIn("Test Dashboard", html)
        self.assertIn('<meta http-equiv="refresh" content="3">', html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_write_dashboard_preview_creates_html(self) -> None:
        with TemporaryDirectory() as tmp:
            alerts = Path(tmp) / "alerts.ndjson"
            output = Path(tmp) / "index.html"
            alerts.write_text(
                json.dumps(
                    {
                        "timestamp": "2026-06-23T18:30:00+00:00",
                        "integration": "honeypot-ai",
                        "kind": "ml_alert",
                        "rule_name": "honeypot_ai_ml_alert_high",
                        "severity": "high",
                        "ml_score": 0.95,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            summary = write_dashboard_preview([alerts], output)

            self.assertEqual(summary["events"], 1)
            self.assertEqual(summary["high_confidence"], 1)
            self.assertIn("Honeypot AI Single Pane", output.read_text(encoding="utf-8"))

    def test_wazuh_preview_cli_writes_output(self) -> None:
        with TemporaryDirectory() as tmp:
            alerts = Path(tmp) / "alerts.ndjson"
            output = Path(tmp) / "preview.html"
            alerts.write_text(
                '{"timestamp":"2026-06-23T18:30:00+00:00","integration":"honeypot-ai","kind":"ebpf_event","event_type":"exec"}\n',
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(["wazuh-preview", str(alerts), "--output", str(output)])

            self.assertEqual(status, 0)
            self.assertTrue(output.exists())
            self.assertIn("events=1", stderr.getvalue())

    def test_local_wazuh_dashboard_smoke_script(self) -> None:
        with TemporaryDirectory() as tmp:
            result = subprocess.run(
                ["bash", str(ROOT / "scripts" / "local-wazuh-dashboard-smoke.sh"), tmp],
                check=False,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(tmp) / "alerts.ndjson").exists())
            html = (Path(tmp) / "index.html").read_text(encoding="utf-8")
            self.assertIn("Honeypot AI Single Pane", html)
            self.assertIn("eBPF Event Mix", html)
            self.assertIn("Local Wazuh preview page", result.stdout)


if __name__ == "__main__":
    unittest.main()
