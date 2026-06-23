from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from honeypot_ai.cli import main
from honeypot_ai.realtime import stream_once


ROOT = Path(__file__).resolve().parents[1]


class RealtimeIngestTests(unittest.TestCase):
    def test_stream_once_tails_raw_events_without_duplicates(self) -> None:
        first, second = (ROOT / "sample_logs" / "honeypot.ndjson").read_text(encoding="utf-8").splitlines()[:2]

        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.ndjson"
            output = Path(tmp) / "alerts.ndjson"
            state = Path(tmp) / "state.json"
            source.write_text(first + "\n", encoding="utf-8")

            initial = stream_once([source], output_path=output, state_path=state)
            repeated = stream_once([source], output_path=output, state_path=state)
            source.write_text(first + "\n" + second + "\n", encoding="utf-8")
            next_batch = stream_once([source], output_path=output, state_path=state)

            lines = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(initial.raw_lines, 1)
        self.assertGreater(initial.alert_events, 0)
        self.assertEqual(repeated.raw_lines, 0)
        self.assertEqual(repeated.alert_events, 0)
        self.assertEqual(next_batch.raw_lines, 1)
        self.assertTrue(lines)
        self.assertTrue(all(line["integration"] == "honeypot-ai" for line in lines))

    def test_stream_once_ignores_partial_trailing_line_until_complete(self) -> None:
        first = (ROOT / "sample_logs" / "honeypot.ndjson").read_text(encoding="utf-8").splitlines()[0]

        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.ndjson"
            output = Path(tmp) / "alerts.ndjson"
            state = Path(tmp) / "state.json"
            source.write_text(first, encoding="utf-8")
            partial = stream_once([source], output_path=output, state_path=state)
            output_exists_after_partial = output.exists()
            source.write_text(first + "\n", encoding="utf-8")
            complete = stream_once([source], output_path=output, state_path=state)
            output_exists_after_complete = output.exists()

        self.assertEqual(partial.raw_lines, 0)
        self.assertFalse(output_exists_after_partial)
        self.assertEqual(complete.raw_lines, 1)
        self.assertTrue(output_exists_after_complete)

    def test_stream_once_passthrough_wazuh_updates_preview(self) -> None:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "alerts-in.ndjson"
            output = Path(tmp) / "alerts-out.ndjson"
            preview = Path(tmp) / "index.html"
            source.write_text(
                '{"timestamp":"2026-06-23T18:30:00+00:00","integration":"honeypot-ai","kind":"ml_alert","rule_name":"honeypot_ai_ml_alert_high","severity":"high"}\n',
                encoding="utf-8",
            )

            result = stream_once(
                [source],
                output_path=output,
                input_format="wazuh",
                preview_output=preview,
                refresh_seconds=5,
            )
            html = preview.read_text(encoding="utf-8")

        self.assertEqual(result.raw_lines, 1)
        self.assertEqual(result.parsed_events, 1)
        self.assertEqual(result.alert_events, 1)
        self.assertIn('<meta http-equiv="refresh" content="5">', html)
        self.assertIn("High confidence", html)

    def test_wazuh_stream_cli_once(self) -> None:
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.ndjson"
            output = Path(tmp) / "alerts.ndjson"
            source.write_text(
                (ROOT / "sample_logs" / "honeypot.ndjson").read_text(encoding="utf-8").splitlines()[0] + "\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(["wazuh-stream", str(source), "--output", str(output), "--once"])

            self.assertEqual(status, 0)
            self.assertTrue(output.exists())
            self.assertIn("Wazuh alert event", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
