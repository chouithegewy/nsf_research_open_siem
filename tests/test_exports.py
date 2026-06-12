from __future__ import annotations

import json
import unittest
from pathlib import Path

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.parsers import parse_file
from honeypot_ai.report import analyze_events
from honeypot_ai.splunk import report_to_splunk_hec_events, report_to_splunk_ndjson


ROOT = Path(__file__).resolve().parents[1]


class ExportTests(unittest.TestCase):
    def test_misp_attribute_export(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        payload = json.loads(report_to_misp_attributes(report))

        attributes = payload["Attribute"]
        values = {(attribute["type"], attribute["value"]) for attribute in attributes}

        self.assertIn(("ip-src", "198.51.100.23"), values)
        self.assertIn(("url", "http://payload.example/stage2.sh"), values)
        self.assertIn(("domain", "payload.example"), values)
        self.assertIn(
            ("sha256", "e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9"),
            values,
        )
        by_value = {attribute["value"]: attribute for attribute in attributes}
        self.assertFalse(by_value["198.51.100.23"]["to_ids"])
        self.assertFalse(by_value["payload.example"]["to_ids"])
        self.assertTrue(
            by_value["e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9"]["to_ids"]
        )

    def test_splunk_hec_export(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        events = report_to_splunk_hec_events(report, index="honeypot")

        self.assertTrue(events)
        self.assertTrue(all("event" in event for event in events))
        self.assertIn("index", events[0])
        self.assertTrue(any(event["event"]["kind"] == "finding" for event in events))

        ndjson = report_to_splunk_ndjson(report, index="honeypot")
        first = json.loads(ndjson.splitlines()[0])
        self.assertEqual(first["index"], "honeypot")


if __name__ == "__main__":
    unittest.main()
