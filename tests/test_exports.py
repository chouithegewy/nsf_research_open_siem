from __future__ import annotations

import json
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from pathlib import Path

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.misp import build_misp_event_payload, misp_attributes_to_wazuh_cdb, push_misp_event, write_wazuh_cdb_lists
from honeypot_ai.ml import MLAlert
from honeypot_ai.parsers import parse_file
from honeypot_ai.report import analyze_events
from honeypot_ai.splunk import report_to_splunk_hec_events, report_to_splunk_ndjson
from honeypot_ai.wazuh import ml_alerts_to_wazuh_ndjson, report_to_wazuh_ndjson


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

    def test_wazuh_report_export_is_flat_ndjson(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        lines = report_to_wazuh_ndjson(report).splitlines()

        self.assertTrue(lines)
        events = [json.loads(line) for line in lines]
        findings = [event for event in events if event["kind"] == "finding"]

        self.assertTrue(findings)
        self.assertTrue(all(event["integration"] == "honeypot-ai" for event in events))
        self.assertTrue(all(event["schema_version"] == 1 for event in events))
        self.assertTrue(all(not isinstance(value, (dict, list)) for event in events for value in event.values()))
        self.assertIn("rule_name", findings[0])
        self.assertIn("src_ip", findings[0])

    def test_wazuh_report_export_marks_ebpf_events(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "ebpf-events.ndjson"))
        events = [json.loads(line) for line in report_to_wazuh_ndjson(report).splitlines()]
        ebpf_events = [event for event in events if event["kind"] == "ebpf_event"]

        self.assertTrue(ebpf_events)
        self.assertTrue(any(event["event_type"] == "privilege_change" for event in ebpf_events))
        self.assertTrue(any(event["rule_name"] == "honeypot_ai_ebpf_privilege_change" for event in ebpf_events))
        self.assertTrue(any(event.get("severity_hint") == "high" for event in ebpf_events))
        self.assertTrue(any(event.get("access_type") == "write" for event in ebpf_events))

    def test_wazuh_ml_alert_export_is_flat_ndjson(self) -> None:
        alert = MLAlert(
            id="alert-1",
            model_id="model-1",
            endpoint="10.0.5.20",
            role="outbound",
            window_start=datetime(2026, 6, 16, 12, 0, tzinfo=timezone.utc),
            window_end=datetime(2026, 6, 16, 12, 1, tzinfo=timezone.utc),
            score=0.91,
            threshold=0.5,
            severity="high",
            reasons=("eBPF shell with outbound connection", "bytes out=4096"),
            features={"shell_execs": 1.0, "outbound_connects": 1.0},
            created_at=datetime(2026, 6, 16, 12, 2, tzinfo=timezone.utc),
        )

        payload = json.loads(ml_alerts_to_wazuh_ndjson([alert]).strip())

        self.assertEqual(payload["integration"], "honeypot-ai")
        self.assertEqual(payload["kind"], "ml_alert")
        self.assertEqual(payload["severity"], "high")
        self.assertEqual(payload["endpoint"], "10.0.5.20")
        self.assertEqual(payload["rule_name"], "honeypot_ai_ml_alert_high")
        self.assertIn("eBPF shell", payload["reasons"])

    def test_misp_event_payload_wraps_existing_attribute_export(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        payload = build_misp_event_payload(report, info="honeypot test export")

        event = payload["Event"]
        self.assertEqual(event["info"], "honeypot test export")
        self.assertFalse(event["published"])
        self.assertTrue(event["Attribute"])
        self.assertTrue(any(attribute["type"] == "url" for attribute in event["Attribute"]))

    def test_push_misp_event_uses_authorization_header(self) -> None:
        captured: dict[str, object] = {}

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"Event":{"id":"42"}}'

        def fake_urlopen(request: object, timeout: float = 0) -> FakeResponse:
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["data"] = request.data
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("honeypot_ai.misp.urllib.request.urlopen", fake_urlopen):
            response = push_misp_event(
                "https://misp.example",
                "secret-key",
                {"Event": {"info": "test", "Attribute": []}},
                timeout_seconds=3,
            )

        self.assertEqual(response["Event"]["id"], "42")
        self.assertEqual(captured["url"], "https://misp.example/events/add")
        self.assertEqual(captured["headers"]["Authorization"], "secret-key")
        self.assertEqual(captured["timeout"], 3)
        self.assertIn(b'"Event"', captured["data"])

    def test_misp_attributes_write_wazuh_cdb_lists(self) -> None:
        attributes = [
            {"type": "ip-src", "value": "8.8.8.8", "uuid": "ip-uuid", "to_ids": True},
            {"type": "domain", "value": "bad.example.net", "uuid": "domain-uuid", "to_ids": True},
            {"type": "sha256", "value": "a" * 64, "uuid": "hash-uuid", "to_ids": True},
            {"type": "url", "value": "http://bad.example.net/a", "uuid": "url-uuid", "to_ids": False},
        ]

        entries = misp_attributes_to_wazuh_cdb(attributes)
        self.assertEqual(entries["misp-ip"], ["8.8.8.8:misp:ip-src:ip-uuid"])
        self.assertEqual(entries["misp-domain"], ["bad.example.net:misp:domain:domain-uuid"])
        self.assertEqual(entries["misp-hash"], [f"{'a' * 64}:misp:sha256:hash-uuid"])
        self.assertEqual(entries["misp-url"], [])

        with TemporaryDirectory() as tmp:
            counts = write_wazuh_cdb_lists(attributes, tmp)
            ip_list = Path(tmp) / "misp-ip"

            self.assertEqual(counts["misp-ip"], 1)
            self.assertEqual(ip_list.read_text(encoding="utf-8").strip(), "8.8.8.8:misp:ip-src:ip-uuid")


if __name__ == "__main__":
    unittest.main()
