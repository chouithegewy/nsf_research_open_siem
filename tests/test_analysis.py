from __future__ import annotations

import unittest
from pathlib import Path

from honeypot_ai.parsers import parse_file
from honeypot_ai.report import analyze_events, report_to_markdown


ROOT = Path(__file__).resolve().parents[1]


class AnalysisTests(unittest.TestCase):
    def test_sample_log_produces_high_risk_finding(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "honeypot.ndjson")
        report = analyze_events(events)

        self.assertEqual(len(events), 17)
        self.assertGreaterEqual(len(report.sessions), 4)
        self.assertGreaterEqual(len(report.actors), 4)
        self.assertGreaterEqual(len(report.iocs), 10)
        self.assertTrue(report.findings)

        top = report.findings[0]
        self.assertEqual(top.session_key, "cowrie:s1")
        self.assertIn(top.severity, {"high", "critical"})
        self.assertIn("T1105", top.mitre_techniques)
        self.assertIn("T1053.003", top.mitre_techniques)
        self.assertIn("T1059.004", top.mitre_techniques)

    def test_markdown_report_contains_ioc_table(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        markdown = report_to_markdown(report)

        self.assertIn("# Honeypot Analysis Report", markdown)
        self.assertIn("## Actor Correlation", markdown)
        self.assertIn("http://203.0.113.50/bot.sh", markdown)
        self.assertIn("http://payload.example/stage2.sh", markdown)
        self.assertIn("MITRE ATT&CK", markdown)

    def test_actor_correlation_joins_sensor_evidence(self) -> None:
        report = analyze_events(parse_file(ROOT / "sample_logs" / "honeypot.ndjson"))
        actors = {actor.ip: actor for actor in report.actors}

        actor = actors["203.0.113.70"]
        self.assertEqual(actor.ip_scope, "documentation")
        self.assertIn("dionaea", actor.sources)
        self.assertIn("suricata", actor.sources)
        self.assertIn("zeek", actor.sources)
        self.assertIn("T1105", actor.techniques)
        self.assertEqual(report.actors[1].ip, "203.0.113.70")


if __name__ == "__main__":
    unittest.main()
