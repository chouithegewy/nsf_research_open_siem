from __future__ import annotations

import json
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]


def _load_saved_objects() -> list[dict[str, object]]:
    path = ROOT / "deploy" / "wazuh" / "dashboard" / "honeypot-ai-overview.ndjson"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


class WazuhDeployTests(unittest.TestCase):
    def test_wazuh_localfile_config_collects_honeypot_alerts_as_json(self) -> None:
        tree = ET.parse(ROOT / "deploy" / "wazuh" / "ossec-localfile.xml")
        localfile = tree.getroot().find("localfile")

        self.assertIsNotNone(localfile)
        self.assertEqual(localfile.findtext("location"), "/var/log/honeypot-ai/alerts.ndjson")
        self.assertEqual(localfile.findtext("log_format"), "json")

    def test_wazuh_rules_have_stable_ids_and_expected_fields(self) -> None:
        tree = ET.parse(ROOT / "deploy" / "wazuh" / "rules" / "honeypot-ai-rules.xml")
        rules = tree.getroot().findall("rule")
        ids = [int(rule.attrib["id"]) for rule in rules]
        fields = {(field.attrib.get("name"), field.text) for rule in rules for field in rule.findall("field")}
        lists = [item.attrib for rule in rules for item in rule.findall("list")]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(110100 <= rule_id < 110200 for rule_id in ids))
        self.assertIn(("integration", "honeypot-ai"), fields)
        self.assertIn(("kind", "ml_alert"), fields)
        self.assertIn(("kind", "ebpf_event"), fields)
        self.assertTrue(any(item.get("field") == "src_ip" for item in lists))

    def test_wazuh_dashboard_bundle_is_valid_saved_objects(self) -> None:
        objects = _load_saved_objects()
        ids = [str(item["id"]) for item in objects]
        types = {str(item["type"]) for item in objects}

        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("index-pattern", types)
        self.assertIn("dashboard", types)
        self.assertIn("visualization", types)
        self.assertIn("search", types)

        for item in objects:
            attributes = item.get("attributes", {})
            self.assertIsInstance(attributes, dict)
            if "visState" in attributes:
                vis_state = json.loads(str(attributes["visState"]))
                self.assertIn("aggs", vis_state)
                self.assertTrue(vis_state["aggs"])
            if "panelsJSON" in attributes:
                panels = json.loads(str(attributes["panelsJSON"]))
                self.assertTrue(all(panel.get("panelRefName") for panel in panels))
            if "optionsJSON" in attributes:
                json.loads(str(attributes["optionsJSON"]))

            meta = attributes.get("kibanaSavedObjectMeta") if isinstance(attributes, dict) else None
            if isinstance(meta, dict) and "searchSourceJSON" in meta:
                search_source = json.loads(str(meta["searchSourceJSON"]))
                query = search_source["query"]["query"]
                self.assertIn("honeypot-ai", query)
                self.assertEqual(search_source["indexRefName"], "kibanaSavedObjectMeta.searchSourceJSON.index")

        dashboard = next(item for item in objects if item["type"] == "dashboard")
        dashboard_attributes = dashboard["attributes"]
        self.assertIsInstance(dashboard_attributes, dict)
        self.assertEqual(dashboard_attributes["title"], "Honeypot AI Single Pane")
        self.assertTrue(dashboard_attributes["timeRestore"])
        self.assertEqual(dashboard_attributes["timeFrom"], "now-1h")
        self.assertEqual(dashboard_attributes["refreshInterval"], {"pause": False, "value": 5000})
        dashboard_refs = {ref["name"] for ref in dashboard["references"]}  # type: ignore[index]
        dashboard_panels = json.loads(str(dashboard_attributes["panelsJSON"]))
        panel_refs = {panel["panelRefName"] for panel in dashboard_panels}
        self.assertTrue(panel_refs.issubset(dashboard_refs))

    def test_wazuh_dashboard_spec_covers_single_pane_sources(self) -> None:
        path = ROOT / "deploy" / "wazuh" / "dashboard" / "honeypot-ai-dashboard-spec.json"
        spec = json.loads(path.read_text())
        panel_ids = {panel["id"] for panel in spec["panels"]}
        all_fields = {field for panel in spec["panels"] for field in panel["fields"]}
        all_queries = "\n".join(panel["query"] for panel in spec["panels"])

        self.assertEqual(spec["data_view"], "wazuh-alerts-*")
        self.assertEqual(spec["refresh_interval_seconds"], 5)
        self.assertIn("data.integration", spec["base_filter"])
        self.assertIn("integration", spec["base_filter"])
        self.assertIn("misp_matches", panel_ids)
        self.assertIn("ebpf_event_mix", panel_ids)
        self.assertIn("recent_events", panel_ids)
        self.assertIn("data.ml_score", all_fields)
        self.assertIn("rule.groups", all_fields)
        self.assertIn("data.event_type", all_fields)
        self.assertIn("honeypot_ai_misp", all_queries)
        self.assertIn("ebpf_event", all_queries)


if __name__ == "__main__":
    unittest.main()
