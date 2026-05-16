# Honeypot AI Research Prototype

This workspace now contains a small, tested prototype for turning honeypot and network-security logs into research-ready signals:

- Parse Cowrie, Dionaea, Suricata EVE JSON, Zeek `conn.log`/`http.log`/`dns.log` JSON, and generic NDJSON.
- Extract IOCs from structured fields and attacker commands.
- Aggregate activity into attacker sessions.
- Correlate actors by IP across sensors, while preserving source/destination roles and IP scope.
- Map observable behaviors to selected MITRE ATT&CK techniques.
- Score risky sessions with transparent heuristics plus dependency-free robust anomaly scoring.
- Generate Markdown or JSON reports for experiment notes, SIEM enrichment, or later model training.

## Quick Start

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze sample_logs/honeypot.ndjson
```

JSON output:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --format json sample_logs/honeypot.ndjson
```

MISP-style IOC attributes:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --format misp sample_logs/honeypot.ndjson
```

The MISP-style export keeps private, documentation, and reserved test indicators as `to_ids: false`; real globally routable indicators remain detection-eligible.

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Research Direction

The current implementation is intentionally explainable. It gives a baseline that can be measured before adding heavier ML:

1. Build a labeled corpus from honeypot sessions.
2. Compare rule-only scoring, robust anomaly scoring, Isolation Forest, and command-sequence models.
3. Measure alert precision, analyst review cost, and discovery of novel command sequences.
4. Feed high-confidence IOCs into MISP, Wazuh, Security Onion, or another open SIEM workflow.

See [docs/research-notes.md](docs/research-notes.md) for source-backed notes and next experiments.
