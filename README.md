# Honeypot AI Research Prototype

This workspace now contains a small, tested prototype for turning honeypot and network-security logs into research-ready signals:

- Parse Cowrie, Dionaea, Suricata EVE JSON, Zeek `conn.log`/`http.log`/`dns.log` JSON, generic NDJSON, and T-Pot-normalized JSON for managed honeypot/NSM/tool services.
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

Splunk HEC-compatible events:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --format splunk sample_logs/honeypot.ndjson
```

To send directly to Splunk HTTP Event Collector:

```bash
SPLUNK_HEC_URL=https://splunk.example:8088 \
SPLUNK_HEC_TOKEN=TOKEN \
SPLUNK_INDEX=honeypot \
PYTHONPATH=src python3 -m honeypot_ai analyze --format splunk sample_logs/honeypot.ndjson
```

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Endpoint ML Workflow

Use Pixi for the Python ML environment:

```bash
pixi run test
pixi run dataset-sample
pixi run train-sample
pixi run score-sample
pixi run evaluate-sample
pixi run tune-sample
pixi run ml-loop
```

The sample workflow writes ignored local artifacts under `data/ml/` and
`data/models/`. It converts parsed honeypot/NSM events into protected-endpoint
time windows, trains an anomaly model, and scores windows into machine-learning
alerts.

Training now evaluates River Half-Space Trees and Isolation Forest variants.
By default, `--scorer auto` saves the stronger scorer when weak-label ROC-AUC
clears the River baseline; use `--scorer river` or
`--scorer isolation-forest-log1p` to force a scorer for comparison.

Use `evaluate` for temporal train/test splits before changing model behavior:

```bash
pixi run python -m honeypot_ai evaluate data/ml/tpot-windows.json --format markdown
```

Evaluation excludes placeholder timestamps before year 2000 by default and
reports ROC-AUC, PR-AUC, threshold precision/recall/F1, false-positive rate,
alert volume, severity split, and best scorer by metric.

Use `tune` or the loop script to select thresholds on a calibration slice before
checking held-out test metrics:

```bash
pixi run python -m honeypot_ai tune data/ml/tpot-windows.json --format markdown
pixi run python -m honeypot_ai tune data/ml/tpot-windows.json --threshold-objective target-fpr --target-fpr 0.10 --format markdown
ML_LOOP_OUT_DIR=/tmp/ml-edr-loop scripts/ml-edr-loop.sh
```

The default tuning objective is `best-f1`, which is useful for comparing model
families but can produce high alert volume. Use `--threshold-objective
target-fpr` or `--threshold-objective target-alerts-per-day` when the threshold
needs to respect an operational false-positive or alert-budget constraint. The
loop script runs all three objectives for each tractable local T-Pot export.

For real T-Pot exports, start by building an endpoint-window dataset:

```bash
pixi run python -m honeypot_ai dataset --source tpot \
  --protected-cidr 10.0.5.0/24 \
  --output data/ml/tpot-windows.json \
  --db data/honeypot-web.duckdb \
  /path/to/tpotce/data
```

Replace `10.0.5.0/24` with the defended host or sensor network for the
deployment being evaluated.

Train and score against that dataset:

```bash
pixi run python -m honeypot_ai train data/ml/tpot-windows.json \
  --model-dir data/models/tpot-baseline \
  --db data/honeypot-web.duckdb

pixi run python -m honeypot_ai score data/ml/tpot-windows.json \
  --model data/models/tpot-baseline/model.joblib \
  --output data/ml/tpot-alerts.json \
  --db data/honeypot-web.duckdb
```

For live or replayed network scoring, use the same model with either a pcap file
or a Linux packet interface:

```bash
pixi run python -m honeypot_ai live-sensor \
  --model data/models/tpot-baseline/model.joblib \
  --protected-cidr 10.0.5.0/24 \
  --pcap captures/sample.pcap

sudo pixi run python -m honeypot_ai live-sensor \
  --model data/models/tpot-baseline/model.joblib \
  --protected-cidr 10.0.5.0/24 \
  --interface eth0
```

The local web UI now includes an `ML Alerts` page and stores model metadata,
endpoint windows, and scored alerts in DuckDB when `--db` is provided. Use
[config/endpoint-detection.example.toml](config/endpoint-detection.example.toml)
as a starting point for local sensor settings; keep host-specific copies out of
git as `config/endpoint-detection.toml`.

## Rust eBPF Sensor MVP

The repository now includes the first Rust host-sensor MVP path:

```bash
cargo build -p ebpf-sensor
target/debug/honeypot-ebpf check --config config/ebpf-sensor.toml
target/debug/honeypot-ebpf capture --config config/ebpf-sensor.toml --dry-run
target/debug/honeypot-ebpf import sample_logs/ebpf-events.ndjson --db /tmp/honeypot-ebpf.duckdb
PYTHONPATH=src python3 -m honeypot_ai dataset --source ebpf \
  --protected-cidr 10.0.5.0/24 sample_logs/ebpf-events.ndjson
```

The implemented path covers the shared eBPF event schema, argument redaction,
NDJSON replay/import, DuckDB raw-event storage, Python eBPF parsing, eBPF-backed
endpoint-window features, web UI visibility through `/ebpf-events`, a fixed
ring-buffer wire decoder, and an optional Aya userspace live loader:

```bash
cargo build -p ebpf-sensor --features live-ebpf
bash scripts/build-ebpf-sensor.sh
sudo target/release/honeypot-ebpf capture \
  --config config/ebpf-sensor.toml \
  --probe-object crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf \
  --duration-seconds 60 \
  --output logs/raw/ebpf-live.ndjson
```

The kernel probe crate is intentionally outside the default workspace. It needs
nightly Rust with `-Z build-std=core` for the `bpfel-unknown-none` target and a
Linux host with BTF/ring-buffer support plus root or equivalent BPF capabilities.
The current probes emit a stable kernel/userspace wire record and extract
process `comm`, exec filename, openat filename/access type, IPv4 connect peer
IP/port, uid/gid, and pid. The live loader also opportunistically enriches
binary/argv for pid-bearing events from `/proc/<pid>/exe` and
`/proc/<pid>/cmdline` when the process is still present.
IPv6 peer extraction and deeper argv capture remain the next telemetry
hardening steps.

See [docs/ebpf-mvp.md](docs/ebpf-mvp.md) for the MVP boundaries and live probe
workflow.

Current implementation and validation notes are tracked in
[docs/ml-edr-phase.md](docs/ml-edr-phase.md). The recommended path for moving
from pull-based remote collection to safer near-real-time streaming is tracked
in [docs/realtime-honeypot-ingest.md](docs/realtime-honeypot-ingest.md).

## Remote Honeypot Deployment

The first deployment target is a remote Cowrie SSH honeypot with pull-based log
collection back into this repository:

- Deployment bundle: [deploy/remote-honeypot](deploy/remote-honeypot)
- Collector: [scripts/collect-remote-cowrie.sh](scripts/collect-remote-cowrie.sh)
- Raw logs: `logs/raw/cowrie/<host>/` (ignored by git)
- Generated reports: `logs/reports/` (ignored by git)

After the remote container is running:

```bash
HONEYPOT_HOST=REMOTE HONEYPOT_USER=user scripts/collect-remote-cowrie.sh
```

This pulls `cowrie.json` audit events from the remote host and writes a current
analysis report locally.

## T-Pot CE Integration

T-Pot CE can be used as a multi-honeypot sensor feeding this analyzer:

- Upstream platform: <https://github.com/telekom-security/tpotce>
- Integration notes: [deploy/tpotce](deploy/tpotce)
- Collector: [scripts/collect-remote-tpot.sh](scripts/collect-remote-tpot.sh)
- Raw logs: `logs/raw/tpot/<host>/` (ignored by git)

After T-Pot is running on the remote host:

```bash
TPOT_HOST=REMOTE TPOT_USER=user scripts/collect-remote-tpot.sh
```

To analyze an exported T-Pot data directory directly:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --source tpot /path/to/tpotce/data
```

## Research Direction

The current implementation is intentionally explainable. It gives a baseline that can be measured before adding heavier ML:

1. Build a labeled corpus from honeypot sessions.
2. Compare rule-only scoring, robust anomaly scoring, Isolation Forest, and command-sequence models.
3. Measure alert precision, analyst review cost, and discovery of novel command sequences.
4. Feed high-confidence IOCs into MISP, Wazuh, Security Onion, or another open SIEM workflow.

See [docs/research-notes.md](docs/research-notes.md) for source-backed notes and next experiments.
