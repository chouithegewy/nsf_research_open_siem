# Rust eBPF Sensor MVP

Last updated: 2026-06-23

## Current MVP Boundary

Implemented now:

- Rust workspace crates for normalized eBPF events and the `honeypot-ebpf` CLI.
- `honeypot-ebpf check` for host readiness hints: BTF, ring-buffer hint, and BPF privilege note.
- `honeypot-ebpf capture --dry-run` for a machine-readable probe/readiness plan.
- Optional `live-ebpf` userspace loader feature that loads an Aya probe object,
  attaches MVP probes, drains the `EVENTS` ring buffer, decodes fixed wire
  records, and writes batch NDJSON, per-event streaming NDJSON, or DuckDB
  output.
- Standalone Aya eBPF probe crate with tracepoint/kprobe entrypoints for process, network, file, and privilege event families.
- Fixed-size kernel/userspace wire record decoder with redaction and watched-prefix filtering.
- `honeypot-ebpf import` and replay-style `run --input` for normalized eBPF NDJSON.
- DuckDB `ebpf_events` storage for raw process/file/network/privilege events.
- Python parser support for `--source ebpf` and automatic schema detection.
- eBPF-backed endpoint-window features and weak labels for guarded baseline learning.
- Web UI `/ebpf-events` table and dashboard counters.
- Sample fixture at `sample_logs/ebpf-events.ndjson`.

Not complete yet:

- IPv6 peer extraction and guaranteed argv capture for very short-lived processes.
- In-kernel filtering and rate limiting.
- Remote live attach is deployed but still needs an interactive sudo session or
  a narrowly scoped root execution path on the research server.
- Automatic model promotion for adaptive baseline mode.

## MVP Workflow

Build and run the userspace tool:

```bash
cargo build -p ebpf-sensor
target/debug/honeypot-ebpf check --config config/ebpf-sensor.toml
target/debug/honeypot-ebpf capture --config config/ebpf-sensor.toml --dry-run
target/debug/honeypot-ebpf import sample_logs/ebpf-events.ndjson --db /tmp/honeypot-ebpf.duckdb
```

Build the live userspace loader and kernel probe object on a Linux host with nightly Rust:

```bash
bash scripts/build-ebpf-sensor.sh
sudo target/release/honeypot-ebpf capture \
  --config config/ebpf-sensor.toml \
  --probe-object crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf \
  --duration-seconds 60 \
  --output logs/raw/ebpf-live.ndjson
```

For strict live SIEM ingestion, use `--stream-output`. This opens the file in
append mode and flushes each decoded event as it arrives from the ring buffer:

```bash
sudo target/release/honeypot-ebpf capture \
  --config config/ebpf-sensor.toml \
  --probe-object crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf \
  --duration-seconds 60 \
  --stream-output logs/raw/ebpf-live-stream.ndjson
```

That stream can be tailed by the Wazuh integration:

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-stream \
  logs/raw/ebpf-live-stream.ndjson \
  --source ebpf \
  --output /var/log/honeypot-ai/alerts.ndjson \
  --state-file /var/lib/honeypot-ai/ebpf-wazuh-stream.state.json \
  --poll-seconds 1
```

Build endpoint windows from the same fixture:

```bash
PYTHONPATH=src python3 -m honeypot_ai dataset --source ebpf \
  --protected-cidr 10.0.5.0/24 sample_logs/ebpf-events.ndjson
```

Use the existing web app with a database containing `ebpf_events`; the eBPF raw-event
view is available at `/ebpf-events`.

## Research Server Deployment

The research server deployment uses the same NetBird-reachable SSH settings as
the T-Pot collection scripts. Keep host-specific values in `.env`; do not commit
server addresses, private keys, or copied live output.

Build locally, then copy the release userspace binary, BPF object, and config:

```bash
bash scripts/build-ebpf-sensor.sh

ssh "$TPOT_USER@$TPOT_HOST" \
  'mkdir -p ~/nsf_research_ebpf/bin ~/nsf_research_ebpf/bpf ~/nsf_research_ebpf/config ~/nsf_research_ebpf/output ~/nsf_research_ebpf/logs'

rsync -az target/release/honeypot-ebpf \
  "$TPOT_USER@$TPOT_HOST:~/nsf_research_ebpf/bin/honeypot-ebpf"
rsync -az crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf \
  "$TPOT_USER@$TPOT_HOST:~/nsf_research_ebpf/bpf/ebpf-sensor-ebpf"
rsync -az config/ebpf-sensor.toml \
  "$TPOT_USER@$TPOT_HOST:~/nsf_research_ebpf/config/ebpf-sensor.toml"
```

Remote non-root validation:

```bash
ssh "$TPOT_USER@$TPOT_HOST" 'cd ~/nsf_research_ebpf && \
  ./bin/honeypot-ebpf check --config config/ebpf-sensor.toml && \
  ./bin/honeypot-ebpf capture --config config/ebpf-sensor.toml \
    --probe-object bpf/ebpf-sensor-ebpf \
    --duration-seconds 1 \
    --output output/dry-run.ndjson \
    --dry-run'
```

Remote live capture requires root or equivalent BPF capabilities because the
server reports `unprivileged_bpf_disabled=2`:

```bash
ssh -t "$TPOT_USER@$TPOT_HOST" 'cd ~/nsf_research_ebpf && \
  sudo ./bin/honeypot-ebpf capture \
    --config config/ebpf-sensor.toml \
    --probe-object bpf/ebpf-sensor-ebpf \
    --duration-seconds 30 \
    --stream-output output/ebpf-live-stream.ndjson \
    --output output/ebpf-live-smoke.ndjson \
    --db output/ebpf-live-smoke.duckdb'
```

Observed on 2026-06-16:

- deployed artifacts under `~/nsf_research_ebpf`;
- artifact hashes matched the local build;
- `check` passed with BTF, tracefs, and ring-buffer support present;
- `capture --dry-run` produced the expected six-probe plan;
- sample `import` and replay-to-DuckDB stored four events each;
- non-interactive `sudo -n` was blocked by the server because interactive
  authentication is required, so live kernel attach still needs an authenticated
  sudo session or a narrowly scoped sudoers rule for the sensor command.

## Event Schema

Normalized eBPF events use `schema_version: 1` and preserve these fields when available:

- process context: `host`, `pid`, `ppid`, `uid`, `gid`, `comm`, `binary`, `arguments_sample`
- runtime context: `cgroup_id`, `container_id`
- network context: `src_ip`, `src_port`, `dest_ip`, `dest_port`, `protocol`
- file context: `filename`, `access_type`
- triage context: `event_type`, `severity_hint`, `raw`

Supported MVP event types:

- `process_exec`
- `process_exit`
- `network_connect`
- `file_access`
- `privilege_change`

## Adaptive Baseline Guardrails

The MVP treats eBPF windows as unsafe for baseline learning when they contain hard-risk evidence:

- privilege changes
- sensitive file writes
- download-tool execution
- shell execution paired with outbound connections
- existing rule evidence such as reverse shell, persistence, Suricata alert, scanner command, or hash indicator

Those windows receive weak malicious labels, which keeps them out of the existing benign-only model fit path.

## Live Probe Notes

The `crates/ebpf-sensor-ebpf` crate is intentionally separate from the default workspace build. Current source declares:

- `EVENTS` ring buffer for fixed wire records.
- `tracepoint_sched_process_exec`
- `tracepoint_sched_process_exit`
- `tracepoint_sys_enter_connect`
- `kprobe_tcp_v4_connect`
- `kprobe_tcp_v6_connect`
- `tracepoint_sys_enter_openat`
- `tracepoint_sys_enter_setuid`
- `tracepoint_sys_enter_setgid`

The userspace `live-ebpf` loader expects those program names and the `EVENTS` map.
Current kernel extraction includes pid, uid/gid, comm, `sched_process_exec`
filename, IPv4 connect destination IP/port, and `openat` filename/access type.
The live loader opportunistically enriches binary/argv for pid-bearing events
from `/proc/<pid>/exe` and `/proc/<pid>/cmdline` before writing NDJSON/DuckDB
output. With `--stream-output`, each normalized event is appended and flushed
immediately so file tailers can forward it before the capture duration ends.

Next hardening pass:

- add IPv6 socket peer formatting;
- improve argv capture for very short-lived processes;
- apply watched-prefix and process/binary filters before events reach DuckDB or Python;
- add in-kernel prefix/rate filters once correctness is proven in userspace;
- run a root smoke test on Linux x86_64 with BTF and ring-buffer support.
