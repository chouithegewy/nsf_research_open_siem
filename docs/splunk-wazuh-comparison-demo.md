# Splunk vs Wazuh Comparison and Real-Time Demo

Last updated: 2026-06-23

## Research Objective

This project compares a commercial SIEM workflow against an open-source SIEM
workflow enhanced with project-specific endpoint and analyst tooling.

Commercial baseline:

```text
Splunk Enterprise / Splunk Enterprise Security style workflow
```

Open-source target:

```text
Wazuh + Honeypot AI + Rust eBPF sensor + ML windows + MISP + analyst dashboard
```

The research question is not whether Wazuh alone is a drop-in replacement for
Splunk Enterprise Security. The stronger and more accurate claim is:

```text
Can an open-source stack, extended with custom eBPF telemetry, behavioral ML,
MISP enrichment, and analyst workflow tooling, provide comparable monitoring
and triage capability for organizations that cannot afford commercial
enterprise security licensing?
```

## Comparison Method

The comparison should use the same telemetry, scenarios, threat intelligence,
and analyst questions in both systems.

Use three baselines:

1. Stock Splunk-style baseline.
   Splunk receives honeypot, endpoint, MISP, and ML alert data. Searches and
   dashboards show what the commercial workflow can do with the common data.

2. Stock Wazuh baseline.
   Wazuh receives standard logs and standard Wazuh rules. This shows what is
   available before project-specific additions.

3. Enhanced open-source baseline.
   Wazuh receives the same common data plus Honeypot AI Wazuh alerts, eBPF EDR
   telemetry, MISP CDB matches, ML anomaly windows, and project dashboards.

The fair comparison is:

```text
Splunk with the common data and searches
vs.
Wazuh with the common data and project extensions
```

Avoid comparing a polished Splunk workflow against raw Wazuh logs. The project
innovation is the layer that closes gaps in the open-source stack.

## Common Data Contract

Every demo run should have a `run_id` and, when possible, a `scenario_id`.
Those IDs make it possible to compare Splunk and Wazuh against the same event
sequence.

Recommended fields:

```text
run_id
scenario_id
timestamp
host
source
event_type
pid
ppid
uid
gid
comm
binary
arguments_sample
src_ip
src_port
dest_ip
dest_port
protocol
filename
access_type
container_id
cgroup_id
indicator
misp_match
ml_score
severity
rule_name
raw
```

The same normalized event should be exportable to:

```text
Splunk HEC
Wazuh localfile JSON
local preview dashboard
offline ground-truth evaluator
```

## Baseline Metrics

Use a 0-3 score for each capability:

```text
0 = missing or not demonstrated
1 = possible but manual or incomplete
2 = supported with configuration
3 = supported, visible, repeatable, and useful for analyst workflow
```

| Area | Measurement |
| --- | --- |
| Log ingestion coverage | Count expected sources ingested and parsed: Cowrie, Dionaea, Suricata, Zeek, T-Pot, eBPF, ML alerts, MISP enrichment. |
| Endpoint visibility | Compare process, parent process, user, binary, argv sample, file write, network connect, privilege change, container ID, and cgroup ID. |
| IOC/signature detection | Feed the same known indicators and signatures into both systems. Measure match rate, missed matches, duplicates, and alert quality. |
| Anomaly/behavior detection | Run behavior scenarios that do not rely on known IOCs. Measure whether shell chains, unusual writes, privilege changes, and abnormal outbound connections are detected. |
| Alert enrichment | Compare MISP context, process context, user, container, MITRE mapping, severity, and linked evidence. |
| Analyst workflow | Give the same task in each product: explain what happened, which host/process/user was involved, which IPs were contacted, and whether the activity is likely malicious. |
| Dashboard usability | Score whether the dashboard has timeline, top alerts, affected hosts, MISP hits, ML alerts, eBPF event mix, and raw-event drilldown. |
| Time to detection | `first_alert_time - source_event_time`. Track median, p95, and worst case per scenario. |
| False positives | Run benign traffic for a fixed window. Track false positives per hour and per 1,000 source events. |
| Deployment complexity | Track elapsed setup time, config files changed, services installed, restarts needed, and errors encountered. |
| Maintenance burden | Track rule/feed updates, dashboard changes, sensor upkeep, storage cleanup, and troubleshooting steps. |
| Licensing and operating cost | Compare software license cost, infrastructure cost, storage cost, and labor to deploy/maintain. |

Example scoring table:

| Capability | Splunk | Wazuh Stock | Wazuh + Project |
| --- | ---: | ---: | ---: |
| Honeypot ingestion | 3 | 2 | 3 |
| eBPF endpoint telemetry | 1 | 1 | 3 |
| MISP IOC matching | 2 | 2 | 3 |
| Behavioral ML windows | 2 | 0 | 3 |
| Single analyst dashboard | 3 | 2 | 3 |
| Licensing cost | 1 | 3 | 3 |

## Real-Time Demo Goal

The presentation should show both products receiving activity from the same
environment and turning it into analyst-visible security signals.

The demo should show:

1. Harmless activity appears as telemetry but does not create high-confidence
   alerts.
2. Suspicious activity creates findings in both Splunk and Wazuh.
3. MISP enrichment raises confidence when an entity matches known intelligence.
4. ML/eBPF behavior detection catches suspicious chains that do not require a
   known IOC.
5. The open-source stack shows the same operational story without enterprise
   SIEM licensing.

## Demo Topology

```text
Demo actor
  runs benign and suspicious commands
        |
        v
Honeypot or instrumented Linux host
  Rust eBPF sensor
  honeypot/T-Pot logs
        |
        v
Honeypot AI tooling
  parser
  IOC extraction
  MISP enrichment
  ML window scoring
  Wazuh alert export
  Splunk HEC export
        |
        +--> Splunk Enterprise dashboard/search
        |
        +--> Wazuh localfile -> Wazuh manager -> Wazuh dashboard
```

Store product URLs and credentials outside git:

```bash
SPLUNK_WEB_URL=http://<netbird-splunk-host>:8000
SPLUNK_HEC_URL=https://<netbird-splunk-host>:8088
SPLUNK_HEC_TOKEN=<secret>
SPLUNK_INDEX=honeypot
WAZUH_DASHBOARD_URL=https://<netbird-wazuh-host>
WAZUH_ALERT_STREAM=/var/log/honeypot-ai/alerts.ndjson
```

The private NetBird dashboard URLs belong in `.env` or lab notes, not in public
documentation.

## Current Implementation Status

Implemented now:

- Honeypot and NSM parser pipeline.
- MISP-style IOC extraction.
- Splunk HEC-compatible export for analysis reports.
- Wazuh-format alert export.
- `wazuh-stream` file tailer for near-real-time Wazuh alert ingestion.
- Local auto-refresh Wazuh dashboard preview.
- Wazuh dashboard saved-object bundle.
- MISP push and MISP pull to Wazuh CDB list files.
- Rust eBPF sensor MVP that captures process, file, network, privilege, UID/GID,
  and container-related fields.
- Rust eBPF live capture supports `--stream-output PATH`, which appends and
  flushes each event as it arrives for strict kernel-to-dashboard demos.

## Demo Mode A: Controlled Real-Time Replay

Use this mode first. It is repeatable, safe, and presentation-friendly.

1. Start Wazuh ingestion on the research server:

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-stream \
  /srv/honeypot-ai/demo/source.ndjson \
  --output /var/log/honeypot-ai/alerts.ndjson \
  --state-file /var/lib/honeypot-ai/demo-wazuh-stream.state.json \
  --poll-seconds 1
```

Omit `--source` for mixed demo files so the parser can auto-detect Cowrie,
T-Pot, Suricata, Zeek, and eBPF records line by line. Use `--source ebpf` only
when the tailed file contains eBPF records exclusively.

2. Configure Wazuh agent localfile collection:

```xml
<localfile>
  <location>/var/log/honeypot-ai/alerts.ndjson</location>
  <log_format>json</log_format>
  <label key="integration">honeypot-ai</label>
</localfile>
```

3. Start a Splunk ingest path.

Current code supports direct Splunk HEC export for analyzed files:

```bash
SPLUNK_HEC_URL="$SPLUNK_HEC_URL" \
SPLUNK_HEC_TOKEN="$SPLUNK_HEC_TOKEN" \
SPLUNK_INDEX="$SPLUNK_INDEX" \
PYTHONPATH=src python3 -m honeypot_ai analyze \
  --format splunk \
  /srv/honeypot-ai/demo/source.ndjson
```

For a live side-by-side demo, either configure Splunk to monitor the same
append-only source file or add a small tail-to-HEC wrapper before the final
presentation.

4. Append benign demo events.

Use normal activity that should be visible but low severity:

```bash
sed -n '1p' sample_logs/honeypot.ndjson >> /srv/honeypot-ai/demo/source.ndjson
```

5. Append suspicious eBPF demo events.

```bash
sed -n '1,4p' sample_logs/ebpf-events.ndjson >> /srv/honeypot-ai/demo/source.ndjson
```

Expected result:

- Wazuh sees new `honeypot-ai` alert rows.
- The Honeypot AI Wazuh dashboard updates on its refresh interval.
- Splunk search results update once the same events are indexed.
- The eBPF scenario shows process execution, outbound connection, file write,
  and privilege-related behavior as linked evidence.

## Demo Mode B: Live Host Activity

Use this after Mode A is working. This demonstrates the innovation layer more
convincingly because the events originate from live host behavior.

Start the eBPF sensor stream and the Wazuh tailer against the same append-only
file:

```bash
sudo target/release/honeypot-ebpf capture \
  --config config/ebpf-sensor.toml \
  --probe-object crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf \
  --duration-seconds 300 \
  --stream-output /srv/honeypot-ai/demo/ebpf-live-stream.ndjson
```

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-stream \
  /srv/honeypot-ai/demo/ebpf-live-stream.ndjson \
  --source ebpf \
  --output /var/log/honeypot-ai/alerts.ndjson \
  --state-file /var/lib/honeypot-ai/demo-ebpf-wazuh-stream.state.json \
  --poll-seconds 1
```

Benign activity:

```bash
id
whoami
date
uname -a
curl -fsS https://example.com/ -o /tmp/honeypot-demo-example.html
```

Suspicious but safe activity:

```bash
sh -c 'mkdir -p /tmp/honeypot-demo && echo demo > /tmp/honeypot-demo/payload.sh && chmod +x /tmp/honeypot-demo/payload.sh'
sh -c 'curl -fsS https://example.com/ -o /tmp/honeypot-demo/payload.txt'
python3 -c 'import socket; s=socket.socket(); s.settimeout(1); s.connect(("example.com", 80)); s.close()'
```

Do not modify `/etc`, create setuid files, or run real exploit payloads during
the presentation. If a high-risk behavior is needed for the story, replay a
synthetic eBPF event with the correct `scenario_id` instead.

Expected detection story:

```text
Benign commands:
  telemetry only, low or no alert severity

Shell creates executable in /tmp:
  behavior signal, possible persistence/staging

Shell or Python connects outbound:
  behavior signal, process-to-network correlation

MISP-matched IP/domain/hash:
  high-confidence IOC enrichment

ML window score above threshold:
  anomalous activity alert independent of known IOC
```

## Splunk Presentation Checks

Open the Splunk dashboard over NetBird using the lab URL stored outside git.

Useful searches:

```spl
index=honeypot source=honeypot-ai
| stats count by sourcetype
```

```spl
index=honeypot source=honeypot-ai
| table _time host sourcetype event.kind event.rule_name event.severity event.src_ip event.dest_ip event.event_type event.comm event.binary event.container_id
| sort - _time
```

```spl
index=honeypot source=honeypot-ai (event.severity=high OR event.ml_score>0.8 OR event.misp_match=true)
| table _time host event.rule_name event.severity event.indicator event.src_ip event.dest_ip event.comm event.binary
| sort - _time
```

Presentation points:

- Splunk is strong at search, indexing, and dashboarding.
- Splunk gives mature analyst workflows when configured well.
- Licensing and enterprise add-ons are the cost pressure this project is
  trying to avoid.

## Wazuh Presentation Checks

Open Wazuh Dashboard over NetBird and import/open the `Honeypot AI Single Pane`
dashboard from `deploy/wazuh/dashboard/honeypot-ai-overview.ndjson`.

Useful Wazuh/OpenSearch filters:

```text
data.integration: "honeypot-ai" or integration: "honeypot-ai"
```

```text
(data.integration: "honeypot-ai" or integration: "honeypot-ai") and data.kind: "ebpf_event"
```

```text
(rule.groups: "honeypot_ai_misp" or data.rule_name: honeypot_ai_misp*)
```

```text
(data.kind: "ml_alert" or data.rule_name: honeypot_ai_ml*)
```

Presentation points:

- Wazuh provides the open SIEM foundation.
- Project-specific alerts enter the same Wazuh alert workflow as other rules.
- MISP CDB lists allow threat-intel matching without a commercial feed product.
- eBPF and ML additions add endpoint behavior visibility that stock Wazuh does
  not provide by itself.

## Presentation Flow

1. Show the architecture slide.
   Explain that both products receive the same telemetry.

2. Show stock SIEM behavior.
   Open Splunk and Wazuh. Show that both can ingest and search security events.

3. Generate harmless activity.
   Run benign commands or append benign scenario events. Show telemetry appears
   but does not dominate the alert view.

4. Generate suspicious activity.
   Run the safe `/tmp` and outbound connection scenario or replay the eBPF
   sample chain. Show both systems receive the evidence.

5. Show MISP enrichment.
   Trigger or replay a known IOC match. Show why confidence increases when an
   observed entity exists in threat intelligence.

6. Show ML/eBPF behavior detection.
   Explain that this layer catches suspicious activity even when there is no
   known IOC. Show the window score and linked events.

7. Compare analyst workflow.
   In both dashboards, answer:

```text
What happened?
Which host/process/user was involved?
Which network destination was contacted?
Was there a MISP match?
Was the behavior anomalous?
What should an analyst investigate next?
```

8. Close with cost and capability.
   Splunk remains the mature commercial benchmark. The project demonstrates
   that Wazuh plus targeted open tooling can cover much of the same monitoring
   and triage workflow without enterprise licensing.

## Ground-Truth Evaluation Sheet

Record this for every scenario:

| Field | Value |
| --- | --- |
| run_id |  |
| scenario_id |  |
| scenario type | benign, IOC, behavior, ML, eBPF |
| source event time |  |
| Splunk first alert time |  |
| Wazuh first alert time |  |
| Splunk detected? | yes/no |
| Wazuh stock detected? | yes/no |
| Wazuh + project detected? | yes/no |
| Splunk false positive? | yes/no |
| Wazuh false positive? | yes/no |
| analyst answer complete? | yes/no |
| notes |  |

Compute:

```text
time_to_detection = first_alert_time - source_event_time
false_positive_rate = false_positive_alerts / benign_events
detection_rate = detected_malicious_scenarios / total_malicious_scenarios
```

## Demo Readiness Checklist

- Splunk web is reachable over NetBird.
- Splunk HEC or file monitor is enabled for Honeypot AI events.
- Wazuh Dashboard is reachable over NetBird.
- Wazuh agent is collecting `/var/log/honeypot-ai/alerts.ndjson`.
- Wazuh manager rules from `deploy/wazuh/rules/honeypot-ai-rules.xml` are
  loaded.
- Honeypot AI Wazuh dashboard is imported.
- MISP API credentials are present only in `.env` or server secret storage.
- MISP CDB lists have been generated and copied to the Wazuh manager.
- `wazuh-stream` is running and appending alerts.
- eBPF sensor is writing `--stream-output` to the file watched by
  `wazuh-stream`.
- A safe replay scenario is ready if live eBPF capture fails.
- The presenter has Splunk and Wazuh searches pinned or saved.

## Implementation Gaps Before Final Demo

Highest-value gaps:

1. Add a Splunk continuous tail-to-HEC path, or document the Splunk file monitor
   configuration used on the research server.
2. Add a scenario runner that appends demo events with a fresh `run_id` and
   `scenario_id`.
3. Verify Wazuh dashboard import and rule matches on the research server.
4. Capture screenshots or short recordings of the same scenario in Splunk and
   Wazuh for the final presentation.

These gaps do not block the research design. They are the remaining work needed
to make the live presentation reliable.
