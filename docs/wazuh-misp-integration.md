# Wazuh and MISP Integration

Last updated: 2026-06-21

## Wazuh Export

Honeypot AI can emit Wazuh-friendly newline-delimited JSON from analysis reports:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --format wazuh \
  sample_logs/honeypot.ndjson >> /var/log/honeypot-ai/alerts.ndjson
```

ML/EDR alerts can use the same format:

```bash
PYTHONPATH=src python3 -m honeypot_ai score data/ml/tpot-windows.json \
  --model data/models/tpot-baseline/model.joblib \
  --format wazuh >> /var/log/honeypot-ai/alerts.ndjson
```

Each line is flat JSON with stable top-level fields:

- `schema_version`
- `integration`
- `kind`
- `rule_name`
- `severity`, when available
- source/destination fields such as `src_ip`, `dest_ip`, `domain`, and
  `indicator`, when available

The Wazuh agent can collect that file with the sample config in
`deploy/wazuh/ossec-localfile.xml`. The sample manager rules live in
`deploy/wazuh/rules/honeypot-ai-rules.xml`.

## Real-Time Ingestion

The real-time layer is a file tailer that keeps a Wazuh alert stream updated as
new source events arrive:

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-stream \
  /path/to/tpot/source.ndjson \
  --source tpot \
  --output /var/log/honeypot-ai/alerts.ndjson \
  --state-file /var/lib/honeypot-ai/wazuh-stream.state.json \
  --poll-seconds 2
```

`wazuh-stream` tracks byte offsets, ignores partial trailing lines until they
are complete, converts newly appended raw events to Wazuh-format alert NDJSON,
and appends those alerts to the file watched by Wazuh. If the upstream process
already emits Honeypot AI Wazuh-format alerts, use `--input-format wazuh` to
validate and pass them through without re-analysis.

For production, install the sample service template at
`deploy/wazuh/systemd/honeypot-ai-wazuh-stream.service` after adjusting paths
and the runtime user.

## Single Dashboard

Wazuh already provides its own dashboard through Wazuh Dashboard / OpenSearch
Dashboards. For this project, the simplest single-pane path is to make Wazuh
the common alert index and add Honeypot AI panels there.

The starter import bundle is:

```text
deploy/wazuh/dashboard/honeypot-ai-overview.ndjson
```

It filters the Wazuh alerts index to Honeypot AI events, defaults to the last
hour with a 5-second refresh interval, and shows:

- high confidence alerts
- MISP matches
- alert volume over time
- alerts by pipeline (`finding`, `ml_alert`, `ebpf_event`)
- eBPF event mix
- recent event table

The dashboard uses the Wazuh-decoded JSON fields under `data.*`, with a
top-level fallback for deployments that index custom JSON fields without the
`data.` prefix. The readable dashboard contract lives at
`deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json`.

Local pre-deployment preview:

```bash
bash scripts/local-wazuh-dashboard-smoke.sh
python3 -m http.server 8091 --bind 127.0.0.1 --directory build/wazuh-preview
```

Then open `http://127.0.0.1:8091/`. This validates the local Wazuh-format data
and preview layout before importing anything into the research-server SIEM.

Local real-time preview:

```bash
bash scripts/local-wazuh-dashboard-live.sh
python3 -m http.server 8092 --bind 127.0.0.1 --directory build/wazuh-live
```

Then open `http://127.0.0.1:8092/`. In another terminal, append JSON lines to
`build/wazuh-live/source.ndjson`; the tailer updates
`build/wazuh-live/alerts.ndjson` and regenerates the preview page.

## MISP Push

Push extracted IOCs into a new MISP event:

```bash
PYTHONPATH=src python3 -m honeypot_ai misp-push \
  --misp-url "$MISP_URL" \
  --misp-key "$MISP_API_KEY" \
  --event-info "Honeypot AI IOC export" \
  --tag source:honeypot \
  sample_logs/honeypot.ndjson
```

Use `--dry-run` to inspect the event payload without sending it:

```bash
PYTHONPATH=src python3 -m honeypot_ai misp-push --dry-run \
  --event-info "Honeypot AI IOC export" \
  sample_logs/honeypot.ndjson
```

The exporter reuses the existing MISP-style attribute conversion. Private,
reserved, and documentation indicators are kept as `to_ids: false`; globally
routable indicators and hashes remain eligible for detection.

## MISP Pull to Wazuh CDB

Pull MISP attributes into Wazuh CDB list files:

```bash
PYTHONPATH=src python3 -m honeypot_ai misp-pull \
  --misp-url "$MISP_URL" \
  --misp-key "$MISP_API_KEY" \
  --output-dir deploy/wazuh/cdb-lists/generated
```

Generated files:

- `misp-ip`
- `misp-domain`
- `misp-hash`
- `misp-url`

By default, only `to_ids` indicators are written. Use `--include-non-ids` only
for lab or review workflows where non-detection indicators are intentionally
included.

Copy the generated list files to the Wazuh manager list directory referenced by
the custom rules, then reload Wazuh and validate with `wazuh-logtest`.

## Data Flow

```text
honeypot logs / eBPF / ML windows
  -> Honeypot AI analysis or scoring
  -> honeypot_ai wazuh-stream for appended source events
  -> /var/log/honeypot-ai/alerts.ndjson
  -> Wazuh agent JSON localfile collector
  -> Wazuh manager custom rules
  -> Wazuh alerts index
  -> Wazuh Dashboard Honeypot AI Single Pane

MISP indicators
  -> honeypot_ai misp-pull
  -> Wazuh CDB lists
  -> Wazuh custom rules match decoded Honeypot AI fields

Honeypot AI extracted IOCs
  -> honeypot_ai misp-push
  -> MISP event attributes
```
