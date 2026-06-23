# Wazuh Integration

This deployment bundle lets Wazuh ingest Honeypot AI findings, ML/EDR alerts,
and eBPF telemetry as newline-delimited JSON.

## Agent Collection

Add `ossec-localfile.xml` to the Wazuh agent or merge its `<localfile>` block
into the existing `ossec.conf`:

```xml
<localfile>
  <location>/var/log/honeypot-ai/alerts.ndjson</location>
  <log_format>json</log_format>
  <label key="integration">honeypot-ai</label>
</localfile>
```

Then write alerts from this project. For batch testing:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --format wazuh \
  logs/raw/tpot/latest.ndjson >> /var/log/honeypot-ai/alerts.ndjson

PYTHONPATH=src python3 -m honeypot_ai score data/ml/tpot-windows.json \
  --model data/models/tpot-baseline/model.joblib \
  --format wazuh >> /var/log/honeypot-ai/alerts.ndjson
```

For near-real-time ingestion, run the tailer so appended source log lines are
converted into the Wazuh alert stream as they arrive:

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-stream \
  /path/to/tpot/source.ndjson \
  --source tpot \
  --output /var/log/honeypot-ai/alerts.ndjson \
  --state-file /var/lib/honeypot-ai/wazuh-stream.state.json \
  --poll-seconds 2
```

The sample systemd template is
`systemd/honeypot-ai-wazuh-stream.service`. Adjust the source log path and
working directory before installing it.

## Manager Rules

Copy `rules/honeypot-ai-rules.xml` into the Wazuh manager custom rules
directory and restart/reload Wazuh. Validate sample events with `wazuh-logtest`
before enabling alert routing.

## MISP Lists

Use `honeypot_ai misp-pull` to generate CDB list files from MISP attributes,
then copy the generated lists into the Wazuh manager list directory referenced
by the sample rules.

## Dashboard

Wazuh has its own dashboard layer through Wazuh Dashboard / OpenSearch
Dashboards. Import `dashboard/honeypot-ai-overview.ndjson` to add a single
Honeypot AI view over the same Wazuh alerts index used by the rest of the SIEM.

The dashboard shows signature/MISP findings, ML alerts, and eBPF EDR telemetry
from the shared Wazuh alert stream. The dashboard bundle defaults to the last
hour and a 5-second refresh interval. The readable panel contract lives in
`dashboard/honeypot-ai-dashboard-spec.json`.
