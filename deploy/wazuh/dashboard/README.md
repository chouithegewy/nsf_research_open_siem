# Honeypot AI Wazuh Dashboard

This directory contains a starter single-pane dashboard for Wazuh Dashboard /
OpenSearch Dashboards.

## Files

- `honeypot-ai-overview.ndjson`: importable saved-object bundle.
- `honeypot-ai-dashboard-spec.json`: readable dashboard contract for review,
  tests, and future regeneration.

## What It Shows

The dashboard is scoped to Honeypot AI events in Wazuh alerts:

```text
data.integration: "honeypot-ai" or integration: "honeypot-ai"
```

Panels included:

- high confidence alerts
- MISP matches
- alert volume over time
- alerts by pipeline (`finding`, `ml_alert`, `ebpf_event`)
- eBPF event mix
- recent event table

The saved-object dashboard defaults to the last hour and a 5-second refresh
interval so it reflects new Wazuh alerts as the SIEM indexes them.

## Import

1. Install the Wazuh localfile collector and manager rules from
   `deploy/wazuh`.
2. Confirm Honeypot AI alerts are present in the Wazuh alerts index.
3. In Wazuh Dashboard / OpenSearch Dashboards, import
   `honeypot-ai-overview.ndjson` from the saved objects management page.
4. Open the `Honeypot AI Single Pane` dashboard.

The bundle includes an index-pattern object for `wazuh-alerts-*`. If the target
Wazuh deployment already has a different data-view ID for the same index
pattern, import without overwriting the existing data view or adjust the
dashboard references after import.

## Local Preview

This repo also includes a local preview path that does not require Wazuh,
OpenSearch, Docker, or the research server. It validates Wazuh-format event
generation and renders a static dashboard from the same dashboard spec:

```bash
bash scripts/local-wazuh-dashboard-smoke.sh
python3 -m http.server 8091 --bind 127.0.0.1 --directory build/wazuh-preview
```

Then open:

```text
http://127.0.0.1:8091/
```

The generated files are ignored by git:

- `build/wazuh-preview/alerts.ndjson`
- `build/wazuh-preview/index.html`

For custom Wazuh-format events:

```bash
PYTHONPATH=src python3 -m honeypot_ai wazuh-preview \
  /path/to/alerts.ndjson \
  --output build/wazuh-preview/index.html
```

The local preview is a pre-deployment check. The target SIEM still needs its own
import test because saved-object formats differ between Wazuh/OpenSearch,
modern Kibana, and older T-Pot/Kibana deployments.

For a local real-time preview, run the stream tailer and serve the regenerated
preview directory:

```bash
bash scripts/local-wazuh-dashboard-live.sh
python3 -m http.server 8092 --bind 127.0.0.1 --directory build/wazuh-live
```

Append source JSON lines to `build/wazuh-live/source.ndjson`. The tailer updates
`build/wazuh-live/alerts.ndjson`, regenerates `build/wazuh-live/index.html`,
and the browser refreshes every 5 seconds.

## Troubleshooting

No dashboard data usually means one of these is true:

- the Wazuh agent is not reading `/var/log/honeypot-ai/alerts.ndjson`
- the Honeypot AI JSON was not emitted with `--format wazuh`
- custom Wazuh rules were not loaded on the manager
- MISP CDB lists were not generated or copied to the manager
- eBPF events are present as raw logs but not exported through the Wazuh format
