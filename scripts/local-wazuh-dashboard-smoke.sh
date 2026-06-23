#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="${1:-build/wazuh-preview}"
alerts_file="$out_dir/alerts.ndjson"
preview_file="$out_dir/index.html"

mkdir -p "$out_dir"
: > "$alerts_file"

export PYTHONPATH="${PYTHONPATH:-$repo_root/src}"

python3 -m honeypot_ai analyze --format wazuh sample_logs/honeypot.ndjson >> "$alerts_file"
python3 -m honeypot_ai analyze --source ebpf --format wazuh sample_logs/ebpf-events.ndjson >> "$alerts_file"

cat >> "$alerts_file" <<'JSON'
{"schema_version":1,"timestamp":"2026-06-23T18:34:00+00:00","integration":"honeypot-ai","kind":"finding","rule_name":"honeypot_ai_misp_ip_match","severity":"high","src_ip":"8.8.8.8","indicator":"8.8.8.8","description":"local preview MISP CDB match"}
{"schema_version":1,"timestamp":"2026-06-23T18:35:00+00:00","integration":"honeypot-ai","kind":"ml_alert","rule_name":"honeypot_ai_ml_alert_high","severity":"high","endpoint":"10.0.5.20","process_name":"sh","ml_score":0.91,"reasons":"sh spawned curl; outbound connection from service account"}
JSON

python3 -m honeypot_ai wazuh-preview "$alerts_file" --output "$preview_file"

printf 'Local Wazuh preview data: %s\n' "$alerts_file"
printf 'Local Wazuh preview page: %s\n' "$preview_file"
printf 'Serve it with: python3 -m http.server 8091 --bind 127.0.0.1 --directory %s\n' "$out_dir"
