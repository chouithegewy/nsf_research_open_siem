#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

out_dir="${1:-build/wazuh-live}"
source_file="$out_dir/source.ndjson"
alerts_file="$out_dir/alerts.ndjson"
preview_file="$out_dir/index.html"
state_file="$out_dir/wazuh-stream.state.json"

mkdir -p "$out_dir"
: > "$source_file"
: > "$alerts_file"

export PYTHONPATH="${PYTHONPATH:-$repo_root/src}"

python3 - <<'PY' >> "$source_file"
from pathlib import Path

sample = Path("sample_logs/honeypot.ndjson").read_text(encoding="utf-8").splitlines()
ebpf = Path("sample_logs/ebpf-events.ndjson").read_text(encoding="utf-8").splitlines()
for line in sample[:5]:
    print(line)
for line in ebpf[:2]:
    print(line)
PY

python3 -m honeypot_ai wazuh-stream "$source_file" \
  --output "$alerts_file" \
  --state-file "$state_file" \
  --preview-output "$preview_file" \
  --poll-seconds "${POLL_SECONDS:-1}"
