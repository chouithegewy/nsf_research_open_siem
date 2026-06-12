#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Collect logs and artifacts from a remote T-Pot CE host and run the local analyzer.

Required environment:
  TPOT_HOST        Remote T-Pot host or IP address.

Optional environment:
  TPOT_USER        SSH user. Defaults to current local user.
  TPOT_SSH_PORT    SSH port. Defaults to 22.
  TPOT_REMOTE_DIR  Remote T-Pot data directory. Defaults to ~/tpotce/data.
  TPOT_ID          Local sensor directory/report name. Defaults to host.
  TPOT_LOCAL_DIR   Local raw-log root. Defaults to logs/raw/tpot.
  TPOT_REPORT_DIR  Local report directory. Defaults to logs/reports.
  ANALYZE_FORMAT   markdown, json, misp, or both. Defaults to markdown.

Example:
  TPOT_HOST=203.0.113.10 TPOT_USER=ubuntu scripts/collect-remote-tpot.sh
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${TPOT_HOST:-}" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
remote_user="${TPOT_USER:-$(id -un)}"
remote_port="${TPOT_SSH_PORT:-22}"
remote_dir="${TPOT_REMOTE_DIR:-~/tpotce/data}"
sensor_id="${TPOT_ID:-$TPOT_HOST}"
local_root="${TPOT_LOCAL_DIR:-$repo_root/logs/raw/tpot}"
report_root="${TPOT_REPORT_DIR:-$repo_root/logs/reports}"
format="${ANALYZE_FORMAT:-markdown}"

if [[ ! "$remote_port" =~ ^[0-9]+$ ]]; then
  echo "TPOT_SSH_PORT must be numeric" >&2
  exit 2
fi

case "$format" in
  markdown) report_ext="md" ;;
  json | misp) report_ext="json" ;;
  both) report_ext="json" ;;
  *)
    echo "Unsupported ANALYZE_FORMAT: $format" >&2
    exit 2
    ;;
esac

local_dir="$local_root/$sensor_id"
report_base="$report_root/${sensor_id}-tpot-latest"
report_path="$report_base.$report_ext"

mkdir -p "$local_dir" "$report_root"

rsync -az \
  -e "ssh -p $remote_port" \
  "${remote_user}@${TPOT_HOST}:${remote_dir}/" \
  "$local_dir/"

if [[ "$format" == "both" ]]; then
  PYTHONPATH="$repo_root/src" \
    python3 -m honeypot_ai analyze "$local_dir" --source tpot --format json \
    > "$report_base.json"
  PYTHONPATH="$repo_root/src" \
    python3 -m honeypot_ai analyze "$local_dir" --source tpot --format markdown \
    > "$report_base.md"
else
  PYTHONPATH="$repo_root/src" \
    python3 -m honeypot_ai analyze "$local_dir" --source tpot --format "$format" \
    > "$report_path"
fi

echo "Collected T-Pot logs and artifacts into $local_dir"
if [[ "$format" == "both" ]]; then
  echo "Wrote json report to $report_base.json"
  echo "Wrote markdown report to $report_base.md"
else
  echo "Wrote $format report to $report_path"
fi
