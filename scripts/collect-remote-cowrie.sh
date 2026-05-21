#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Collect Cowrie JSON logs from a remote honeypot and run the local analyzer.

Required environment:
  HONEYPOT_HOST       Remote host or IP address.

Optional environment:
  HONEYPOT_USER       SSH user. Defaults to current local user.
  HONEYPOT_SSH_PORT   SSH port. Defaults to 22.
  HONEYPOT_REMOTE_DIR Remote Cowrie log directory.
                      Defaults to /opt/honeypot/cowrie/var/log/cowrie.
  HONEYPOT_ID         Local sensor directory/report name. Defaults to host.
  HONEYPOT_LOCAL_DIR  Local raw-log root. Defaults to logs/raw/cowrie.
  HONEYPOT_REPORT_DIR Local report directory. Defaults to logs/reports.
  ANALYZE_FORMAT      markdown, json, or misp. Defaults to markdown.

Example:
  HONEYPOT_HOST=203.0.113.10 HONEYPOT_USER=ubuntu scripts/collect-remote-cowrie.sh
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${HONEYPOT_HOST:-}" ]]; then
  usage >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
remote_user="${HONEYPOT_USER:-$(id -un)}"
remote_port="${HONEYPOT_SSH_PORT:-22}"
remote_dir="${HONEYPOT_REMOTE_DIR:-/opt/honeypot/cowrie/var/log/cowrie}"
sensor_id="${HONEYPOT_ID:-$HONEYPOT_HOST}"
local_root="${HONEYPOT_LOCAL_DIR:-$repo_root/logs/raw/cowrie}"
report_root="${HONEYPOT_REPORT_DIR:-$repo_root/logs/reports}"
format="${ANALYZE_FORMAT:-markdown}"

if [[ ! "$remote_port" =~ ^[0-9]+$ ]]; then
  echo "HONEYPOT_SSH_PORT must be numeric" >&2
  exit 2
fi

case "$format" in
  markdown) report_ext="md" ;;
  json | misp) report_ext="json" ;;
  *)
    echo "Unsupported ANALYZE_FORMAT: $format" >&2
    exit 2
    ;;
esac

local_dir="$local_root/$sensor_id"
report_path="$report_root/${sensor_id}-latest.$report_ext"

mkdir -p "$local_dir" "$report_root"

rsync -az \
  -e "ssh -p $remote_port" \
  --exclude='*.gz' \
  --exclude='*.zip' \
  --exclude='*.bz2' \
  --exclude='*.xz' \
  --include='cowrie.json' \
  --include='cowrie.json.*' \
  --exclude='*' \
  "${remote_user}@${HONEYPOT_HOST}:${remote_dir}/" \
  "$local_dir/"

PYTHONPATH="$repo_root/src" \
  python3 -m honeypot_ai analyze "$local_dir" --source cowrie --format "$format" \
  > "$report_path"

echo "Collected Cowrie logs into $local_dir"
echo "Wrote $format report to $report_path"
