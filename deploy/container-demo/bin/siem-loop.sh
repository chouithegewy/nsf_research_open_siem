#!/usr/bin/env bash
set -euo pipefail

RAW_LOG="${RAW_LOG:-/data/raw/honeypot.ndjson}"
ALERT_LOG="${ALERT_LOG:-/data/alerts/wazuh-alerts.ndjson}"
STATE_FILE="${SIEM_STATE_FILE:-/data/state/wazuh-stream.state.json}"
POLL_SECONDS="${SIEM_POLL_SECONDS:-2}"

mkdir -p "$(dirname "$RAW_LOG")" "$(dirname "$ALERT_LOG")" "$(dirname "$STATE_FILE")"
touch "$RAW_LOG" "$ALERT_LOG"

echo "SIEM loop tailing $RAW_LOG into $ALERT_LOG"
exec python -m honeypot_ai wazuh-stream "$RAW_LOG" \
  --output "$ALERT_LOG" \
  --state-file "$STATE_FILE" \
  --poll-seconds "$POLL_SECONDS"
