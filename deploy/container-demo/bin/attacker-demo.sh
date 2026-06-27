#!/usr/bin/env bash
set -euo pipefail

RAW_LOG="${RAW_LOG:-/data/raw/honeypot.ndjson}"
ATTACKER_IP="${ATTACKER_IP:-10.70.1.50}"
TARGET_IP="${TARGET_IP:-10.70.0.10}"
PROXY_HOST="${PROXY_HOST:-reverse-proxy}"
PROXY_HTTP_PORT="${PROXY_HTTP_PORT:-80}"
PROXY_SSH_PORT="${PROXY_SSH_PORT:-2222}"

echo "[attacker] scanning $PROXY_HOST through exposed proxy ports"
nmap -sT -Pn -p 1-1024,"$PROXY_SSH_PORT" "$PROXY_HOST" || true

echo "[attacker] probing dashboard over HTTP"
curl -fsS "http://${PROXY_HOST}:${PROXY_HTTP_PORT}/" >/tmp/dashboard-probe.html || true

echo "[attacker] attempting SSH logins through the reverse proxy"
for attempt in "root:admin" "admin:password" "root:toor"; do
  user="${attempt%%:*}"
  pass="${attempt#*:}"
  sshpass -p "$pass" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -p "$PROXY_SSH_PORT" \
    "${user}@${PROXY_HOST}" \
    "uname -a" >/tmp/ssh-attempt.log 2>&1 || true
done

echo "[attacker] appending normalized telemetry for deterministic SIEM and ML alerts"
python /app/deploy/container-demo/bin/emit_attack_events.py \
  --raw-log "$RAW_LOG" \
  --attacker-ip "$ATTACKER_IP" \
  --target-ip "$TARGET_IP"

echo "[attacker] done; wait a few seconds and refresh the dashboard"
