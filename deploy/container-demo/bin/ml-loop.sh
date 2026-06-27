#!/usr/bin/env bash
set -euo pipefail

RAW_LOG="${RAW_LOG:-/data/raw/honeypot.ndjson}"
ML_ALERT_LOG="${ML_ALERT_LOG:-/data/alerts/ml-alerts.ndjson}"
DATASET_PATH="${ML_DATASET_PATH:-/data/ml/windows.json}"
MODEL_DIR="${ML_MODEL_DIR:-/data/models/current}"
POLL_SECONDS="${ML_POLL_SECONDS:-5}"
WINDOW_SECONDS="${ML_WINDOW_SECONDS:-60}"
PROTECTED_CIDR="${PROTECTED_CIDR:-10.70.0.0/24}"
THRESHOLD="${ML_THRESHOLD:-0}"

mkdir -p "$(dirname "$RAW_LOG")" "$(dirname "$ML_ALERT_LOG")" "$(dirname "$DATASET_PATH")" "$MODEL_DIR"
touch "$RAW_LOG" "$ML_ALERT_LOG"

last_signature=""
echo "ML loop watching $RAW_LOG with protected CIDR $PROTECTED_CIDR"

while true; do
  signature="$(stat -c '%s:%Y' "$RAW_LOG" 2>/dev/null || true)"
  if [[ -n "$signature" && "$signature" != "$last_signature" && -s "$RAW_LOG" ]]; then
    tmp_dataset="${DATASET_PATH}.tmp"
    tmp_alerts="${ML_ALERT_LOG}.tmp"

    if python -m honeypot_ai dataset "$RAW_LOG" \
      --protected-cidr "$PROTECTED_CIDR" \
      --window-seconds "$WINDOW_SECONDS" \
      --output "$tmp_dataset"; then
      rows="$(python -c 'import json,sys; print(len(json.load(open(sys.argv[1], encoding="utf-8"))))' "$tmp_dataset")"
      if [[ "$rows" -gt 0 ]]; then
        mv "$tmp_dataset" "$DATASET_PATH"
        python -m honeypot_ai train "$DATASET_PATH" \
          --model-dir "$MODEL_DIR" \
          --scorer river \
          --threshold-quantile 0.50 >/data/ml/train.log 2>&1 || cat /data/ml/train.log
        if [[ -f "$MODEL_DIR/model.joblib" ]]; then
          python -m honeypot_ai score "$DATASET_PATH" \
            --model "$MODEL_DIR/model.joblib" \
            --threshold "$THRESHOLD" \
            --include-below-threshold \
            --format wazuh \
            --output "$tmp_alerts"
          mv "$tmp_alerts" "$ML_ALERT_LOG"
          echo "ML loop wrote $rows endpoint window(s) to $ML_ALERT_LOG"
        fi
      else
        : > "$ML_ALERT_LOG"
        rm -f "$tmp_dataset"
      fi
    else
      echo "ML loop skipped invalid or incomplete input batch" >&2
      rm -f "$tmp_dataset" "$tmp_alerts"
    fi
    last_signature="$signature"
  fi
  sleep "$POLL_SECONDS"
done
