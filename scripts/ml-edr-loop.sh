#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Run the ML EDR evaluation/tuning loop over local T-Pot exports.

By default this uses tractable local exports and skips the broad data/logs_only
tree because that can take several minutes. Use --include-logs-only when that
full local export is needed.

Environment:
  PIXI                   Pixi executable. Defaults to pixi on PATH, then $HOME/.pixi/bin/pixi.
  PROTECTED_CIDR         Protected endpoint CIDR. Defaults to 10.0.5.0/24.
  ML_LOOP_OUT_DIR        Output directory. Defaults to data/ml/loop.
  TARGET_FPR             Target-FPR objective budget. Defaults to 0.10.
  TARGET_ALERTS_PER_DAY  Alert/day objective budget. Defaults to 50.

Options:
  --sync               Run scripts/sync-tpot-logs.sh first if .env has TPOT_HOST.
  --include-logs-only  Include data/logs_only in dataset generation.
  -h, --help           Show this help.
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -n "${PIXI:-}" ]]; then
  pixi="$PIXI"
elif command -v pixi >/dev/null 2>&1; then
  pixi="$(command -v pixi)"
else
  pixi="$HOME/.pixi/bin/pixi"
fi
protected_cidr="${PROTECTED_CIDR:-10.0.5.0/24}"
out_dir="${ML_LOOP_OUT_DIR:-$repo_root/data/ml/loop}"
target_fpr="${TARGET_FPR:-0.10}"
target_alerts_per_day="${TARGET_ALERTS_PER_DAY:-50}"
sync_first=false
include_logs_only=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sync)
      sync_first=true
      shift
      ;;
    --include-logs-only)
      include_logs_only=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$out_dir"

if [[ "$sync_first" == true ]]; then
  if [[ -f "$repo_root/.env" ]] && grep -Eq '^TPOT_HOST=.+' "$repo_root/.env"; then
    "$repo_root/scripts/sync-tpot-logs.sh" --env "$repo_root/.env"
  else
    echo "Skipping remote sync: .env is missing TPOT_HOST." >&2
  fi
fi

run_tuning_objectives() {
  local name="$1"
  local dataset="$2"

  "$pixi" run python -m honeypot_ai tune "$dataset" \
    --format json \
    --threshold-objective best-f1 \
    --output "$out_dir/$name-tune.json"
  "$pixi" run python -m honeypot_ai tune "$dataset" \
    --format json \
    --threshold-objective target-fpr \
    --target-fpr "$target_fpr" \
    --output "$out_dir/$name-tune-target-fpr.json"
  "$pixi" run python -m honeypot_ai tune "$dataset" \
    --format json \
    --threshold-objective target-alerts-per-day \
    --target-alerts-per-day "$target_alerts_per_day" \
    --output "$out_dir/$name-tune-target-alerts-per-day.json"
}

run_existing_dataset() {
  local name="$1"
  local dataset="$2"
  if [[ ! -f "$dataset" ]]; then
    return
  fi
  echo "Tuning existing dataset: $name"
  run_tuning_objectives "$name" "$dataset"
  "$pixi" run python -m honeypot_ai evaluate "$dataset" \
    --format json \
    --output "$out_dir/$name-evaluate.json"
}

run_export_dir() {
  local name="$1"
  local path="$2"
  if [[ ! -d "$path" ]]; then
    return
  fi
  local dataset="$out_dir/$name-windows.json"
  echo "Building dataset: $name from $path"
  "$pixi" run python -m honeypot_ai dataset \
    --source tpot \
    --protected-cidr "$protected_cidr" \
    --output "$dataset" \
    "$path"
  run_existing_dataset "$name" "$dataset"
}

run_existing_dataset "tpot-saved" "$repo_root/data/ml/tpot-windows.json"
run_export_dir "tpot-logs" "$repo_root/data/tpot_logs"
run_export_dir "tpot-logs-2" "$repo_root/data/tpot_logs_2"
run_export_dir "tpot-rsync" "$repo_root/data/tpot_logs_with_rsync_instead"

if [[ "$include_logs_only" == true ]]; then
  run_export_dir "logs-only" "$repo_root/data/logs_only"
fi

echo "ML EDR loop outputs written to $out_dir"
