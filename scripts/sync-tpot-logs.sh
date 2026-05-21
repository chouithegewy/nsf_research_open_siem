#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Sync log-like files from a remote T-Pot CE host.

The script loads configuration from .env by default. Override with:
  scripts/sync-tpot-logs.sh --env path/to/file.env

Required .env values:
  TPOT_HOST        Remote host or IP address.
  TPOT_USER        SSH user.
  TPOT_REMOTE_DIR  Remote T-Pot data directory.

Optional .env values:
  TPOT_SSH_PORT        SSH port. Defaults to 22.
  TPOT_SSH_KEY         SSH private key path.
  TPOT_LOCAL_DIR       Local destination. Defaults to data/logs_only.
  TPOT_USE_SUDO_RSYNC  Use sudo -n rsync remotely. Defaults to true.

Example:
  cp .env.example .env
  editor .env
  scripts/sync-tpot-logs.sh
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_root/.env"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env)
      if [[ $# -lt 2 ]]; then
        echo "--env requires a path" >&2
        exit 2
      fi
      env_file="$2"
      shift 2
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

if [[ ! -f "$env_file" ]]; then
  echo "Missing env file: $env_file" >&2
  echo "Create one with: cp .env.example .env" >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$env_file"
set +a

required_vars=(TPOT_HOST TPOT_USER TPOT_REMOTE_DIR)
for var_name in "${required_vars[@]}"; do
  if [[ -z "${!var_name:-}" ]]; then
    echo "$var_name is required in $env_file" >&2
    exit 2
  fi
done

remote_port="${TPOT_SSH_PORT:-22}"
local_dir="${TPOT_LOCAL_DIR:-$repo_root/data/logs_only}"
use_sudo_rsync="${TPOT_USE_SUDO_RSYNC:-true}"

if [[ ! "$remote_port" =~ ^[0-9]+$ ]]; then
  echo "TPOT_SSH_PORT must be numeric" >&2
  exit 2
fi

ssh_cmd=(ssh -p "$remote_port")
if [[ -n "${TPOT_SSH_KEY:-}" ]]; then
  ssh_cmd+=(-i "$TPOT_SSH_KEY")
fi

printf -v ssh_remote_shell "%q " "${ssh_cmd[@]}"
ssh_remote_shell="${ssh_remote_shell% }"

rsync_args=(
  -rtvz
  --no-perms
  --chmod=Du=rwx,Dgo=rx,Fu=rw,Fgo=r
  -e "$ssh_remote_shell"
)

case "$use_sudo_rsync" in
  true | yes | 1)
    rsync_args+=(--rsync-path="sudo -n rsync")
    ;;
  false | no | 0)
    ;;
  *)
    echo "TPOT_USE_SUDO_RSYNC must be true or false" >&2
    exit 2
    ;;
esac

rsync_args+=(
  --exclude="*/downloads/***"
  --exclude="*/binaries/***"
  --exclude="*/bistreams/***"
  --exclude="*/tty/***"
  --include="*/"
  --include="*.json*"
  --include="*.log*"
  --include="*.txt*"
  --include="*.csv*"
  --exclude="*"
)

mkdir -p "$local_dir"

rsync "${rsync_args[@]}" \
  "${TPOT_USER}@${TPOT_HOST}:${TPOT_REMOTE_DIR%/}/" \
  "$local_dir/"

echo "Synced T-Pot log files into $local_dir"
