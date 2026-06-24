#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root, for example: sudo $0 <sensor-user>" >&2
  exit 2
fi

sensor_user="${1:-${SUDO_USER:-}}"
if [[ -z "${sensor_user}" || "${sensor_user}" == "root" ]]; then
  echo "Usage: sudo $0 <sensor-user>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
unit_src="${repo_root}/deploy/ebpf/systemd/honeypot-ebpf@.service"
unit_dst="/etc/systemd/system/honeypot-ebpf@.service"
install_root="/home/${sensor_user}/nsf_research_ebpf"
unit_name="honeypot-ebpf@${sensor_user}.service"

if [[ ! -x "${install_root}/bin/honeypot-ebpf" ]]; then
  echo "Missing executable: ${install_root}/bin/honeypot-ebpf" >&2
  exit 2
fi
if [[ ! -f "${install_root}/bpf/ebpf-sensor-ebpf" ]]; then
  echo "Missing eBPF object: ${install_root}/bpf/ebpf-sensor-ebpf" >&2
  exit 2
fi
if [[ ! -f "${install_root}/config/ebpf-sensor.toml" ]]; then
  echo "Missing config: ${install_root}/config/ebpf-sensor.toml" >&2
  exit 2
fi

install -m 0644 "${unit_src}" "${unit_dst}"
mkdir -p "${install_root}/output"

# Avoid duplicate captures when replacing a manually started sensor.
pkill -f "honeypot-ebpf capture" 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now "${unit_name}"
systemctl --no-pager --full status "${unit_name}"
