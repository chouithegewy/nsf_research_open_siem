#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OBJECT="$ROOT/crates/ebpf-sensor-ebpf/target/bpfel-unknown-none/release/ebpf-sensor-ebpf"
LOADER="$ROOT/target/release/honeypot-ebpf"

cargo +nightly build \
  -Z build-std=core \
  --target bpfel-unknown-none \
  --manifest-path "$ROOT/crates/ebpf-sensor-ebpf/Cargo.toml" \
  --release

cargo build \
  -p ebpf-sensor \
  --features live-ebpf \
  --release

cat <<EOF
Built userspace loader:
  $LOADER

Built eBPF object:
  $OBJECT
EOF
