# Honeypot eBPF systemd service

This bundle runs the Rust eBPF sensor continuously under root systemd and
writes normalized events to an append-only stream file:

```text
~/nsf_research_ebpf/output/ebpf-live-stream.ndjson
```

Install on the sensor host after copying the current `honeypot-ebpf` binary,
`ebpf-sensor-ebpf` object, and `config/ebpf-sensor.toml` into
`~/nsf_research_ebpf`:

```bash
sudo deploy/ebpf/install-systemd.sh "$USER"
```

The unit is templated as `honeypot-ebpf@<sensor-user>.service`. It runs as root
because live BPF loading usually requires root or equivalent BPF capabilities,
but it uses `/home/<sensor-user>/nsf_research_ebpf` for artifacts and output.

Status and logs:

```bash
sudo systemctl status "honeypot-ebpf@$USER.service"
sudo journalctl -u "honeypot-ebpf@$USER.service" -f
tail -f ~/nsf_research_ebpf/output/ebpf-live-stream.ndjson
```
