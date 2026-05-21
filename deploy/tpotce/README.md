# T-Pot CE Integration

This project integrates with T-Pot CE as a log collection and analysis target.
It does not vendor or repackage T-Pot itself; install and update T-Pot from the
upstream project:

- https://github.com/telekom-security/tpotce

## Remote Host Checklist

Use an isolated VPS, VM, or lab host with no route into trusted networks.

1. Meet the upstream T-Pot requirements for the selected role. The current
   T-Pot README calls out 8-16 GB RAM, 128 GB free disk, and a working outbound
   internet connection for installation and operation.
2. Install a supported Linux distribution with minimal services. Keep real SSH
   administration separate from exposed honeypot services.
3. Review T-Pot's default community data submission behavior before collecting
   live data. Disable services such as `ewsposter` in the T-Pot compose file if
   your experiment requires local-only telemetry.
4. Restrict outbound traffic where practical. Honeypot artifacts and captured
   sessions should be treated as hostile.
5. Snapshot or rotate the T-Pot data directory before long-running experiments.

## Install T-Pot

Follow the upstream installer and deployment guidance. T-Pot stores its working
copy in `~/tpotce` by default, and persistent honeypot/tool logs are kept under
`~/tpotce/data`.

For research runs, document the T-Pot git commit or release, selected compose
profile, public ports, host region/provider, and any opt-out changes. Those
details materially affect the traffic and logs you collect.

## Collect Logs Locally

From this repository on the analysis workstation:

```bash
TPOT_HOST=REMOTE \
TPOT_USER=user \
scripts/collect-remote-tpot.sh
```

The collector pulls JSON-like logs, including rotated compressed JSON files,
from `~/tpotce/data` into
`logs/raw/tpot/<host>/` and writes the latest analysis report to
`logs/reports/<host>-tpot-latest.md`.

Override the remote T-Pot data path when needed:

```bash
TPOT_HOST=REMOTE \
TPOT_USER=user \
TPOT_REMOTE_DIR=/opt/tpotce/data \
scripts/collect-remote-tpot.sh
```

The analyzer can also read a local T-Pot data export directly:

```bash
PYTHONPATH=src python3 -m honeypot_ai analyze --source tpot /path/to/tpotce/data
```

## Supported Inputs

The collector intentionally copies JSON, JSONL, NDJSON, and compressed rotated
variants of those files only. Several T-Pot services write plain text or CSV
files that T-Pot's own Logstash pipeline can parse, but this prototype does not
ingest those raw formats yet.

The parser recognizes T-Pot-normalized records for the managed honeypot, NSM,
and tool service types listed by T-Pot, including `ADBHoney`, `Beelzebub`,
`CiscoASA`, `CitrixHoneypot`, `ConPot`, `Cowrie`, `Ddospot`, `Dicompot`,
`Dionaea`, `ElasticPot`, `Endlessh`, `Galah`, `Go-pot`, `Glutton`, `H0neytr4p`,
`HellPot`, `Heralding`, `Honeyaml`, `qHoneypots`, `Honeytrap`, `IPPHoney`,
`Log4Pot`, `Mailoney`, `Medpot`, `Miniprint`, `RedisHoneyPot`, `SentryPeer`,
`Snare`, `Tanner`, `Wordpot`, `Fatt`, `P0f`, `Suricata`, `NGINX`, `AttackMap`,
`Autoheal`, `CyberChef`, `Elasticsearch`, `Elasticvue`, `Ewsposter`,
`GeoIP Attack Map`, `Kibana`, `Logstash`, `Map Redis`, `Map Web`, `Spiderfoot`,
and `Tpotinit`. Cowrie, Dionaea, Suricata, and Zeek-shaped records are dispatched
to dedicated parsers; other T-Pot JSON records are normalized through the
generic event path.
