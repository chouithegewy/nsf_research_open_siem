# Research Notes: Honeypot-to-SIEM Anomaly Detection

## Problem

Honeypots produce rich attacker interaction data, but the raw logs are noisy and sensor-specific. The immediate research problem is to transform Cowrie, Dionaea, Suricata, and Zeek records into explainable signals that support:

- IOC extraction for threat-intelligence sharing.
- Session-level behavioral summaries.
- ATT&CK-style TTP mapping.
- Baseline anomaly scoring that can be compared with heavier ML methods.

## Source-Backed Grounding

- Cowrie's output event reference documents shared fields such as `timestamp`, `src_ip`, and `session`, plus event families for login success/failure, command input, and file upload/download: https://docs.cowrie.org/en/latest/OUTPUT.html
- Dionaea exposes JSON and incident handlers for connection and attack telemetry, but the current docs warn those handlers are pre-alpha and may change: https://dionaea.readthedocs.io/en/latest/ihandler/log_json.html and https://dionaea.readthedocs.io/en/latest/ihandler/log_incident.html
- Suricata EVE JSON is a unified event stream for alerts, anomalies, file metadata, flow records, and protocol records. EVE records use `event_type`, and related records can be correlated with `flow_id`: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Zeek `conn.log` captures who talked to whom, when, for how long, and with which protocol. The JSON examples use fields such as `ts`, `uid`, `id.orig_h`, `id.resp_h`, `duration`, `orig_bytes`, and `resp_bytes`: https://docs.zeek.org/en/v7.0.10/logs/conn.html
- Zeek transaction logs share `uid` values with `conn.log`, which makes HTTP and DNS observations useful for pivoting from flow metadata into URLs, hosts, and queried domains.
- MITRE ATT&CK provides stable terminology for techniques used in this prototype, including T1105 Ingress Tool Transfer, T1110 Brute Force, T1059.004 Unix Shell, T1053.003 Cron, and T1046 Network Service Discovery: https://attack.mitre.org/
- Network-intrusion dataset surveys emphasize that labeled datasets are needed to evaluate anomaly-based IDS methods, and that dataset selection must account for recording environment, data type, and evaluation bias. See Ring et al., "A survey of network-based intrusion detection data sets," Computers & Security, 2019: https://doi.org/10.1016/j.cose.2019.06.005
- The CICIDS2017 dataset is commonly cited for labeled flow-based IDS evaluation; the original paper is Sharafaldin, Lashkari, and Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP 2018.
- The UNSW-NB15 dataset was created to address limitations in older KDD-era datasets and includes hybrid normal and synthetic attack traffic. See Moustafa and Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems," MilCIS 2015: https://doi.org/10.1109/MilCIS.2015.7348942

## Current Prototype Scope

Implemented now:

- JSON parser normalization for Cowrie, Dionaea, Suricata EVE, Zeek `conn.log`, and generic logs.
- IOC extraction from IP fields, URL fields, hashes, and attacker command text.
- Session aggregation using native session IDs when present and source IP fallbacks otherwise.
- Actor correlation across source and destination IPs, including IP scope classification for private and RFC 5737 documentation ranges.
- Transparent heuristic scoring for brute force, post-login command execution, downloads, reverse shells, persistence, scanner tooling, alerts, hashes, and large transfers.
- URL/domain extraction from Zeek HTTP and DNS JSON logs.
- Dependency-free robust anomaly scoring using median absolute deviation over session feature vectors.
- Markdown and JSON reports.
- MISP-style IOC attribute export for SIEM and threat-intelligence handoff.
- Export safety gating marks private, documentation, and reserved test indicators as `to_ids: false`.
- Unit tests over parsers, IOC extraction, and end-to-end sample analysis.

## Experiment Plan

1. Baseline validation
   - Run the current test corpus.
   - Add benign and low-noise sessions to check false-positive behavior.
   - Confirm that high-risk sessions remain explainable through reason strings.

2. Sensor expansion
   - Add real Cowrie `cowrie.json` samples.
   - Add Suricata `flow`, `http`, `dns`, and `fileinfo` examples.
   - Add Zeek `ssl.log`/`x509.log` and SSH client fingerprint support.

3. Model comparison
   - Keep the current heuristic score as the control.
   - Add scikit-learn Isolation Forest as an optional plugin when dependencies are available.
   - Add sequence features for command order, inter-command timing, and repeated attacker playbooks.

4. Evaluation metrics
   - Precision and recall on labeled sessions.
   - Alert volume per sensor per day.
   - Analyst explanation usefulness, measured by whether a finding includes concrete IOCs, commands, and ATT&CK tags.
   - Novelty: percentage of high-risk sessions without known hash/IP/domain reputation.

5. SIEM integration path
   - Export JSON findings to Wazuh, Security Onion/Elastic, or MISP.
   - Preserve raw event references so analysts can pivot back to original logs.

## Known Limitations

- MITRE mapping is intentionally partial and rule-based.
- The robust anomaly score needs at least several sessions to become meaningful.
- Anomaly-only findings should be treated as review prompts, not confirmed attacker evidence.
- Documentation-reserved IP ranges appear in sample logs; real deployments should classify private, reserved, and globally routable IPs separately.
- Dionaea JSON schemas are treated defensively because upstream documentation marks the handlers as unstable.
