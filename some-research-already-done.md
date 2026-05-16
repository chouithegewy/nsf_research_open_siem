# Verified Research Already Done

This file now keeps only source-backed research leads for the honeypot/SIEM/anomaly-detection prototype. The older generated list contained paper titles that should not be treated as verified citations.

## Tooling Documentation

1. Cowrie documentation: Cowrie records SSH/Telnet brute-force attempts and shell interaction, with structured audit output in `var/log/cowrie/cowrie.json`.
   Source: https://docs.cowrie.org/en/latest/README.html

2. Dionaea JSON and incident handlers: Dionaea can emit JSON connection and incident telemetry, but the current docs warn the handlers are pre-alpha and may change.
   Sources: https://dionaea.readthedocs.io/en/latest/ihandler/log_json.html and https://dionaea.readthedocs.io/en/latest/ihandler/log_incident.html

3. Suricata EVE JSON: EVE provides a JSON stream for alerts, anomalies, metadata, file info, flow records, and protocol records. The shared `event_type` field and `flow_id` support correlation.
   Source: https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html

4. Zeek `conn.log`: Zeek connection logs summarize endpoint, timing, protocol, duration, and byte-count features useful for session-level anomaly detection.
   Source: https://docs.zeek.org/en/v7.0.11/logs/conn.html

## Research Literature

1. Markus Ring, Sarah Wunderlich, Deniz Scheuring, Dieter Landes, and Andreas Hotho, "A survey of network-based intrusion detection data sets," Computers & Security, 2019.
   DOI: https://doi.org/10.1016/j.cose.2019.06.005

2. Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP 2018.
   Dataset page: https://www.unb.ca/cic/datasets/ids-2017.html

3. Nour Moustafa and Jill Slay, "UNSW-NB15: a comprehensive data set for network intrusion detection systems," MilCIS 2015.
   DOI: https://doi.org/10.1109/MilCIS.2015.7348942

4. Ansam Khraisat, Iqbal Gondal, Peter Vamplew, and Joarder Kamruzzaman, "Survey of intrusion detection systems: techniques, datasets and challenges," Cybersecurity, 2019.
   Source: https://cybersecurity.springeropen.com/articles/10.1186/s42400-019-0038-7

## Research Gap to Pursue

The useful gap is not another generic IDS benchmark. It is an explainable pipeline that joins high-interaction honeypot behavior with network telemetry, produces analyst-readable reasons, and still leaves room for ML comparison. The current codebase implements that baseline so future experiments can quantify whether heavier models actually improve detection quality.
