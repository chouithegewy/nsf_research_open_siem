from __future__ import annotations

from collections import OrderedDict

from honeypot_ai.models import Event


TECHNIQUES = {
    "T1046": "Network Service Discovery",
    "T1053.003": "Scheduled Task/Job: Cron",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1496": "Resource Hijacking",
}


DOWNLOAD_TOKENS = ("wget ", "curl ", "tftp ", "ftp ", "scp ", "sftp ", "Invoke-WebRequest")
REVERSE_SHELL_TOKENS = ("/dev/tcp/", "bash -i", "sh -i", "nc -e", "ncat -e", "mkfifo")
PERSISTENCE_TOKENS = ("crontab", "/etc/cron", "systemctl enable", "rc.local", ".bashrc", ".profile")
SCANNER_TOKENS = ("nmap ", "masscan ", "zmap ", "hydra ", "medusa ")
MINER_TOKENS = ("xmrig", "cpuminer", "stratum+tcp", "miningpool", "monero")


def map_event(event: Event) -> tuple[str, ...]:
    techniques: OrderedDict[str, None] = OrderedDict()
    event_type = event.event_type.lower()
    command = (event.command or "").lower()

    if event.source == "cowrie" and "login.failed" in event_type:
        techniques["T1110"] = None
    if event.source == "cowrie" and event.command:
        techniques["T1059.004"] = None
    if any(token.lower() in command for token in DOWNLOAD_TOKENS) or event.url:
        techniques["T1105"] = None
    if any(token in command for token in REVERSE_SHELL_TOKENS):
        techniques["T1059.004"] = None
    if any(token in command for token in PERSISTENCE_TOKENS):
        techniques["T1053.003"] = None
    if any(token in command for token in SCANNER_TOKENS):
        techniques["T1046"] = None
    if any(token in command for token in MINER_TOKENS):
        techniques["T1496"] = None

    alert = event.raw.get("alert") if isinstance(event.raw.get("alert"), dict) else {}
    category = str(alert.get("category", "")).lower()
    signature = str(alert.get("signature", "")).lower()
    if "malware" in category or "command and control" in category or "c2" in signature:
        techniques["T1105"] = None

    return tuple(techniques.keys())


def describe(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)

