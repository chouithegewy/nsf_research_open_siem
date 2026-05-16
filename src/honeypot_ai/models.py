from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping


@dataclass(frozen=True)
class Event:
    source: str
    event_type: str
    timestamp: datetime | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    session: str | None = None
    username: str | None = None
    password: str | None = None
    command: str | None = None
    url: str | None = None
    domain: str | None = None
    filename: str | None = None
    hashes: Mapping[str, str] = field(default_factory=dict)
    raw: Mapping[str, Any] = field(default_factory=dict)
    line_number: int | None = None


@dataclass(frozen=True)
class IOC:
    kind: str
    value: str
    source: str
    context: str


@dataclass
class SessionFeatures:
    key: str
    src_ip: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_events: int = 0
    login_failures: int = 0
    login_successes: int = 0
    commands: int = 0
    download_commands: int = 0
    reverse_shells: int = 0
    persistence_attempts: int = 0
    scanner_commands: int = 0
    suspicious_shells: int = 0
    suricata_alerts: int = 0
    dionaea_connections: int = 0
    network_connections: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    duration_seconds: float = 0.0
    usernames: set[str] = field(default_factory=set)
    passwords: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    event_types: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class RiskFinding:
    session_key: str
    src_ip: str | None
    score: float
    severity: str
    reasons: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    anomaly_score: float


@dataclass
class ActorProfile:
    ip: str
    ip_scope: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    total_events: int = 0
    source_events: int = 0
    destination_events: int = 0
    sources: set[str] = field(default_factory=set)
    sessions: set[str] = field(default_factory=set)
    event_types: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    usernames: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)
    finding_score: float = 0.0
    finding_severities: set[str] = field(default_factory=set)
