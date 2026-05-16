from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
from typing import Iterable

from honeypot_ai.mitre import DOWNLOAD_TOKENS, PERSISTENCE_TOKENS, REVERSE_SHELL_TOKENS, SCANNER_TOKENS
from honeypot_ai.models import Event, SessionFeatures


def aggregate_sessions(events: Iterable[Event]) -> list[SessionFeatures]:
    sessions: OrderedDict[str, SessionFeatures] = OrderedDict()
    for event in events:
        key = _session_key(event)
        features = sessions.setdefault(key, SessionFeatures(key=key, src_ip=event.src_ip))
        _apply_event(features, event)
    return list(sessions.values())


def _apply_event(features: SessionFeatures, event: Event) -> None:
    features.total_events += 1
    features.event_types.add(event.event_type)
    if not features.src_ip and event.src_ip:
        features.src_ip = event.src_ip
    _update_time_window(features, event.timestamp)

    event_type = event.event_type.lower()
    if event.source == "cowrie" and "login.failed" in event_type:
        features.login_failures += 1
    if event.source == "cowrie" and "login.success" in event_type:
        features.login_successes += 1
    if event.username:
        features.usernames.add(event.username)
    if event.password:
        features.passwords.add(event.password)
    if event.url:
        features.urls.add(event.url)
    for value in event.hashes.values():
        features.hashes.add(value)

    if event.command:
        command = event.command.lower()
        features.commands += 1
        if any(token.lower() in command for token in DOWNLOAD_TOKENS):
            features.download_commands += 1
        if any(token in command for token in REVERSE_SHELL_TOKENS):
            features.reverse_shells += 1
        if any(token in command for token in PERSISTENCE_TOKENS):
            features.persistence_attempts += 1
        if any(token in command for token in SCANNER_TOKENS):
            features.scanner_commands += 1
        if any(shell in command for shell in ("bash", "/bin/sh", "python -c", "perl -e")):
            features.suspicious_shells += 1

    if event.source == "suricata" and event.event_type == "alert":
        features.suricata_alerts += 1
    if event.source == "dionaea":
        features.dionaea_connections += 1
    if event.source == "zeek":
        features.network_connections += 1

    features.bytes_out += _int_from_raw(event, "orig_bytes", "bytes_toserver")
    features.bytes_in += _int_from_raw(event, "resp_bytes", "bytes_toclient")
    features.duration_seconds += _float_from_raw(event, "duration", "age")


def numeric_vector(features: SessionFeatures) -> tuple[float, ...]:
    return (
        float(features.total_events),
        float(features.login_failures),
        float(features.login_successes),
        float(features.commands),
        float(features.download_commands),
        float(features.reverse_shells),
        float(features.persistence_attempts),
        float(features.scanner_commands),
        float(features.suricata_alerts),
        float(features.network_connections),
        float(features.bytes_out),
        float(features.bytes_in),
        float(features.duration_seconds),
        float(len(features.usernames)),
        float(len(features.passwords)),
    )


def _session_key(event: Event) -> str:
    if event.session:
        return f"{event.source}:{event.session}"
    if event.src_ip:
        return f"{event.source}:src:{event.src_ip}"
    if event.dest_ip:
        return f"{event.source}:dest:{event.dest_ip}"
    return f"{event.source}:line:{event.line_number or 'unknown'}"


def _update_time_window(features: SessionFeatures, timestamp: datetime | None) -> None:
    if timestamp is None:
        return
    if features.first_seen is None or timestamp < features.first_seen:
        features.first_seen = timestamp
    if features.last_seen is None or timestamp > features.last_seen:
        features.last_seen = timestamp


def _int_from_raw(event: Event, *keys: str) -> int:
    total = 0
    flow = event.raw.get("flow") if isinstance(event.raw.get("flow"), dict) else {}
    for key in keys:
        for value in (event.raw.get(key), flow.get(key)):
            try:
                total += int(value)
            except (TypeError, ValueError):
                continue
    return total


def _float_from_raw(event: Event, *keys: str) -> float:
    total = 0.0
    flow = event.raw.get("flow") if isinstance(event.raw.get("flow"), dict) else {}
    for key in keys:
        for value in (event.raw.get(key), flow.get(key)):
            try:
                total += float(value)
            except (TypeError, ValueError):
                continue
    return total
