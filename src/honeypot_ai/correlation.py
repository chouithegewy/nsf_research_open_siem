from __future__ import annotations

import ipaddress
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from typing import Iterable

from honeypot_ai.mitre import map_event
from honeypot_ai.models import ActorProfile, Event, RiskFinding


DOCUMENTATION_NETS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
UTC_MIN = datetime.min.replace(tzinfo=timezone.utc)


def correlate_actors(events: Iterable[Event], findings: Iterable[RiskFinding]) -> list[ActorProfile]:
    actors: OrderedDict[str, ActorProfile] = OrderedDict()
    event_list = list(events)
    events_by_session: dict[str, list[Event]] = defaultdict(list)
    for event in event_list:
        if event.src_ip:
            _apply_event(actors, event.src_ip, event, role="source")
        if event.dest_ip and event.dest_ip != event.src_ip:
            _apply_event(actors, event.dest_ip, event, role="destination")
        events_by_session[_session_key(event)].append(event)

    for finding in findings:
        for ip in _finding_actor_ips(finding, events_by_session.get(finding.session_key, [])):
            actor = actors.setdefault(ip, ActorProfile(ip=ip, ip_scope=ip_scope(ip)))
            if _has_behavioral_evidence(finding):
                actor.finding_score += finding.score
                actor.finding_severities.add(finding.severity)
            actor.techniques.update(finding.mitre_techniques)

    return sorted(
        actors.values(),
        key=lambda actor: (
            actor.finding_score,
            len(actor.sources),
            actor.total_events,
            actor.last_seen or UTC_MIN,
        ),
        reverse=True,
    )


def ip_scope(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "invalid"
    if any(ip in network for network in DOCUMENTATION_NETS):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_global:
        return "global"
    return "special"


def _finding_actor_ips(finding: RiskFinding, session_events: list[Event]) -> set[str]:
    ips: set[str] = set()
    if finding.session_key.startswith("zeek:"):
        for event in session_events:
            if event.dest_ip and ip_scope(event.dest_ip) != "private":
                ips.add(event.dest_ip)
        if ips:
            return ips
    if finding.src_ip:
        ips.add(finding.src_ip)
    return ips


def _session_key(event: Event) -> str:
    if event.session:
        return f"{event.source}:{event.session}"
    if event.src_ip:
        return f"{event.source}:src:{event.src_ip}"
    if event.dest_ip:
        return f"{event.source}:dest:{event.dest_ip}"
    return f"{event.source}:line:{event.line_number or 'unknown'}"


def _apply_event(actors: OrderedDict[str, ActorProfile], ip: str, event: Event, role: str) -> None:
    actor = actors.setdefault(ip, ActorProfile(ip=ip, ip_scope=ip_scope(ip)))
    actor.total_events += 1
    actor.sources.add(event.source)
    actor.event_types.add(event.event_type)
    actor.techniques.update(map_event(event))
    _update_time_window(actor, event.timestamp)

    if role == "source":
        actor.source_events += 1
    else:
        actor.destination_events += 1

    if event.session:
        actor.sessions.add(f"{event.source}:{event.session}")
    if event.url:
        actor.urls.add(event.url)
    if event.username:
        actor.usernames.add(event.username)
    for value in event.hashes.values():
        actor.hashes.add(value)


def _has_behavioral_evidence(finding: RiskFinding) -> bool:
    if finding.mitre_techniques:
        return True
    return any(reason != "session feature outlier versus local baseline" for reason in finding.reasons)


def _update_time_window(actor: ActorProfile, timestamp: datetime | None) -> None:
    if timestamp is None:
        return
    if actor.first_seen is None or timestamp < actor.first_seen:
        actor.first_seen = timestamp
    if actor.last_seen is None or timestamp > actor.last_seen:
        actor.last_seen = timestamp
