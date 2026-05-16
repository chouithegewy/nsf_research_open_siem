from __future__ import annotations

from collections import defaultdict
from statistics import median
from typing import Iterable

from honeypot_ai.features import numeric_vector
from honeypot_ai.mitre import map_event
from honeypot_ai.models import Event, RiskFinding, SessionFeatures


def score_sessions(events: Iterable[Event], sessions: Iterable[SessionFeatures]) -> list[RiskFinding]:
    event_list = list(events)
    session_list = list(sessions)
    events_by_session = _events_by_session(event_list)
    anomaly_scores = _robust_anomaly_scores(session_list)
    findings: list[RiskFinding] = []

    for session in session_list:
        base_score, reasons = _heuristic_score(session)
        anomaly_score = anomaly_scores.get(session.key, 0.0)
        techniques = _session_techniques(events_by_session.get(session.key, ()))
        anomaly_reasons: list[str] = []
        anomaly_boost = 0.0
        if anomaly_score >= 3.0 and (base_score > 0 or techniques or anomaly_score >= 20.0):
            anomaly_boost = min(anomaly_score * 1.5, 20.0)
            anomaly_reasons.append("session feature outlier versus local baseline")
        score = base_score + anomaly_boost
        if score <= 0 and not techniques:
            continue
        findings.append(
            RiskFinding(
                session_key=session.key,
                src_ip=session.src_ip,
                score=round(score, 2),
                severity=_severity(score),
                reasons=tuple(reasons + anomaly_reasons),
                mitre_techniques=techniques,
                anomaly_score=round(anomaly_score, 2),
            )
        )

    return sorted(findings, key=lambda finding: finding.score, reverse=True)


def _heuristic_score(session: SessionFeatures) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    if session.login_failures:
        add = min(session.login_failures * 0.75, 12.0)
        score += add
        reasons.append(f"{session.login_failures} failed login attempt(s)")
    if session.login_successes:
        score += 8.0
        reasons.append(f"{session.login_successes} successful honeypot login(s)")
    if session.commands:
        score += min(session.commands * 1.5, 12.0)
        reasons.append(f"{session.commands} command(s) after access")
    if session.download_commands:
        score += session.download_commands * 12.0
        reasons.append(f"{session.download_commands} tool or payload download command(s)")
    if session.reverse_shells:
        score += session.reverse_shells * 20.0
        reasons.append(f"{session.reverse_shells} reverse-shell pattern(s)")
    if session.persistence_attempts:
        score += session.persistence_attempts * 16.0
        reasons.append(f"{session.persistence_attempts} persistence attempt(s)")
    if session.scanner_commands:
        score += session.scanner_commands * 8.0
        reasons.append(f"{session.scanner_commands} scanning or brute-force tool command(s)")
    if session.suricata_alerts:
        score += session.suricata_alerts * 10.0
        reasons.append(f"{session.suricata_alerts} Suricata alert(s)")
    if session.hashes:
        score += min(len(session.hashes) * 6.0, 18.0)
        reasons.append(f"{len(session.hashes)} file hash indicator(s)")
    if session.urls:
        score += min(len(session.urls) * 6.0, 18.0)
        reasons.append(f"{len(session.urls)} URL indicator(s)")
    if len(session.passwords) >= 5:
        score += 6.0
        reasons.append(f"{len(session.passwords)} distinct attempted password(s)")
    if session.bytes_out > 5_000_000 or session.bytes_in > 5_000_000:
        score += 10.0
        reasons.append("large network transfer volume")

    return score, reasons


def _robust_anomaly_scores(sessions: list[SessionFeatures]) -> dict[str, float]:
    if len(sessions) < 3:
        return {session.key: 0.0 for session in sessions}

    vectors = [numeric_vector(session) for session in sessions]
    columns = list(zip(*vectors))
    medians = [median(column) for column in columns]
    mads = [_mad(column, med) for column, med in zip(columns, medians)]
    scores: dict[str, float] = {}

    for session, vector in zip(sessions, vectors):
        total = 0.0
        for value, med, mad in zip(vector, medians, mads):
            if mad == 0:
                if value > med:
                    total += min(value - med, 10.0)
                continue
            robust_z = 0.6745 * (value - med) / mad
            if robust_z > 0:
                total += min(robust_z, 10.0)
        scores[session.key] = total
    return scores


def _mad(values: Iterable[float], med: float) -> float:
    deviations = [abs(value - med) for value in values]
    return median(deviations)


def _events_by_session(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        key = _session_key(event)
        grouped[key].append(event)
    return grouped


def _session_key(event: Event) -> str:
    if event.session:
        return f"{event.source}:{event.session}"
    if event.src_ip:
        return f"{event.source}:src:{event.src_ip}"
    if event.dest_ip:
        return f"{event.source}:dest:{event.dest_ip}"
    return f"{event.source}:line:{event.line_number or 'unknown'}"


def _session_techniques(events: Iterable[Event]) -> tuple[str, ...]:
    ordered: dict[str, None] = {}
    for event in events:
        for technique in map_event(event):
            ordered.setdefault(technique, None)
    return tuple(ordered)


def _severity(score: float) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    return "low"
