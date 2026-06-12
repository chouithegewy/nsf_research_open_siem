from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from honeypot_ai.correlation import correlate_actors
from honeypot_ai.detectors import score_sessions
from honeypot_ai.features import aggregate_sessions
from honeypot_ai.ioc import extract_iocs
from honeypot_ai.mitre import describe
from honeypot_ai.models import ActorProfile, Event, IOC, RiskFinding, SessionFeatures


@dataclass(frozen=True)
class AnalysisReport:
    events: tuple[Event, ...]
    sessions: tuple[SessionFeatures, ...]
    iocs: tuple[IOC, ...]
    findings: tuple[RiskFinding, ...]
    actors: tuple[ActorProfile, ...]


def analyze_events(events: Iterable[Event]) -> AnalysisReport:
    event_tuple = tuple(events)
    sessions = tuple(aggregate_sessions(event_tuple))
    iocs = tuple(extract_iocs(event_tuple))
    findings = tuple(score_sessions(event_tuple, sessions))
    actors = tuple(correlate_actors(event_tuple, findings))
    return AnalysisReport(events=event_tuple, sessions=sessions, iocs=iocs, findings=findings, actors=actors)


def report_to_markdown(report: AnalysisReport) -> str:
    lines: list[str] = []
    lines.append("# Honeypot Analysis Report")
    lines.append("")
    lines.append(f"- Events parsed: {len(report.events)}")
    lines.append(f"- Sessions observed: {len(report.sessions)}")
    lines.append(f"- Actors correlated: {len(report.actors)}")
    lines.append(f"- IOCs extracted: {len(report.iocs)}")
    lines.append(f"- Findings: {len(report.findings)}")
    lines.append("")

    if report.findings:
        lines.append("## Findings")
        lines.append("")
        for finding in report.findings:
            techniques = ", ".join(f"{technique} ({describe(technique)})" for technique in finding.mitre_techniques) or "none"
            lines.append(f"### {finding.severity.upper()} {finding.session_key}")
            lines.append("")
            lines.append(f"- Score: {finding.score}")
            lines.append(f"- Source IP: {finding.src_ip or 'unknown'}")
            lines.append(f"- Robust anomaly score: {finding.anomaly_score}")
            lines.append(f"- MITRE ATT&CK: {techniques}")
            for reason in finding.reasons:
                lines.append(f"- Reason: {reason}")
            lines.append("")

    if report.actors:
        lines.append("## Actor Correlation")
        lines.append("")
        lines.append("| IP | Scope | Sources | Events | Sessions | Finding Score | Techniques |")
        lines.append("| --- | --- | --- | ---: | ---: | ---: | --- |")
        for actor in report.actors:
            sources = ", ".join(sorted(actor.sources)) or "none"
            techniques = ", ".join(sorted(actor.techniques)) or "none"
            lines.append(
                f"| `{actor.ip}` | {actor.ip_scope} | {sources} | {actor.total_events} | "
                f"{len(actor.sessions)} | {round(actor.finding_score, 2)} | {techniques} |"
            )
        lines.append("")

    if report.iocs:
        lines.append("## IOCs")
        lines.append("")
        lines.append("| Kind | Value | Source | Context |")
        lines.append("| --- | --- | --- | --- |")
        for ioc in report.iocs:
            lines.append(f"| {ioc.kind} | `{ioc.value}` | {ioc.source} | {ioc.context} |")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def report_to_json(report: AnalysisReport) -> str:
    return json.dumps(report_to_dict(report), indent=2, sort_keys=True)


def report_to_dict(report: AnalysisReport) -> dict[str, object]:
    payload = _to_jsonable(report)
    if not isinstance(payload, dict):
        raise TypeError("analysis report did not serialize to a mapping")
    return payload


def _to_jsonable(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, tuple):
        return [_to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_to_jsonable(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    return value
