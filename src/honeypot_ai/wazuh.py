from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from honeypot_ai.ml import MLAlert, alert_to_record
from honeypot_ai.report import AnalysisReport, report_to_dict


COLLECTION_KINDS = {
    "events": "event",
    "findings": "finding",
    "actors": "actor",
    "iocs": "ioc",
    "sessions": "session",
}


def report_to_wazuh_events(report: AnalysisReport) -> list[dict[str, object]]:
    payload = report_to_dict(report)
    events: list[dict[str, object]] = []
    for collection, kind in COLLECTION_KINDS.items():
        rows = payload.get(collection, [])
        if not isinstance(rows, list):
            continue
        for row in rows:
            if isinstance(row, Mapping):
                events.append(_wazuh_event(kind, row))
    return events


def report_to_wazuh_ndjson(report: AnalysisReport) -> str:
    return _events_to_ndjson(report_to_wazuh_events(report))


def ml_alerts_to_wazuh_events(alerts: Iterable[MLAlert]) -> list[dict[str, object]]:
    return [_wazuh_event("ml_alert", alert_to_record(alert)) for alert in alerts]


def ml_alerts_to_wazuh_ndjson(alerts: Iterable[MLAlert]) -> str:
    return _events_to_ndjson(ml_alerts_to_wazuh_events(alerts))


def _wazuh_event(kind: str, row: Mapping[str, Any]) -> dict[str, object]:
    effective_kind = _effective_kind(kind, row)
    event: dict[str, object] = {
        "schema_version": 1,
        "integration": "honeypot-ai",
        "kind": effective_kind,
        "rule_name": _rule_name(effective_kind, row),
    }
    timestamp = _timestamp(row)
    if timestamp:
        event["timestamp"] = timestamp
    event.update(_extra_fields(effective_kind, row))
    for key, value in row.items():
        normalized_key = _field_name(effective_kind, str(key))
        event[normalized_key] = _flat_value(_normalized_value(effective_kind, str(key), value))
    _copy_aliases(event)
    return event


def _events_to_ndjson(events: Iterable[Mapping[str, object]]) -> str:
    return "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n"


def _rule_name(kind: str, row: Mapping[str, Any]) -> str:
    if kind in {"finding", "ml_alert"}:
        severity = str(row.get("severity") or "unknown").lower()
        return f"honeypot_ai_{kind}_{severity}"
    if kind == "ebpf_event":
        event_type = str(row.get("event_type") or "event").lower().removeprefix("ebpf.")
        return f"honeypot_ai_ebpf_{event_type}"
    return f"honeypot_ai_{kind}"


def _effective_kind(kind: str, row: Mapping[str, Any]) -> str:
    if kind == "event" and str(row.get("source") or "").lower() == "ebpf":
        return "ebpf_event"
    return kind


def _timestamp(row: Mapping[str, Any]) -> str | None:
    for key in ("timestamp", "created_at", "window_start", "first_seen"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _field_name(kind: str, key: str) -> str:
    if kind == "ioc" and key == "kind":
        return "ioc_kind"
    if kind == "ioc" and key == "value":
        return "ioc_value"
    if kind == "event" and key == "source":
        return "event_source"
    if kind == "ebpf_event" and key == "source":
        return "event_source"
    return key


def _normalized_value(kind: str, key: str, value: Any) -> Any:
    if kind == "ebpf_event" and key == "event_type" and isinstance(value, str):
        return value.removeprefix("ebpf.")
    return value


def _copy_aliases(event: dict[str, object]) -> None:
    if "ioc_value" in event and "indicator" not in event:
        event["indicator"] = event["ioc_value"]
    if "ip" in event and "src_ip" not in event:
        event["src_ip"] = event["ip"]
    if "endpoint" in event and "host_endpoint" not in event:
        event["host_endpoint"] = event["endpoint"]


def _extra_fields(kind: str, row: Mapping[str, Any]) -> dict[str, object]:
    if kind != "ebpf_event":
        return {}
    raw = row.get("raw")
    if not isinstance(raw, Mapping):
        return {}
    fields: dict[str, object] = {}
    for key in ("severity_hint", "access_type", "binary", "uid", "gid", "pid", "comm"):
        value = raw.get(key)
        if value is not None:
            fields[key] = _flat_value(value)
    return fields


def _flat_value(value: Any) -> object:
    if value is None:
        return ""
    if isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list | tuple | set):
        return "; ".join(_flat_part(item) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _flat_part(value: Any) -> str:
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True)
    return str(value)
