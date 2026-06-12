from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Iterable

from honeypot_ai.report import AnalysisReport, report_to_dict


def report_to_splunk_hec_events(
    report: AnalysisReport,
    *,
    index: str | None = None,
    source: str = "honeypot-ai",
    sourcetype: str = "honeypot:analysis",
    host: str = "honeypot-ai",
) -> list[dict[str, Any]]:
    payload = report_to_dict(report)
    envelopes: list[dict[str, Any]] = []
    for collection in ("events", "findings", "actors", "iocs", "sessions"):
        for item in payload.get(collection, []):
            if not isinstance(item, dict):
                continue
            event = {"kind": collection[:-1], **item}
            envelope: dict[str, Any] = {
                "event": event,
                "host": item.get("src_ip") or item.get("ip") or host,
                "source": source,
                "sourcetype": f"{sourcetype}:{collection[:-1]}",
            }
            if index:
                envelope["index"] = index
            event_time = _event_time(item)
            if event_time is not None:
                envelope["time"] = event_time
            envelopes.append(envelope)
    return envelopes


def report_to_splunk_ndjson(report: AnalysisReport, **kwargs: Any) -> str:
    return "\n".join(json.dumps(event, sort_keys=True) for event in report_to_splunk_hec_events(report, **kwargs)) + "\n"


def send_to_splunk_hec(
    url: str,
    token: str,
    events: Iterable[dict[str, Any]],
    *,
    timeout_seconds: float = 10.0,
) -> int:
    endpoint = _hec_endpoint(url)
    sent = 0
    for event in events:
        request = urllib.request.Request(
            endpoint,
            data=json.dumps(event).encode("utf-8"),
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Splunk HEC request failed with HTTP {exc.code}: {body}") from exc
        sent += 1
    return sent


def _hec_endpoint(url: str) -> str:
    value = url.rstrip("/")
    if value.endswith("/services/collector/event"):
        return value
    return f"{value}/services/collector/event"


def _event_time(item: dict[str, Any]) -> float | None:
    value = item.get("timestamp") or item.get("first_seen")
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
