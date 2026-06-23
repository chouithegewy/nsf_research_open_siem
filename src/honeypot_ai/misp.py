from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse
import urllib.error
import urllib.request

from honeypot_ai.exports import report_to_misp_attributes
from honeypot_ai.report import AnalysisReport


DEFAULT_MISP_TYPES = ("ip-src", "ip-dst", "domain", "url", "md5", "sha1", "sha256")
CDB_LISTS = {
    "misp-ip": {"ip-src", "ip-dst"},
    "misp-domain": {"domain"},
    "misp-url": {"url"},
    "misp-hash": {"md5", "sha1", "sha256"},
}


def build_misp_event_payload(
    report: AnalysisReport,
    *,
    info: str,
    distribution: str = "0",
    threat_level_id: str = "2",
    analysis: str = "0",
    published: bool = False,
    tags: Iterable[str] = (),
) -> dict[str, object]:
    attribute_payload = json.loads(report_to_misp_attributes(report))
    attributes = attribute_payload.get("Attribute", [])
    if not isinstance(attributes, list):
        attributes = []
    event: dict[str, object] = {
        "info": info,
        "distribution": str(distribution),
        "threat_level_id": str(threat_level_id),
        "analysis": str(analysis),
        "published": bool(published),
        "Attribute": attributes,
    }
    tag_rows = [{"name": tag} for tag in tags if tag]
    if tag_rows:
        event["Tag"] = tag_rows
    return {"Event": event}


def push_misp_event(
    base_url: str,
    api_key: str,
    payload: Mapping[str, object],
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, object]:
    response = _misp_request(base_url, "/events/add", api_key, payload, timeout_seconds=timeout_seconds)
    if isinstance(response, Mapping):
        return dict(response)
    return {"response": response}


def pull_misp_attributes(
    base_url: str,
    api_key: str,
    *,
    types: Iterable[str] = DEFAULT_MISP_TYPES,
    to_ids_only: bool = True,
    timeout_seconds: float = 30.0,
) -> list[dict[str, object]]:
    payload: dict[str, object] = {
        "returnFormat": "json",
        "type": list(types),
        "includeContext": True,
    }
    if to_ids_only:
        payload["to_ids"] = True
    response = _misp_request(base_url, "/attributes/restSearch", api_key, payload, timeout_seconds=timeout_seconds)
    return _extract_attributes(response)


def misp_attributes_to_wazuh_cdb(
    attributes: Iterable[Mapping[str, object]],
    *,
    include_non_ids: bool = False,
) -> dict[str, list[str]]:
    lists: dict[str, list[str]] = {name: [] for name in CDB_LISTS}
    seen: dict[str, set[str]] = {name: set() for name in CDB_LISTS}
    for attribute in attributes:
        if not include_non_ids and not bool(attribute.get("to_ids", True)):
            continue
        attr_type = str(attribute.get("type") or "")
        value = str(attribute.get("value") or "").strip()
        list_name = _list_name(attr_type)
        key = _cdb_key(attr_type, value)
        if list_name is None or key is None or key in seen[list_name]:
            continue
        seen[list_name].add(key)
        lists[list_name].append(f"{key}:misp:{attr_type}:{_attribute_reference(attribute)}")
    for values in lists.values():
        values.sort()
    return lists


def write_wazuh_cdb_lists(
    attributes: Iterable[Mapping[str, object]],
    output_dir: str | Path,
    *,
    include_non_ids: bool = False,
) -> dict[str, int]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    lists = misp_attributes_to_wazuh_cdb(attributes, include_non_ids=include_non_ids)
    counts: dict[str, int] = {}
    for name, rows in lists.items():
        (output / name).write_text("".join(f"{row}\n" for row in rows), encoding="utf-8")
        counts[name] = len(rows)
    return counts


def _misp_request(
    base_url: str,
    path: str,
    api_key: str,
    payload: Mapping[str, object],
    *,
    timeout_seconds: float,
) -> object:
    endpoint = f"{base_url.rstrip('/')}{path}"
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"MISP request failed with HTTP {exc.code}: {body}") from exc
    if not body.strip():
        return {}
    return json.loads(body)


def _extract_attributes(response: object) -> list[dict[str, object]]:
    if isinstance(response, list):
        return [dict(item) for item in response if isinstance(item, Mapping)]
    if not isinstance(response, Mapping):
        return []
    candidates = response.get("Attribute")
    if candidates is None and isinstance(response.get("response"), Mapping):
        candidates = response["response"].get("Attribute")  # type: ignore[index]
    if candidates is None and isinstance(response.get("response"), list):
        candidates = response.get("response")
    if candidates is None:
        return []
    rows: list[dict[str, object]] = []
    for item in candidates:
        if not isinstance(item, Mapping):
            continue
        if isinstance(item.get("Attribute"), Mapping):
            rows.append(dict(item["Attribute"]))  # type: ignore[arg-type,index]
        else:
            rows.append(dict(item))
    return rows


def _list_name(attr_type: str) -> str | None:
    for name, types in CDB_LISTS.items():
        if attr_type in types:
            return name
    return None


def _cdb_key(attr_type: str, value: str) -> str | None:
    if not value or "\n" in value or "\r" in value:
        return None
    if attr_type == "url":
        parsed = urlparse(value)
        if parsed.scheme or ":" in value:
            return None
    if ":" in value and attr_type not in {"md5", "sha1", "sha256"}:
        return None
    return value


def _attribute_reference(attribute: Mapping[str, object]) -> str:
    for key in ("uuid", "id", "event_id"):
        value = str(attribute.get(key) or "").strip()
        if value and "\n" not in value and "\r" not in value:
            return value.replace(":", "_")
    return "attribute"
