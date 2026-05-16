from __future__ import annotations

import json
from collections import OrderedDict
from urllib.parse import urlparse

from honeypot_ai.correlation import ip_scope
from honeypot_ai.models import IOC
from honeypot_ai.report import AnalysisReport


MISP_TYPES = {
    "src_ip": "ip-src",
    "dest_ip": "ip-dst",
    "ip": "ip-dst",
    "domain": "domain",
    "url": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}


def report_to_misp_attributes(report: AnalysisReport) -> str:
    attributes = [_ioc_to_misp(ioc) for ioc in report.iocs if ioc.kind in MISP_TYPES]
    deduped: OrderedDict[tuple[str, str], dict[str, object]] = OrderedDict()
    for attribute in attributes:
        key = (str(attribute["type"]), str(attribute["value"]))
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = attribute
            continue
        existing["comment"] = _merge_comments(str(existing["comment"]), str(attribute["comment"]))
    return json.dumps({"Attribute": list(deduped.values())}, indent=2, sort_keys=True)


def _ioc_to_misp(ioc: IOC) -> dict[str, object]:
    misp_type = MISP_TYPES[ioc.kind]
    return {
        "category": _misp_category(misp_type),
        "type": misp_type,
        "value": ioc.value,
        "to_ids": _to_ids(misp_type, ioc.value),
        "comment": f"{ioc.source} {ioc.context}",
    }


def _misp_category(misp_type: str) -> str:
    if misp_type in {"md5", "sha1", "sha256"}:
        return "Payload delivery"
    return "Network activity"


def _merge_comments(left: str, right: str) -> str:
    parts = []
    seen = set()
    for comment in (left, right):
        for part in comment.split("; "):
            if part not in seen:
                seen.add(part)
                parts.append(part)
    return "; ".join(parts)


def _to_ids(misp_type: str, value: str) -> bool:
    if misp_type in {"ip-src", "ip-dst"}:
        return ip_scope(value) == "global"
    if misp_type == "domain":
        return not _is_reserved_domain(value)
    if misp_type == "url":
        host = urlparse(value).hostname or ""
        if not host:
            return False
        if _looks_like_ip(host):
            return ip_scope(host) == "global"
        return not _is_reserved_domain(host)
    return True


def _is_reserved_domain(value: str) -> bool:
    normalized = value.strip().rstrip(".").lower()
    if normalized in {"example.com", "example.net", "example.org", "localhost"}:
        return True
    return normalized.endswith((".example", ".test", ".invalid", ".localhost"))


def _looks_like_ip(value: str) -> bool:
    return ":" in value or value.replace(".", "").isdigit()
