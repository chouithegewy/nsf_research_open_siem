from __future__ import annotations

import ipaddress
import re
from collections import OrderedDict
from typing import Iterable
from urllib.parse import urlparse

from honeypot_ai.models import Event, IOC


URL_RE = re.compile(r"https?://[^\s'\"<>`]+", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?P<hash>[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_iocs(events: Iterable[Event]) -> list[IOC]:
    seen: OrderedDict[tuple[str, str, str], IOC] = OrderedDict()
    for event in events:
        for ioc in _event_iocs(event):
            key = (ioc.kind, ioc.value, ioc.context)
            seen.setdefault(key, ioc)
    return list(seen.values())


def _event_iocs(event: Event) -> list[IOC]:
    iocs: list[IOC] = []
    context = _context(event)
    structured_ips = {value for value in (event.src_ip, event.dest_ip) if value}

    for role, value in (("src_ip", event.src_ip), ("dest_ip", event.dest_ip)):
        if value and _valid_ip(value):
            iocs.append(IOC(kind=role, value=value, source=event.source, context=context))

    if event.url:
        iocs.extend(_url_iocs(event.url, event.source, context))
    if event.domain:
        iocs.append(IOC(kind="domain", value=_normalize_domain(event.domain), source=event.source, context=context))

    for hash_name, value in event.hashes.items():
        if _valid_hash(value):
            iocs.append(IOC(kind=hash_name, value=value.lower(), source=event.source, context=context))

    for text in (event.command, _raw_text(event)):
        if not text:
            continue
        for url in URL_RE.findall(text):
            iocs.extend(_url_iocs(_strip_trailing_punctuation(url), event.source, context))
        for ip in IP_RE.findall(text):
            if ip not in structured_ips and _valid_ip(ip):
                iocs.append(IOC(kind="ip", value=ip, source=event.source, context=context))
        for match in HASH_RE.finditer(text):
            digest = match.group("hash").lower()
            iocs.append(IOC(kind=_hash_kind(digest), value=digest, source=event.source, context=context))

    return iocs


def _url_iocs(url: str, source: str, context: str) -> list[IOC]:
    clean_url = _strip_trailing_punctuation(url)
    iocs = [IOC(kind="url", value=clean_url, source=source, context=context)]
    parsed = urlparse(clean_url)
    host = parsed.hostname
    if host:
        if _valid_ip(host):
            iocs.append(IOC(kind="ip", value=host, source=source, context=context))
        else:
            iocs.append(IOC(kind="domain", value=host.lower(), source=source, context=context))
    return iocs


def _context(event: Event) -> str:
    if event.session:
        return f"session:{event.session}"
    if event.src_ip:
        return f"src:{event.src_ip}"
    if event.line_number:
        return f"line:{event.line_number}"
    return event.event_type


def _raw_text(event: Event) -> str:
    return " ".join(str(value) for value in event.raw.values() if isinstance(value, (str, int, float)))


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _valid_hash(value: str) -> bool:
    return bool(HASH_RE.fullmatch(value))


def _hash_kind(value: str) -> str:
    if len(value) == 32:
        return "md5"
    if len(value) == 40:
        return "sha1"
    return "sha256"


def _strip_trailing_punctuation(value: str) -> str:
    return value.rstrip(".,);]")


def _normalize_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()
