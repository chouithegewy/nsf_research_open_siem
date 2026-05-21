from __future__ import annotations

import bz2
import gzip
import json
import lzma
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, TextIO

from honeypot_ai.models import Event


HASH_FIELD_ALIASES = {
    "md5": ("md5", "md5_hash", "hash.md5", "file.hash.md5", "fileinfo.md5"),
    "sha1": ("sha1", "sha1_hash", "hash.sha1", "file.hash.sha1", "fileinfo.sha1"),
    "sha256": ("sha256", "sha256_hash", "hash.sha256", "file.hash.sha256", "fileinfo.sha256"),
}

TPOT_HONEYPOT_TYPES = {
    "adbhoney",
    "beelzebub",
    "ciscoasa",
    "citrixhoneypot",
    "conpot",
    "cowrie",
    "ddospot",
    "dicompot",
    "dionaea",
    "elasticpot",
    "endlessh",
    "galah",
    "glutton",
    "go-pot",
    "h0neytr4p",
    "hellpot",
    "heralding",
    "honeyaml",
    "honeypots",
    "honeytrap",
    "ipphoney",
    "log4pot",
    "mailoney",
    "medpot",
    "miniprint",
    "redishoneypot",
    "sentrypeer",
    "snare",
    "tanner",
    "wordpot",
}

TPOT_NSM_TYPES = {
    "fatt",
    "p0f",
    "suricata",
}

TPOT_TOOL_TYPES = {
    "attackmap",
    "autoheal",
    "cyberchef",
    "elasticsearch",
    "elasticvue",
    "ewsposter",
    "geoip-attack-map",
    "kibana",
    "logstash",
    "map_redis",
    "map_web",
    "nginx",
    "spiderfoot",
    "tpotinit",
}

TPOT_TYPES = TPOT_HONEYPOT_TYPES | TPOT_NSM_TYPES | TPOT_TOOL_TYPES

TPOT_TYPE_ALIASES = {
    "go pot": "go-pot",
    "go_pot": "go-pot",
    "honey pots": "honeypots",
    "honey-pots": "honeypots",
    "qhoneypots": "honeypots",
    "q-honeypots": "honeypots",
    "qhoney pots": "honeypots",
    "qhoney-pots": "honeypots",
    "redis-honeypot": "redishoneypot",
    "geoip attack map": "geoip-attack-map",
    "geoip_attack_map": "geoip-attack-map",
    "snare-tanner": "snare",
    "t-pot-attack-map": "attackmap",
    "tpot-attack-map": "attackmap",
}

TPOT_TYPES = TPOT_TYPES | set(TPOT_TYPE_ALIASES.values())
TPOT_MANAGED_TYPES = TPOT_TYPES | set(TPOT_TYPE_ALIASES)
COMPRESSED_SUFFIXES = {".gz", ".bz2", ".xz"}
ARCHIVE_SUFFIXES = COMPRESSED_SUFFIXES | {".zip"}


def parse_file(path: str | Path, source_hint: str | None = None) -> list[Event]:
    file_path = Path(path)
    with _open_text(file_path) as handle:
        return list(parse_ndjson(handle, source_hint=source_hint))


def parse_paths(paths: Iterable[str | Path], source_hint: str | None = None) -> list[Event]:
    events: list[Event] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            for file_path in sorted(path.rglob("*")):
                if file_path.is_file() and _looks_like_log(file_path, source_hint=source_hint):
                    events.extend(parse_file(file_path, source_hint=source_hint))
        else:
            events.extend(parse_file(path, source_hint=source_hint))
    return events


def parse_ndjson(lines: Iterable[str], source_hint: str | None = None) -> Iterator[Event]:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON on line {line_number}: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"line {line_number} must contain a JSON object")
        yield parse_record(payload, source_hint=source_hint, line_number=line_number)


def parse_record(
    record: Mapping[str, Any],
    source_hint: str | None = None,
    line_number: int | None = None,
) -> Event:
    source = source_hint or detect_source(record)
    if source == "cowrie":
        return _parse_cowrie(record, line_number)
    if source == "dionaea":
        return _parse_dionaea(record, line_number)
    if source == "suricata":
        return _parse_suricata(record, line_number)
    if source == "zeek":
        return _parse_zeek(record, line_number)
    if source == "tpot":
        return _parse_tpot(record, line_number)
    return _parse_generic(record, line_number)


def detect_source(record: Mapping[str, Any]) -> str:
    eventid = str(record.get("eventid", ""))
    if eventid.startswith("cowrie."):
        return "cowrie"
    origin = str(record.get("origin", ""))
    if origin.startswith("dionaea."):
        return "dionaea"
    if "connection" in record and _nested(record, "connection", "remote", "address"):
        return "dionaea"
    if "event_type" in record and ("src_ip" in record or "dest_ip" in record):
        return "suricata"
    if "uid" in record and "id.orig_h" in record and "id.resp_h" in record:
        return "zeek"
    if _is_tpot_record(record):
        return "tpot"
    return "generic"


def _parse_cowrie(record: Mapping[str, Any], line_number: int | None) -> Event:
    event_type = _as_str(record.get("eventid")) or "cowrie.unknown"
    return Event(
        source="cowrie",
        event_type=event_type,
        timestamp=_parse_timestamp(_first_value(record, ("timestamp", "@timestamp", "ts"))),
        src_ip=_as_str(record.get("src_ip")),
        src_port=_as_int(record.get("src_port")),
        dest_ip=_first_string(record, ("dst_ip", "dest_ip")),
        dest_port=_as_int(_first_value(record, ("dst_port", "dest_port"))),
        protocol=_as_str(record.get("protocol")),
        session=_as_str(record.get("session")),
        username=_as_str(record.get("username")),
        password=_as_str(record.get("password")),
        command=_first_string(record, ("input", "command", "cmd")),
        url=_first_string(record, ("url", "download_url", "http.url")),
        filename=_as_str(record.get("filename")),
        hashes=_extract_hashes(record),
        raw=record,
        line_number=line_number,
    )


def _parse_dionaea(record: Mapping[str, Any], line_number: int | None) -> Event:
    origin = _as_str(record.get("origin"))
    timestamp = _parse_timestamp(_first_value(record, ("timestamp", "@timestamp", "ts")))
    connection = record.get("connection")

    if isinstance(connection, Mapping):
        remote = connection.get("remote") if isinstance(connection.get("remote"), Mapping) else {}
        local = connection.get("local") if isinstance(connection.get("local"), Mapping) else {}
        event_type = origin or f"dionaea.connection.{_as_str(connection.get('type')) or 'event'}"
        return Event(
            source="dionaea",
            event_type=event_type,
            timestamp=timestamp,
            src_ip=_as_str(remote.get("address")),
            src_port=_as_int(remote.get("port")),
            dest_ip=_as_str(local.get("address")),
            dest_port=_as_int(local.get("port")),
            protocol=_as_str(connection.get("protocol") or connection.get("transport")),
            username=_first_string(record, ("username", "credentials.username")),
            password=_first_string(record, ("password", "credentials.password")),
            url=_first_string(record, ("url", "download_url")),
            filename=_first_string(record, ("filename", "path")),
            hashes=_extract_hashes(record),
            raw=record,
            line_number=line_number,
        )

    data = record.get("data") if isinstance(record.get("data"), Mapping) else {}
    data_connection = data.get("connection") if isinstance(data.get("connection"), Mapping) else {}
    return Event(
        source="dionaea",
        event_type=origin or "dionaea.incident",
        timestamp=timestamp,
        src_ip=_as_str(data_connection.get("remote_ip")),
        src_port=_as_int(data_connection.get("remote_port")),
        dest_ip=_as_str(data_connection.get("local_ip")),
        dest_port=_as_int(data_connection.get("local_port")),
        protocol=_as_str(data_connection.get("protocol") or data_connection.get("transport")),
        username=_first_string(record, ("username", "credentials.username", "data.credentials.username")),
        password=_first_string(record, ("password", "credentials.password", "data.credentials.password")),
        url=_first_string(data, ("url", "download_url")),
        filename=_first_string(data, ("filename", "path")),
        hashes=_extract_hashes(data),
        raw=record,
        line_number=line_number,
    )


def _parse_suricata(record: Mapping[str, Any], line_number: int | None) -> Event:
    http = record.get("http") if isinstance(record.get("http"), Mapping) else {}
    dns = record.get("dns") if isinstance(record.get("dns"), Mapping) else {}
    fileinfo = record.get("fileinfo") if isinstance(record.get("fileinfo"), Mapping) else {}
    url = _http_url(http) or _first_string(record, ("url", "http.url"))
    return Event(
        source="suricata",
        event_type=_as_str(record.get("event_type")) or "suricata.event",
        timestamp=_parse_timestamp(_first_value(record, ("timestamp", "@timestamp", "ts"))),
        src_ip=_as_str(record.get("src_ip")),
        src_port=_as_int(record.get("src_port")),
        dest_ip=_as_str(record.get("dest_ip")),
        dest_port=_as_int(record.get("dest_port")),
        protocol=_as_str(record.get("proto") or record.get("app_proto")),
        url=url,
        domain=(
            _first_string(http, ("hostname", "http_hostname"))
            or _first_string(record, ("http.hostname", "http_hostname"))
            or _first_string(dns, ("rrname", "query"))
        ),
        filename=_as_str(fileinfo.get("filename")),
        hashes=_extract_hashes(record) | _extract_hashes(fileinfo),
        raw=record,
        line_number=line_number,
    )


def _parse_tpot(record: Mapping[str, Any], line_number: int | None) -> Event:
    tpot_type = _tpot_type(record) or ""
    eventid = str(record.get("eventid", ""))
    origin = str(record.get("origin", ""))

    if tpot_type == "cowrie" or eventid.startswith("cowrie."):
        return _parse_cowrie(record, line_number)
    if tpot_type == "dionaea" or origin.startswith("dionaea.") or (
        "connection" in record and _nested(record, "connection", "remote", "address")
    ):
        return _parse_dionaea(record, line_number)
    if tpot_type == "suricata" or ("event_type" in record and ("src_ip" in record or "dest_ip" in record)):
        return _parse_suricata(record, line_number)
    if "uid" in record and "id.orig_h" in record and "id.resp_h" in record:
        return _parse_zeek(record, line_number)
    return _parse_tpot_generic(record, line_number)


def _parse_tpot_generic(record: Mapping[str, Any], line_number: int | None) -> Event:
    source = _source_name_from_tpot_type(_tpot_type(record)) or "tpot"
    event_type = _first_string(
        record,
        ("event_type", "event.action", "event.dataset", "eventid", "origin", "reason", "message"),
    )
    if not event_type:
        event_type = f"{source}.event" if source != "tpot" else "tpot.event"
    return Event(
        source=source,
        event_type=event_type,
        timestamp=_parse_timestamp(
            _first_value(record, ("timestamp", "@timestamp", "ts", "time", "event_timestamp", "event.created", "date"))
        ),
        src_ip=_first_string(
            record,
            (
                "src_ip",
                "source.ip",
                "source.address",
                "source_ip",
                "srcip",
                "remote_ip",
                "remote.address",
                "remote.addr",
                "remote_host",
                "client_ip",
                "client.ip",
                "client.address",
                "peer.ip",
                "id.orig_h",
                "sip",
                "REMOTE_ADDR",
            ),
        ),
        src_port=_as_int(
            _first_value(
                record,
                (
                    "src_port",
                    "source.port",
                    "source_port",
                    "srcport",
                    "remote_port",
                    "remote.port",
                    "client_port",
                    "client.port",
                    "peer.port",
                    "id.orig_p",
                    "sport",
                ),
            )
        ),
        dest_ip=_first_string(
            record,
            (
                "dest_ip",
                "dst_ip",
                "destination.ip",
                "destination.address",
                "destination_ip",
                "dstip",
                "local_ip",
                "local.address",
                "local.addr",
                "server_ip",
                "server.ip",
                "server.address",
                "id.resp_h",
                "dip",
            ),
        ),
        dest_port=_as_int(
            _first_value(
                record,
                (
                    "dest_port",
                    "dst_port",
                    "destination.port",
                    "destination_port",
                    "dstport",
                    "local_port",
                    "local.port",
                    "server_port",
                    "server.port",
                    "id.resp_p",
                    "dport",
                ),
            )
        ),
        protocol=_first_string(record, ("protocol", "proto", "transport", "app_proto", "network.protocol", "network.transport", "service")),
        session=_first_string(record, ("session", "uid", "flow_id", "session_id", "connection.id", "data.connection.id", "auth_id", "id")),
        username=_first_string(record, ("username", "user", "user.name", "source.user.name", "credentials.username", "login", "account")),
        password=_first_string(record, ("password", "credentials.password", "pass", "secret")),
        command=_first_string(
            record,
            (
                "input",
                "command",
                "cmd",
                "request",
                "request_uri",
                "payload",
                "log.original",
                "message",
                "query",
                "method",
                "url.path",
                "http.request.body.content",
            ),
        ),
        url=_first_string(record, ("url", "url.original", "download_url", "http.url", "http.request.full_uri", "request_uri", "uri")),
        domain=_first_string(
            record,
            (
                "domain",
                "hostname",
                "host",
                "query",
                "rrname",
                "http.hostname",
                "url.domain",
                "dns.question.name",
                "destination.domain",
                "server.domain",
            ),
        ),
        filename=_first_string(record, ("filename", "file.name", "path", "file.path", "fileinfo.filename", "target")),
        hashes=_extract_hashes(record),
        raw=record,
        line_number=line_number,
    )


def _parse_zeek(record: Mapping[str, Any], line_number: int | None) -> Event:
    if "query" in record:
        return _parse_zeek_dns(record, line_number)
    if "host" in record or "uri" in record or "method" in record:
        return _parse_zeek_http(record, line_number)
    return Event(
        source="zeek",
        event_type="zeek.conn",
        timestamp=_parse_timestamp(record.get("ts")),
        src_ip=_as_str(record.get("id.orig_h")),
        src_port=_as_int(record.get("id.orig_p")),
        dest_ip=_as_str(record.get("id.resp_h")),
        dest_port=_as_int(record.get("id.resp_p")),
        protocol=_as_str(record.get("proto") or record.get("service")),
        session=_as_str(record.get("uid")),
        raw=record,
        line_number=line_number,
    )


def _parse_zeek_http(record: Mapping[str, Any], line_number: int | None) -> Event:
    host = _as_str(record.get("host"))
    uri = _as_str(record.get("uri"))
    url = _build_http_url(host, uri)
    return Event(
        source="zeek",
        event_type="zeek.http",
        timestamp=_parse_timestamp(record.get("ts")),
        src_ip=_as_str(record.get("id.orig_h")),
        src_port=_as_int(record.get("id.orig_p")),
        dest_ip=_as_str(record.get("id.resp_h")),
        dest_port=_as_int(record.get("id.resp_p")),
        protocol="http",
        session=_as_str(record.get("uid")),
        url=url,
        domain=host,
        raw=record,
        line_number=line_number,
    )


def _parse_zeek_dns(record: Mapping[str, Any], line_number: int | None) -> Event:
    return Event(
        source="zeek",
        event_type="zeek.dns",
        timestamp=_parse_timestamp(record.get("ts")),
        src_ip=_as_str(record.get("id.orig_h")),
        src_port=_as_int(record.get("id.orig_p")),
        dest_ip=_as_str(record.get("id.resp_h")),
        dest_port=_as_int(record.get("id.resp_p")),
        protocol=_as_str(record.get("proto")) or "dns",
        session=_as_str(record.get("uid")),
        domain=_as_str(record.get("query")),
        raw=record,
        line_number=line_number,
    )


def _parse_generic(record: Mapping[str, Any], line_number: int | None) -> Event:
    return Event(
        source="generic",
        event_type=_first_string(record, ("event_type", "eventid", "type")) or "generic.event",
        timestamp=_parse_timestamp(_first_value(record, ("timestamp", "@timestamp", "ts", "time"))),
        src_ip=_first_string(record, ("src_ip", "source_ip", "remote_ip", "client_ip")),
        src_port=_as_int(_first_value(record, ("src_port", "source_port", "remote_port", "client_port"))),
        dest_ip=_first_string(record, ("dest_ip", "dst_ip", "destination_ip", "local_ip", "server_ip")),
        dest_port=_as_int(_first_value(record, ("dest_port", "dst_port", "destination_port", "local_port", "server_port"))),
        protocol=_first_string(record, ("protocol", "proto", "transport", "app_proto")),
        session=_first_string(record, ("session", "uid", "flow_id")),
        username=_first_string(record, ("username", "credentials.username")),
        password=_first_string(record, ("password", "credentials.password")),
        command=_first_string(record, ("input", "command", "cmd")),
        url=_first_string(record, ("url", "download_url", "http.url")),
        domain=_first_string(record, ("domain", "hostname", "host", "query", "rrname", "http.hostname")),
        filename=_first_string(record, ("filename", "path", "fileinfo.filename")),
        hashes=_extract_hashes(record),
        raw=record,
        line_number=line_number,
    )


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        if len(text) > 5 and text[-5] in "+-" and text[-2:].isdigit() and text[-3] != ":":
            text = f"{text[:-2]}:{text[-2:]}"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                return datetime.fromtimestamp(float(text), tz=timezone.utc)
            except ValueError:
                return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    return None


def _extract_hashes(record: Mapping[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for normalized, keys in HASH_FIELD_ALIASES.items():
        value = _first_string(record, keys)
        if value:
            hashes[normalized] = value.lower()
    for key, value in record.items():
        if isinstance(value, Mapping):
            hashes.update(_extract_hashes(value))
    return hashes


def _http_url(http: Mapping[str, Any]) -> str | None:
    host = _as_str(http.get("hostname"))
    path = _as_str(http.get("url"))
    return _build_http_url(host, path)


def _build_http_url(host: str | None, path: str | None) -> str | None:
    if not path:
        return None
    if path.startswith(("http://", "https://")):
        return path
    if host:
        return f"http://{host}{path if path.startswith('/') else '/' + path}"
    return path


def _looks_like_log(path: Path, source_hint: str | None = None) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in ARCHIVE_SUFFIXES:
        if path.suffix.lower() == ".zip":
            return False
        path = Path(_strip_compression_suffix(name))
        name = path.name.lower()
    if name.endswith(".zip"):
        return False
    if source_hint == "tpot":
        return path.suffix.lower() in {".json", ".jsonl", ".ndjson"} or ".json." in name or ".ndjson." in name
    return (
        path.suffix.lower() in {".json", ".jsonl", ".ndjson", ".log"}
        or ".json." in name
        or ".ndjson." in name
        or "log" in name
    )


def _nested(record: Mapping[str, Any], *keys: str) -> Any:
    current: Any = record
    for key in keys:
        if not isinstance(current, Mapping):
            return None
        current = current.get(key)
    return current


def _is_tpot_record(record: Mapping[str, Any]) -> bool:
    if _tpot_type(record):
        return True
    return any(key.startswith("t-pot_") for key in record)


def _tpot_type(record: Mapping[str, Any]) -> str | None:
    value = _normalize_tpot_type(record.get("type"))
    if value and value in TPOT_MANAGED_TYPES:
        return TPOT_TYPE_ALIASES.get(value, value)
    return None


def _source_name_from_tpot_type(value: str | None) -> str | None:
    if not value:
        return None
    normalized = TPOT_TYPE_ALIASES.get(value.strip().lower(), value.strip().lower())
    if normalized in TPOT_TYPES:
        return normalized
    return None


def _normalize_tpot_type(value: Any) -> str | None:
    text = _as_str(value)
    if not text:
        return None
    return " ".join(text.strip().lower().split())


def _strip_compression_suffix(name: str) -> str:
    for suffix in COMPRESSED_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _open_text(path: Path) -> TextIO:
    suffix = path.suffix.lower()
    if suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    if suffix == ".bz2":
        return bz2.open(path, "rt", encoding="utf-8")
    if suffix == ".xz":
        return lzma.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _get_field(record: Mapping[str, Any], key: str) -> Any:
    if key in record:
        return record.get(key)
    if "." in key:
        return _nested(record, *key.split("."))
    return record.get(key)


def _first_value(record: Mapping[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = _get_field(record, key)
        if value is not None and value != "":
            return value
    return None


def _first_string(record: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        value = _as_str(_get_field(record, key))
        if value:
            return value
    return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (Mapping, list, tuple, set)):
        return None
    text = str(value)
    return text if text else None


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
