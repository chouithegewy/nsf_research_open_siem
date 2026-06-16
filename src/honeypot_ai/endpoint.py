from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from honeypot_ai.mitre import DOWNLOAD_TOKENS, PERSISTENCE_TOKENS, REVERSE_SHELL_TOKENS, SCANNER_TOKENS
from honeypot_ai.models import Event


FEATURE_NAMES = (
    "event_count",
    "packet_count",
    "bytes_in",
    "bytes_out",
    "duration_seconds",
    "unique_peers",
    "unique_dest_ports",
    "unique_protocols",
    "unique_event_types",
    "login_failures",
    "login_successes",
    "commands",
    "download_commands",
    "reverse_shells",
    "persistence_attempts",
    "scanner_commands",
    "suricata_alerts",
    "dionaea_connections",
    "network_connections",
    "url_count",
    "domain_count",
    "hash_count",
    "ebpf_event_count",
    "process_execs",
    "shell_execs",
    "script_execs",
    "download_tool_execs",
    "outbound_connects",
    "sensitive_file_writes",
    "temp_file_writes",
    "privilege_changes",
    "unique_binaries",
    "process_fanout",
)


@dataclass(frozen=True)
class EndpointWindow:
    id: str
    endpoint: str
    role: str
    window_start: datetime
    window_end: datetime
    features: Mapping[str, float]
    label: str = "unknown"
    label_reasons: tuple[str, ...] = ()
    source_event_count: int = 0


class PacketLike(Protocol):
    timestamp: datetime
    src_ip: str
    dest_ip: str
    src_port: int | None
    dest_port: int | None
    protocol: str
    length: int


@dataclass
class _WindowState:
    endpoint: str
    role: str
    window_start: datetime
    window_end: datetime
    features: dict[str, float]
    peers: set[str]
    dest_ports: set[int]
    protocols: set[str]
    event_types: set[str]
    urls: set[str]
    domains: set[str]
    hashes: set[str]
    binaries: set[str]
    source_event_count: int = 0


def build_endpoint_windows(
    events: Iterable[Event],
    *,
    window_seconds: int = 60,
    protected_cidrs: Iterable[str] = (),
) -> list[EndpointWindow]:
    networks = _parse_networks(protected_cidrs)
    states: dict[tuple[str, str, datetime], _WindowState] = {}
    for event in events:
        selected = _select_event_endpoint(event, networks)
        if selected is None:
            continue
        endpoint, role = selected
        start = _window_start(event.timestamp, window_seconds)
        key = (endpoint, role, start)
        state = states.setdefault(
            key,
            _WindowState(
                endpoint=endpoint,
                role=role,
                window_start=start,
                window_end=_window_end(start, window_seconds),
                features=_zero_features(),
                peers=set(),
                dest_ports=set(),
                protocols=set(),
                event_types=set(),
                urls=set(),
                domains=set(),
                hashes=set(),
                binaries=set(),
            ),
        )
        _apply_event(state, event)
    return assign_weak_labels(_finalize(states.values()))


def build_endpoint_windows_from_packets(
    packets: Iterable[PacketLike],
    *,
    window_seconds: int = 1,
    protected_cidrs: Iterable[str] = (),
) -> list[EndpointWindow]:
    networks = _parse_networks(protected_cidrs)
    states: dict[tuple[str, str, datetime], _WindowState] = {}
    for packet in packets:
        selected = _select_endpoint(packet.src_ip, packet.dest_ip, networks)
        if selected is None:
            continue
        endpoint, role = selected
        start = _window_start(packet.timestamp, window_seconds)
        key = (endpoint, role, start)
        state = states.setdefault(
            key,
            _WindowState(
                endpoint=endpoint,
                role=role,
                window_start=start,
                window_end=_window_end(start, window_seconds),
                features=_zero_features(),
                peers=set(),
                dest_ports=set(),
                protocols=set(),
                event_types=set(),
                urls=set(),
                domains=set(),
                hashes=set(),
                binaries=set(),
            ),
        )
        _apply_packet(state, packet)
    return _finalize(states.values())


def assign_weak_labels(windows: Iterable[EndpointWindow]) -> list[EndpointWindow]:
    labeled: list[EndpointWindow] = []
    for window in windows:
        label, reasons = weak_label(window.features)
        labeled.append(replace(window, label=label, label_reasons=reasons))
    return labeled


def weak_label(features: Mapping[str, float]) -> tuple[str, tuple[str, ...]]:
    reasons: list[str] = []
    if features.get("suricata_alerts", 0) > 0:
        reasons.append("Suricata alert observed")
    if features.get("reverse_shells", 0) > 0:
        reasons.append("reverse-shell command pattern")
    if features.get("persistence_attempts", 0) > 0:
        reasons.append("persistence command pattern")
    if features.get("download_commands", 0) > 0:
        reasons.append("tool or payload download")
    if features.get("hash_count", 0) > 0:
        reasons.append("file hash indicator")
    if features.get("scanner_commands", 0) > 0:
        reasons.append("scanner command pattern")
    if features.get("privilege_changes", 0) > 0:
        reasons.append("eBPF privilege change")
    if features.get("sensitive_file_writes", 0) > 0:
        reasons.append("eBPF sensitive file write")
    if features.get("download_tool_execs", 0) > 0:
        reasons.append("eBPF download tool execution")
    if features.get("shell_execs", 0) > 0 and features.get("outbound_connects", 0) > 0:
        reasons.append("eBPF shell with outbound connection")
    if reasons:
        return "malicious", tuple(reasons)
    return "benign", ("no weak malicious evidence",)


def feature_vector(window: EndpointWindow, feature_names: Iterable[str] = FEATURE_NAMES) -> dict[str, float]:
    return {name: float(window.features.get(name, 0.0)) for name in feature_names}


def windows_to_records(windows: Iterable[EndpointWindow]) -> list[dict[str, object]]:
    return [window_to_record(window) for window in windows]


def window_to_record(window: EndpointWindow) -> dict[str, object]:
    return {
        "id": window.id,
        "endpoint": window.endpoint,
        "role": window.role,
        "window_start": window.window_start.isoformat(),
        "window_end": window.window_end.isoformat(),
        "features": feature_vector(window),
        "label": window.label,
        "label_reasons": list(window.label_reasons),
        "source_event_count": window.source_event_count,
    }


def window_from_record(record: Mapping[str, object]) -> EndpointWindow:
    raw_features = record.get("features")
    if not isinstance(raw_features, Mapping):
        raw_features = {name: record.get(name, 0.0) for name in FEATURE_NAMES}
    reasons = record.get("label_reasons", ())
    if isinstance(reasons, str):
        reason_tuple = tuple(part for part in reasons.split(";") if part)
    elif isinstance(reasons, Iterable):
        reason_tuple = tuple(str(part) for part in reasons)
    else:
        reason_tuple = ()
    start = _parse_datetime(str(record["window_start"]))
    end = _parse_datetime(str(record["window_end"]))
    return EndpointWindow(
        id=str(record.get("id") or _window_id(str(record["endpoint"]), str(record.get("role", "unknown")), start)),
        endpoint=str(record["endpoint"]),
        role=str(record.get("role", "unknown")),
        window_start=start,
        window_end=end,
        features={name: _as_float(raw_features.get(name)) for name in FEATURE_NAMES},
        label=str(record.get("label", "unknown")),
        label_reasons=reason_tuple,
        source_event_count=int(_as_float(record.get("source_event_count", 0))),
    )


def read_windows(path: str | Path) -> list[EndpointWindow]:
    file_path = Path(path)
    if file_path.suffix.lower() == ".csv":
        with file_path.open("r", encoding="utf-8", newline="") as handle:
            return [window_from_record(row) for row in csv.DictReader(handle)]
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("endpoint-window dataset must contain a JSON array")
    return [window_from_record(item) for item in payload if isinstance(item, Mapping)]


def write_windows(windows: Iterable[EndpointWindow], path: str | Path | None, *, fmt: str = "json") -> str | None:
    records = windows_to_records(windows)
    if path is None:
        return _records_to_json(records)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "csv" or file_path.suffix.lower() == ".csv":
        with file_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "id",
                    "endpoint",
                    "role",
                    "window_start",
                    "window_end",
                    "label",
                    "label_reasons",
                    "source_event_count",
                    *FEATURE_NAMES,
                ],
            )
            writer.writeheader()
            for record in records:
                row = {
                    "id": record["id"],
                    "endpoint": record["endpoint"],
                    "role": record["role"],
                    "window_start": record["window_start"],
                    "window_end": record["window_end"],
                    "label": record["label"],
                    "label_reasons": ";".join(str(item) for item in record["label_reasons"]),
                    "source_event_count": record["source_event_count"],
                }
                features = record["features"]
                if isinstance(features, Mapping):
                    row.update({name: features.get(name, 0.0) for name in FEATURE_NAMES})
                writer.writerow(row)
        return None
    file_path.write_text(_records_to_json(records), encoding="utf-8")
    return None


def _records_to_json(records: list[dict[str, object]]) -> str:
    return json.dumps(records, indent=2, sort_keys=True) + "\n"


def _finalize(states: Iterable[_WindowState]) -> list[EndpointWindow]:
    windows: list[EndpointWindow] = []
    for state in states:
        state.features["unique_peers"] = float(len(state.peers))
        state.features["unique_dest_ports"] = float(len(state.dest_ports))
        state.features["unique_protocols"] = float(len(state.protocols))
        state.features["unique_event_types"] = float(len(state.event_types))
        state.features["url_count"] = float(len(state.urls))
        state.features["domain_count"] = float(len(state.domains))
        state.features["hash_count"] = float(len(state.hashes))
        state.features["unique_binaries"] = float(len(state.binaries))
        windows.append(
            EndpointWindow(
                id=_window_id(state.endpoint, state.role, state.window_start),
                endpoint=state.endpoint,
                role=state.role,
                window_start=state.window_start,
                window_end=state.window_end,
                features={name: float(state.features.get(name, 0.0)) for name in FEATURE_NAMES},
                source_event_count=state.source_event_count,
            )
        )
    return sorted(windows, key=lambda item: (item.window_start, item.endpoint, item.role))


def _apply_event(state: _WindowState, event: Event) -> None:
    state.source_event_count += 1
    state.features["event_count"] += 1.0
    state.event_types.add(event.event_type)
    if event.protocol:
        state.protocols.add(event.protocol.lower())
    if event.src_ip and event.src_ip != state.endpoint:
        state.peers.add(event.src_ip)
    if event.dest_ip and event.dest_ip != state.endpoint:
        state.peers.add(event.dest_ip)
    if event.dest_port is not None:
        state.dest_ports.add(event.dest_port)

    event_type = event.event_type.lower()
    if event.source == "cowrie" and "login.failed" in event_type:
        state.features["login_failures"] += 1.0
    if event.source == "cowrie" and "login.success" in event_type:
        state.features["login_successes"] += 1.0
    if event.command:
        command = event.command.lower()
        state.features["commands"] += 1.0
        if any(token.lower() in command for token in DOWNLOAD_TOKENS):
            state.features["download_commands"] += 1.0
        if any(token in command for token in REVERSE_SHELL_TOKENS):
            state.features["reverse_shells"] += 1.0
        if any(token in command for token in PERSISTENCE_TOKENS):
            state.features["persistence_attempts"] += 1.0
        if any(token in command for token in SCANNER_TOKENS):
            state.features["scanner_commands"] += 1.0
    if event.source == "suricata" and event.event_type == "alert":
        state.features["suricata_alerts"] += 1.0
    if event.source == "dionaea":
        state.features["dionaea_connections"] += 1.0
    if event.source == "zeek":
        state.features["network_connections"] += 1.0
    if event.source == "ebpf":
        _apply_ebpf_event(state, event)
    if event.url:
        state.urls.add(event.url)
    if event.domain:
        state.domains.add(event.domain)
    for value in event.hashes.values():
        state.hashes.add(value)

    bytes_out, bytes_in = _directional_bytes(event, state.endpoint)
    state.features["bytes_out"] += float(bytes_out)
    state.features["bytes_in"] += float(bytes_in)
    state.features["duration_seconds"] += _raw_float(event, "duration", "age")


def _apply_ebpf_event(state: _WindowState, event: Event) -> None:
    state.features["ebpf_event_count"] += 1.0
    event_type = event.event_type.lower()
    binary = _raw_string(event, "binary")
    command = (event.command or "").lower()
    if binary:
        state.binaries.add(binary)
    if "process_exec" in event_type:
        state.features["process_execs"] += 1.0
        state.features["process_fanout"] += 1.0
    if _looks_like_shell(binary, command):
        state.features["shell_execs"] += 1.0
    if _looks_like_script_runtime(binary, command):
        state.features["script_execs"] += 1.0
    if _looks_like_download_tool(binary, command):
        state.features["download_tool_execs"] += 1.0
    if "network_connect" in event_type:
        state.features["outbound_connects"] += 1.0
    if "privilege_change" in event_type:
        state.features["privilege_changes"] += 1.0
    if "file_access" in event_type:
        access = (_raw_string(event, "access_type") or "").lower()
        filename = event.filename or ""
        if any(token in access for token in ("write", "create", "delete", "unlink", "rename", "chmod", "chown")):
            if _is_temp_path(filename):
                state.features["temp_file_writes"] += 1.0
            if _is_sensitive_path(filename):
                state.features["sensitive_file_writes"] += 1.0


def _apply_packet(state: _WindowState, packet: PacketLike) -> None:
    state.features["packet_count"] += 1.0
    state.protocols.add(packet.protocol.lower())
    if packet.src_ip != state.endpoint:
        state.peers.add(packet.src_ip)
    if packet.dest_ip != state.endpoint:
        state.peers.add(packet.dest_ip)
    if packet.dest_port is not None:
        state.dest_ports.add(packet.dest_port)
    if packet.src_ip == state.endpoint:
        state.features["bytes_out"] += float(packet.length)
    elif packet.dest_ip == state.endpoint:
        state.features["bytes_in"] += float(packet.length)
    else:
        state.features["bytes_in"] += float(packet.length)


def _directional_bytes(event: Event, endpoint: str) -> tuple[int, int]:
    orig = _raw_int(event, "orig_bytes", "bytes_toserver")
    resp = _raw_int(event, "resp_bytes", "bytes_toclient")
    if event.src_ip == endpoint:
        return orig, resp
    if event.dest_ip == endpoint:
        return resp, orig
    return 0, orig + resp


def _raw_int(event: Event, *keys: str) -> int:
    return int(_raw_float(event, *keys))


def _raw_float(event: Event, *keys: str) -> float:
    total = 0.0
    flow = event.raw.get("flow") if isinstance(event.raw.get("flow"), Mapping) else {}
    for key in keys:
        for value in (event.raw.get(key), flow.get(key)):
            try:
                total += float(value)
            except (TypeError, ValueError):
                continue
    return total


def _raw_string(event: Event, key: str) -> str | None:
    value = event.raw.get(key)
    if value is None:
        return None
    return str(value)


def _select_event_endpoint(event: Event, networks: tuple[ipaddress._BaseNetwork, ...]) -> tuple[str, str] | None:
    selected = _select_endpoint(event.src_ip, event.dest_ip, networks)
    if selected is not None:
        return selected
    if event.source == "ebpf":
        host = _raw_string(event, "host")
        if host:
            role = "outbound" if event.dest_ip and not event.src_ip else "host"
            return host, role
    return None


def _looks_like_shell(binary: str | None, command: str) -> bool:
    value = (binary or "").rsplit("/", 1)[-1].lower()
    return value in {"sh", "bash", "dash", "zsh", "ksh"} or any(shell in command for shell in ("/bin/sh", " bash", " sh "))


def _looks_like_script_runtime(binary: str | None, command: str) -> bool:
    value = (binary or "").rsplit("/", 1)[-1].lower()
    runtimes = {"python", "python3", "perl", "php", "ruby", "node", "lua"}
    return value in runtimes or any(f"{runtime} " in command for runtime in runtimes)


def _looks_like_download_tool(binary: str | None, command: str) -> bool:
    value = (binary or "").rsplit("/", 1)[-1].lower()
    return value in {"curl", "wget", "fetch", "ftp", "tftp"} or any(token.lower() in command for token in DOWNLOAD_TOKENS)


def _is_temp_path(path: str) -> bool:
    return path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))


def _is_sensitive_path(path: str) -> bool:
    value = path.lower()
    sensitive_prefixes = (
        "/etc/",
        "/root/.ssh/",
        "/var/www/",
        "/usr/local/bin/",
        "/bin/",
        "/usr/bin/",
    )
    if value.startswith(sensitive_prefixes):
        return True
    if not value.startswith("/home/"):
        return False
    home_sensitive_markers = (
        "/.ssh/",
        "/.config/systemd/user/",
        "/.config/autostart/",
    )
    home_sensitive_suffixes = (
        "/.bashrc",
        "/.bash_profile",
        "/.profile",
        "/.zshrc",
        "/.zprofile",
        "/.kshrc",
    )
    return any(marker in value for marker in home_sensitive_markers) or value.endswith(home_sensitive_suffixes)


def _select_endpoint(src_ip: str | None, dest_ip: str | None, networks: tuple[ipaddress._BaseNetwork, ...]) -> tuple[str, str] | None:
    if networks:
        src_protected = _in_networks(src_ip, networks)
        dest_protected = _in_networks(dest_ip, networks)
        if src_protected and dest_protected and src_ip:
            return src_ip, "internal"
        if src_protected and src_ip:
            return src_ip, "outbound"
        if dest_protected and dest_ip:
            return dest_ip, "inbound"
        return None
    if dest_ip and _is_likely_internal(dest_ip):
        return dest_ip, "inbound"
    if src_ip and _is_likely_internal(src_ip):
        return src_ip, "outbound"
    if dest_ip:
        return dest_ip, "inbound"
    if src_ip:
        return src_ip, "unknown"
    return None


def _parse_networks(values: Iterable[str]) -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for value in values:
        if not value:
            continue
        networks.append(ipaddress.ip_network(value, strict=False))
    return tuple(networks)


def _in_networks(value: str | None, networks: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in networks)


def _is_likely_internal(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _window_start(timestamp: datetime | None, window_seconds: int) -> datetime:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if timestamp is None:
        timestamp = datetime.fromtimestamp(0, tz=timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    epoch = int(timestamp.timestamp())
    return datetime.fromtimestamp((epoch // window_seconds) * window_seconds, tz=timezone.utc)


def _window_end(start: datetime, window_seconds: int) -> datetime:
    return datetime.fromtimestamp(int(start.timestamp()) + window_seconds, tz=timezone.utc)


def _window_id(endpoint: str, role: str, start: datetime) -> str:
    raw = f"{endpoint}|{role}|{start.isoformat()}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()[:20]


def _zero_features() -> dict[str, float]:
    return {name: 0.0 for name in FEATURE_NAMES}


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _as_float(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
