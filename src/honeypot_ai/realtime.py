from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import time
from typing import Iterable, Mapping

from honeypot_ai.parsers import parse_ndjson
from honeypot_ai.report import analyze_events
from honeypot_ai.wazuh import report_to_wazuh_ndjson
from honeypot_ai.wazuh_preview import DEFAULT_DASHBOARD_SPEC, write_dashboard_preview


@dataclass(frozen=True)
class StreamResult:
    raw_lines: int
    parsed_events: int
    alert_events: int


def default_state_path(output_path: str | Path) -> Path:
    return Path(f"{output_path}.state.json")


def stream_once(
    paths: Iterable[str | Path],
    *,
    output_path: str | Path,
    state_path: str | Path | None = None,
    source_hint: str | None = None,
    input_format: str = "raw",
    preview_output: str | Path | None = None,
    preview_spec: str | Path = DEFAULT_DASHBOARD_SPEC,
    refresh_seconds: int = 5,
) -> StreamResult:
    if input_format not in {"raw", "wazuh"}:
        raise ValueError("input_format must be raw or wazuh")

    output = Path(output_path)
    state_file = Path(state_path) if state_path else default_state_path(output)
    offsets = _load_offsets(state_file)
    raw_lines: list[str] = []
    next_offsets = dict(offsets)

    for raw_path in paths:
        path = Path(raw_path)
        offset = int(offsets.get(str(path), 0))
        lines, new_offset = _read_new_complete_lines(path, offset)
        if lines:
            raw_lines.extend(lines)
        next_offsets[str(path)] = new_offset

    if not raw_lines:
        if preview_output and output.exists():
            write_dashboard_preview([output], preview_output, spec_path=preview_spec, refresh_seconds=refresh_seconds)
        _save_offsets(state_file, next_offsets)
        return StreamResult(raw_lines=0, parsed_events=0, alert_events=0)

    if input_format == "wazuh":
        payload = _validate_wazuh_lines(raw_lines)
        parsed_events = len(raw_lines)
    else:
        events = list(parse_ndjson(raw_lines, source_hint=source_hint))
        parsed_events = len(events)
        payload = report_to_wazuh_ndjson(analyze_events(events))

    alert_events = len([line for line in payload.splitlines() if line.strip()])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("a", encoding="utf-8") as handle:
        handle.write(payload)
        if payload and not payload.endswith("\n"):
            handle.write("\n")

    _save_offsets(state_file, next_offsets)

    if preview_output:
        write_dashboard_preview([output], preview_output, spec_path=preview_spec, refresh_seconds=refresh_seconds)

    return StreamResult(raw_lines=len(raw_lines), parsed_events=parsed_events, alert_events=alert_events)


def stream_forever(
    paths: Iterable[str | Path],
    *,
    output_path: str | Path,
    state_path: str | Path | None = None,
    source_hint: str | None = None,
    input_format: str = "raw",
    preview_output: str | Path | None = None,
    preview_spec: str | Path = DEFAULT_DASHBOARD_SPEC,
    refresh_seconds: int = 5,
    poll_seconds: float = 2.0,
) -> None:
    while True:
        stream_once(
            paths,
            output_path=output_path,
            state_path=state_path,
            source_hint=source_hint,
            input_format=input_format,
            preview_output=preview_output,
            preview_spec=preview_spec,
            refresh_seconds=refresh_seconds,
        )
        time.sleep(poll_seconds)


def _read_new_complete_lines(path: Path, offset: int) -> tuple[list[str], int]:
    if not path.exists():
        return [], offset
    size = path.stat().st_size
    if size < offset:
        offset = 0
    if size == offset:
        return [], offset

    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read()

    if not data:
        return [], offset
    complete = data
    new_offset = offset + len(data)
    if not data.endswith(b"\n"):
        newline_index = data.rfind(b"\n")
        if newline_index < 0:
            return [], offset
        complete = data[: newline_index + 1]
        new_offset = offset + newline_index + 1

    text = complete.decode("utf-8", errors="replace")
    return text.splitlines(), new_offset


def _validate_wazuh_lines(lines: Iterable[str]) -> str:
    payload_lines: list[str] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid Wazuh JSON on line {line_number}: {exc.msg}") from exc
        if not isinstance(payload, Mapping):
            raise ValueError(f"Wazuh line {line_number} did not contain a JSON object")
        if payload.get("integration") != "honeypot-ai":
            raise ValueError(f"Wazuh line {line_number} is missing integration=honeypot-ai")
        payload_lines.append(json.dumps(payload, sort_keys=True))
    return "\n".join(payload_lines) + ("\n" if payload_lines else "")


def _load_offsets(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    offsets: dict[str, int] = {}
    for key, value in payload.items():
        try:
            offsets[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return offsets


def _save_offsets(path: Path, offsets: Mapping[str, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(sorted(offsets.items())), indent=2, sort_keys=True) + "\n", encoding="utf-8")
