from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


DEFAULT_DASHBOARD_SPEC = Path("deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json")


def load_dashboard_spec(path: str | Path = DEFAULT_DASHBOARD_SPEC) -> dict[str, Any]:
    spec_path = Path(path)
    try:
        payload = json.loads(spec_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{spec_path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{spec_path} did not contain a dashboard object")
    return payload


def load_wazuh_events(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ValueError(f"could not read {path}: {exc}") from exc
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is not valid JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"{path}:{line_number} did not contain a JSON object")
            events.append(payload)
    return events


def render_dashboard_preview(
    events: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    refresh_seconds: int = 0,
) -> str:
    model = build_preview_model(events)
    title = str(spec.get("name") or "Honeypot AI Single Pane")
    purpose = str(spec.get("purpose") or "Local preview of Honeypot AI events before SIEM deployment.")
    data_view = str(spec.get("data_view") or "wazuh-alerts-*")
    base_filter = str(spec.get("base_filter") or 'data.integration: "honeypot-ai"')
    refresh_meta = f'  <meta http-equiv="refresh" content="{int(refresh_seconds)}">\n' if refresh_seconds > 0 else ""
    refresh_note = f" Browser refresh interval: {int(refresh_seconds)} seconds." if refresh_seconds > 0 else ""

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
{refresh_meta}  <title>{_html(title)}</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --text: #18202a;
      --muted: #647084;
      --line: #d8dee8;
      --blue: #2563eb;
      --teal: #0f766e;
      --amber: #b45309;
      --red: #b91c1c;
      --green: #15803d;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: #172033;
      color: white;
      padding: 22px 28px 20px;
      border-bottom: 4px solid var(--teal);
    }}
    h1 {{ margin: 0 0 6px; font-size: 28px; font-weight: 740; }}
    h2 {{ margin: 0; font-size: 18px; }}
    p {{ margin: 0; }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
      color: #d7deea;
      font-size: 13px;
    }}
    .pill {{
      border: 1px solid rgba(255, 255, 255, 0.25);
      border-radius: 999px;
      padding: 4px 10px;
      white-space: nowrap;
    }}
    main {{ max-width: 1320px; margin: 0 auto; padding: 22px; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    .metric, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.06);
    }}
    .metric {{ padding: 16px; min-height: 96px; }}
    .metric span {{ color: var(--muted); font-size: 13px; }}
    .metric strong {{ display: block; margin-top: 8px; font-size: 30px; line-height: 1; }}
    .grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.25fr) minmax(360px, 0.75fr);
      gap: 18px;
    }}
    .panel {{ padding: 16px; margin-bottom: 18px; }}
    .panel h2 {{ margin-bottom: 12px; }}
    .bar-row {{
      display: grid;
      grid-template-columns: minmax(92px, 160px) minmax(120px, 1fr) 52px;
      gap: 10px;
      align-items: center;
      min-height: 28px;
      font-size: 13px;
    }}
    .bar-track {{ height: 10px; background: #edf1f7; border-radius: 999px; overflow: hidden; }}
    .bar {{ height: 100%; background: var(--blue); border-radius: 999px; }}
    .bar.teal {{ background: var(--teal); }}
    .bar.amber {{ background: var(--amber); }}
    .bar.red {{ background: var(--red); }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 8px 7px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 680; }}
    tbody tr:hover {{ background: #f8fafc; }}
    code {{ background: #eef2f7; border-radius: 4px; padding: 1px 4px; }}
    .empty {{ color: var(--muted); padding: 10px 0; }}
    .severity-high, .severity-critical {{ color: var(--red); font-weight: 700; }}
    .severity-medium {{ color: var(--amber); font-weight: 700; }}
    .severity-low {{ color: var(--green); font-weight: 700; }}
    footer {{ color: var(--muted); font-size: 12px; padding: 2px 0 20px; }}
    @media (max-width: 940px) {{
      main {{ padding: 14px; }}
      .metrics, .grid {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: minmax(80px, 120px) minmax(100px, 1fr) 42px; }}
      table {{ font-size: 12px; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>{_html(title)}</h1>
    <p>{_html(purpose)}</p>
    <div class="meta">
      <span class="pill">Data view: {_html(data_view)}</span>
      <span class="pill">Filter: {_html(base_filter)}</span>
      <span class="pill">Generated: {_html(datetime.now().astimezone().isoformat(timespec="seconds"))}</span>
    </div>
  </header>
  <main>
    <section class="metrics">
      {_metric("Total events", model["total_events"])}
      {_metric("High confidence", model["high_confidence"])}
      {_metric("MISP matches", model["misp_matches"])}
      {_metric("eBPF events", model["ebpf_events"])}
    </section>
    <section class="grid">
      <div>
        {_panel("Alert Volume Over Time", _bars(model["timeline"], "teal"))}
        {_panel("Alerts By Pipeline", _bars(model["kind_counts"], "blue"))}
        {_panel("Recent Honeypot AI Events", _recent_table(model["recent_events"]))}
      </div>
      <div>
        {_panel("Confidence Mix", _bars(model["confidence_counts"], "amber"))}
        {_panel("eBPF Event Mix", _bars(model["ebpf_event_types"], "red"))}
        {_panel("Local Test Checklist", _checklist())}
      </div>
    </section>
    <footer>
      This preview renders Wazuh-format Honeypot AI events locally. It does not prove that the target SIEM accepted saved objects or rules.{_html(refresh_note)}
    </footer>
  </main>
</body>
</html>
"""


def write_dashboard_preview(
    event_paths: Iterable[str | Path],
    output_path: str | Path,
    spec_path: str | Path = DEFAULT_DASHBOARD_SPEC,
    refresh_seconds: int = 0,
) -> dict[str, int]:
    events = load_wazuh_events(event_paths)
    spec = load_dashboard_spec(spec_path)
    html = render_dashboard_preview(events, spec, refresh_seconds=refresh_seconds)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")
    model = build_preview_model(events)
    return {
        "events": int(model["total_events"]),
        "high_confidence": int(model["high_confidence"]),
        "misp_matches": int(model["misp_matches"]),
        "ebpf_events": int(model["ebpf_events"]),
    }


def build_preview_model(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    normalized = [_normalize_event(event) for event in events if _is_honeypot_ai_event(event)]
    timeline = Counter(_minute_bucket(event["timestamp"]) for event in normalized)
    kind_counts = Counter(event["kind"] or "unknown" for event in normalized)
    ebpf_event_types = Counter(
        event["event_type"] or "unknown" for event in normalized if event["kind"] == "ebpf_event"
    )
    confidence_counts = Counter(_confidence(event) for event in normalized)

    recent = sorted(normalized, key=lambda event: event["timestamp"] or "", reverse=True)[:25]
    return {
        "total_events": len(normalized),
        "high_confidence": sum(1 for event in normalized if _confidence(event) == "high"),
        "misp_matches": sum(1 for event in normalized if _is_misp_match(event)),
        "ebpf_events": sum(1 for event in normalized if event["kind"] == "ebpf_event"),
        "timeline": dict(sorted(timeline.items())),
        "kind_counts": dict(kind_counts.most_common()),
        "ebpf_event_types": dict(ebpf_event_types.most_common()),
        "confidence_counts": dict(confidence_counts.most_common()),
        "recent_events": recent,
    }


def _normalize_event(event: Mapping[str, Any]) -> dict[str, str]:
    return {
        "timestamp": _string_field(event, "timestamp") or _string_field(event, "@timestamp"),
        "kind": _string_field(event, "data.kind") or _string_field(event, "kind"),
        "rule_name": _string_field(event, "data.rule_name") or _string_field(event, "rule_name"),
        "rule_description": _string_field(event, "rule.description"),
        "rule_groups": _string_field(event, "rule.groups"),
        "rule_level": _string_field(event, "rule.level") or _string_field(event, "level"),
        "severity": (
            _string_field(event, "data.severity")
            or _string_field(event, "severity")
            or _string_field(event, "data.severity_hint")
            or _string_field(event, "severity_hint")
        ),
        "event_type": _string_field(event, "data.event_type") or _string_field(event, "event_type"),
        "src_ip": _string_field(event, "data.src_ip") or _string_field(event, "src_ip"),
        "dest_ip": _string_field(event, "data.dest_ip") or _string_field(event, "dest_ip"),
        "dest_port": _string_field(event, "data.dest_port") or _string_field(event, "dest_port"),
        "process": (
            _string_field(event, "data.process_name")
            or _string_field(event, "process_name")
            or _string_field(event, "data.comm")
            or _string_field(event, "comm")
        ),
        "ml_score": _string_field(event, "data.ml_score") or _string_field(event, "ml_score") or _string_field(event, "score"),
    }


def _is_honeypot_ai_event(event: Mapping[str, Any]) -> bool:
    return (_string_field(event, "data.integration") or _string_field(event, "integration")) == "honeypot-ai"


def _is_misp_match(event: Mapping[str, str]) -> bool:
    return "honeypot_ai_misp" in event["rule_name"] or "honeypot_ai_misp" in event["rule_groups"]


def _confidence(event: Mapping[str, str]) -> str:
    severity = event["severity"].lower()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    try:
        level = int(float(event["rule_level"]))
    except ValueError:
        return severity or "unknown"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def _field(event: Mapping[str, Any], dotted: str) -> Any:
    current: Any = event
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            if dotted.startswith("data."):
                return event.get(dotted[5:])
            return event.get(dotted)
        current = current[part]
    return current


def _string_field(event: Mapping[str, Any], dotted: str) -> str:
    value = _field(event, dotted)
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ";".join(str(item) for item in value)
    if isinstance(value, Mapping):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _minute_bucket(timestamp: str) -> str:
    if not timestamp:
        return "unknown"
    normalized = timestamp.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return timestamp[:16]
    return parsed.isoformat(timespec="minutes")


def _metric(label: str, value: object) -> str:
    return f'<div class="metric"><span>{_html(label)}</span><strong>{_html(value)}</strong></div>'


def _panel(title: str, body: str) -> str:
    return f'<section class="panel"><h2>{_html(title)}</h2>{body}</section>'


def _bars(values: Mapping[str, int], class_name: str) -> str:
    if not values:
        return '<p class="empty">No matching events.</p>'
    max_value = max(values.values()) or 1
    rows = []
    for label, value in values.items():
        width = max(4, round((value / max_value) * 100))
        rows.append(
            '<div class="bar-row">'
            f'<span>{_html(label)}</span>'
            f'<div class="bar-track"><div class="bar {_html(class_name)}" style="width: {width}%"></div></div>'
            f'<strong>{_html(value)}</strong>'
            "</div>"
        )
    return "\n".join(rows)


def _recent_table(events: Iterable[Mapping[str, str]]) -> str:
    rows = []
    for event in events:
        severity = _confidence(event)
        endpoint = event["dest_ip"] or event["src_ip"]
        if event["dest_port"]:
            endpoint = f"{endpoint}:{event['dest_port']}" if endpoint else event["dest_port"]
        rows.append(
            "<tr>"
            f"<td>{_html(event['timestamp'])}</td>"
            f"<td>{_html(event['kind'])}</td>"
            f"<td>{_html(event['rule_name'] or event['rule_description'])}</td>"
            f'<td class="severity-{_html(severity)}">{_html(severity)}</td>'
            f"<td>{_html(endpoint)}</td>"
            f"<td>{_html(event['process'])}</td>"
            f"<td>{_html(event['ml_score'])}</td>"
            "</tr>"
        )
    if not rows:
        return '<p class="empty">No matching events.</p>'
    return (
        "<table><thead><tr>"
        "<th>Time</th><th>Kind</th><th>Rule</th><th>Confidence</th><th>Endpoint</th><th>Process</th><th>ML Score</th>"
        "</tr></thead><tbody>"
        + "\n".join(rows)
        + "</tbody></table>"
    )


def _checklist() -> str:
    items = [
        "Wazuh-format NDJSON parses locally",
        "Dashboard saved-object bundle is validated by tests",
        "Preview renders signature/MISP, ML, and eBPF fields",
        "Remote SIEM import still needs target-specific validation",
    ]
    return "<ul>" + "".join(f"<li>{_html(item)}</li>" for item in items) + "</ul>"


def _html(value: object) -> str:
    return escape(str(value), quote=True)
