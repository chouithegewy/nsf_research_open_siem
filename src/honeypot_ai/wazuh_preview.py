from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
import json
from pathlib import Path
import threading
import time
import os
from typing import Any, Iterable, Mapping


DEFAULT_DASHBOARD_SPEC = Path("deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json")
RECENT_EVENT_LIMIT = 200


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


_LLM_LOCK = threading.Lock()
_LLM_SUMMARY_CACHE: str | None = None
_LLM_LAST_RUN: float = 0.0
_LLM_THREAD_ACTIVE = False


def get_live_llm_summary(events: Iterable[Mapping[str, Any]]) -> str:
    global _LLM_SUMMARY_CACHE, _LLM_LAST_RUN, _LLM_THREAD_ACTIVE

    from honeypot_ai.llm import LLMClient, LLMConfig
    import dotenv
    dotenv.load_dotenv()
    config = LLMConfig()
    config.bearer_token = os.getenv("LLM_API_KEY", config.bearer_token)
    client = LLMClient(config=config)
    if not client.is_enabled():
        return ""


    now = time.time()
    if _LLM_SUMMARY_CACHE is not None and (now - _LLM_LAST_RUN) < 30.0:
        return _LLM_SUMMARY_CACHE

    if _LLM_THREAD_ACTIVE:
        return _LLM_SUMMARY_CACHE or "AI Analyst is currently analyzing live telemetry..."

    event_list = list(events)
    if not event_list:
        return "No events received to analyze."

    recent_events = sorted(
        event_list,
        key=lambda e: e.get("timestamp") or e.get("data", {}).get("timestamp") or "",
        reverse=True
    )[:5]

    cleaned_events = []
    for e in recent_events:
        item = dict(e)
        if "data" in item and isinstance(item["data"], dict):
            item = dict(item["data"])
        item = {
            k: v for k, v in item.items()
            if k not in (
                "kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS",
                "hasshAlgorithms", "kexAlgorithms", "payload", "packet",
                "payload_printable"
            )
        }
        cleaned_events.append(item)

    def _run_llm_request():
        global _LLM_SUMMARY_CACHE, _LLM_LAST_RUN, _LLM_THREAD_ACTIVE
        with _LLM_LOCK:
            try:
                summary = client.summarize_events(cleaned_events)
                if summary:
                    _LLM_SUMMARY_CACHE = summary
                    _LLM_LAST_RUN = time.time()
            except Exception as exc:
                _LLM_SUMMARY_CACHE = f"AI Analyst failed: {exc}"
                _LLM_LAST_RUN = time.time()
                print(f"LLM request failed: {exc}")
            finally:
                _LLM_THREAD_ACTIVE = False

    _LLM_THREAD_ACTIVE = True
    thread = threading.Thread(target=_run_llm_request, daemon=True)
    thread.start()

    return _LLM_SUMMARY_CACHE or "AI Analyst is reviewing live telemetry (this may take up to 20 seconds)..."


def render_dashboard_preview(
    events: Iterable[Mapping[str, Any]],
    spec: Mapping[str, Any],
    *,
    refresh_seconds: int = 0,
) -> str:
    events = list(events)
    model = build_preview_model(events)
    llm_summary = get_live_llm_summary(events)
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
    .event-row {{ cursor: pointer; }}
    .event-row.selected {{ background: #ecfeff; outline: 2px solid rgba(15, 118, 110, 0.26); outline-offset: -2px; }}
    code {{ background: #eef2f7; border-radius: 4px; padding: 1px 4px; }}
    .empty {{ color: var(--muted); padding: 10px 0; }}
    .severity-high, .severity-critical {{ color: var(--red); font-weight: 700; }}
    .severity-medium {{ color: var(--amber); font-weight: 700; }}
    .severity-low {{ color: var(--green); font-weight: 700; }}
    .filter-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      margin-bottom: 12px;
    }}
    .filter-toggle {{
      display: flex;
      align-items: center;
      gap: 7px;
      color: var(--text);
      font-size: 13px;
    }}
    .filter-search, .filter-select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      font: inherit;
      padding: 8px 9px;
    }}
    .filter-meta {{
      color: var(--muted);
      font-size: 12px;
      margin-top: 10px;
    }}
    .detail-panel h3 {{ margin: 0 0 8px; font-size: 16px; }}
    .detail-pills {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin: 8px 0 12px;
    }}
    .detail-pill {{
      border: 1px solid var(--line);
      border-radius: 999px;
      background: #f8fafc;
      color: var(--muted);
      padding: 3px 8px;
      font-size: 12px;
    }}
    .detail-fields {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 12px;
      margin-bottom: 14px;
    }}
    .detail-field span {{
      display: block;
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
    }}
    .detail-field strong {{
      display: block;
      overflow-wrap: anywhere;
      font-size: 13px;
      font-weight: 620;
    }}
    .related-list {{
      display: grid;
      gap: 8px;
      margin: 8px 0 14px;
    }}
    .related-item {{
      border-left: 3px solid var(--teal);
      padding: 6px 0 6px 9px;
      font-size: 12px;
    }}
    .related-item strong {{ display: block; font-size: 13px; }}
    .raw-json {{
      max-height: 280px;
      overflow: auto;
      background: #111827;
      color: #e5e7eb;
      border-radius: 6px;
      padding: 10px;
      font-size: 12px;
      white-space: pre-wrap;
    }}
    footer {{ color: var(--muted); font-size: 12px; padding: 2px 0 20px; }}
    @media (max-width: 940px) {{
      main {{ padding: 14px; }}
      .metrics, .grid {{ grid-template-columns: 1fr; }}
      .bar-row {{ grid-template-columns: minmax(80px, 120px) minmax(100px, 1fr) 42px; }}
      .filter-grid, .detail-fields {{ grid-template-columns: 1fr; }}
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
    {_ai_summary_panel(llm_summary)}
    <section class="grid">
      <div>
        {_panel("Alert Volume Over Time", _bars(model["timeline"], "teal"))}
        {_panel("Alerts By Pipeline", _bars(model["kind_counts"], "blue"))}
        {_panel("Recent Honeypot AI Events", _recent_table(model["recent_events"]))}
      </div>
      <div>
        {_panel("Event Filters", _event_filters())}
        {_panel("Event Details", _detail_shell())}
        {_panel("Confidence Mix", _bars(model["confidence_counts"], "amber"))}
        {_panel("eBPF Event Mix", _bars(model["ebpf_event_types"], "red"))}
        {_panel("Local Test Checklist", _checklist())}
      </div>
    </section>
    {_event_payload_script(model["recent_events"])}
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

    recent = sorted(normalized, key=lambda event: event["timestamp"] or "", reverse=True)[:RECENT_EVENT_LIMIT]
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


def _normalize_event(event: Mapping[str, Any]) -> dict[str, Any]:
    raw_payload = _raw_payload(event)
    normalized: dict[str, Any] = {
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
        "event_source": _string_field(event, "data.event_source") or _string_field(event, "event_source"),
        "host": _string_field(event, "data.host") or _string_field(event, "host"),
        "src_ip": _string_field(event, "data.src_ip") or _string_field(event, "src_ip"),
        "src_port": _string_field(event, "data.src_port") or _string_field(event, "src_port"),
        "dest_ip": _string_field(event, "data.dest_ip") or _string_field(event, "dest_ip"),
        "dest_port": _string_field(event, "data.dest_port") or _string_field(event, "dest_port"),
        "endpoint_hint": _string_field(event, "data.endpoint") or _string_field(event, "endpoint"),
        "indicator": _string_field(event, "data.indicator") or _string_field(event, "indicator"),
        "container_id": _string_field(event, "data.container_id") or _string_field(event, "container_id"),
        "cgroup_id": _string_field(event, "data.cgroup_id") or _string_field(event, "cgroup_id"),
        "session": _string_field(event, "data.session") or _string_field(event, "session"),
        "session_key": _string_field(event, "data.session_key") or _string_field(event, "session_key") or _string_field(event, "key"),
        "pid": _string_field(event, "data.pid") or _string_field(event, "pid"),
        "ppid": _string_field(event, "data.ppid") or _string_field(event, "ppid"),
        "uid": _string_field(event, "data.uid") or _string_field(event, "uid"),
        "gid": _string_field(event, "data.gid") or _string_field(event, "gid"),
        "binary": _string_field(event, "data.binary") or _string_field(event, "binary"),
        "command": _string_field(event, "data.command") or _string_field(event, "command"),
        "arguments_sample": _string_field(event, "data.arguments_sample") or _string_field(event, "arguments_sample"),
        "filename": _string_field(event, "data.filename") or _string_field(event, "filename"),
        "access_type": _string_field(event, "data.access_type") or _string_field(event, "access_type"),
        "process": (
            _string_field(event, "data.process_name")
            or _string_field(event, "process_name")
            or _string_field(event, "data.comm")
            or _string_field(event, "comm")
        ),
        "ml_score": _string_field(event, "data.ml_score") or _string_field(event, "ml_score") or _string_field(event, "score"),
        "description": _string_field(event, "data.description") or _string_field(event, "description"),
        "reasons": _string_field(event, "data.reasons") or _string_field(event, "reasons"),
    }
    for target, source in (
        ("event_source", "event_source"),
        ("host", "host"),
        ("src_ip", "src_ip"),
        ("src_port", "src_port"),
        ("dest_ip", "dest_ip"),
        ("dest_port", "dest_port"),
        ("container_id", "container_id"),
        ("cgroup_id", "cgroup_id"),
        ("pid", "pid"),
        ("ppid", "ppid"),
        ("uid", "uid"),
        ("gid", "gid"),
        ("binary", "binary"),
        ("command", "command"),
        ("arguments_sample", "arguments_sample"),
        ("filename", "filename"),
        ("access_type", "access_type"),
    ):
        if not normalized.get(target) and source in raw_payload:
            normalized[target] = _string_value(raw_payload.get(source))
    normalized["endpoint"] = _event_endpoint(normalized)
    normalized["summary"] = _event_summary(normalized)
    normalized["detail_fields"] = _detail_fields(normalized)
    normalized["related_keys"] = _related_keys(normalized)
    normalized["raw_event"] = _json_safe(event)
    return normalized


def _is_honeypot_ai_event(event: Mapping[str, Any]) -> bool:
    return (_string_field(event, "data.integration") or _string_field(event, "integration")) == "honeypot-ai"


def _is_misp_match(event: Mapping[str, Any]) -> bool:
    return "honeypot_ai_misp" in event["rule_name"] or "honeypot_ai_misp" in event["rule_groups"]


def _confidence(event: Mapping[str, Any]) -> str:
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
    return _string_value(_field(event, dotted))


def _string_value(value: Any) -> str:
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



def _ai_summary_panel(summary: str) -> str:
    if not summary:
        return ""
    return f'''
    <section id="ai-summary-panel" class="panel" style="margin-bottom: 22px; position: relative; overflow: hidden; border: 1px solid rgba(15, 118, 110, 0.3); box-shadow: 0 4px 15px -3px rgba(15, 118, 110, 0.1);">
      <div style="position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--teal), #06b6d4, var(--teal));"></div>
      <h2 style="margin-top: 4px; color: var(--teal); font-weight: 700; display: flex; align-items: center; gap: 8px;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
        Live AI Threat Analyst Summary
      </h2>
      <div style="background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 20px; margin-top: 14px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 13.5px; white-space: pre-wrap; line-height: 1.6; border: 1px solid rgba(255, 255, 255, 0.1); box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.06);">
        {_html(summary)}
      </div>
    </section>
    '''

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


def _event_filters() -> str:
    return """
      <div class="filter-grid" role="group" aria-label="Event visibility filters">
        <label class="filter-toggle"><input id="filter-ebpf" type="checkbox" checked> eBPF</label>
        <label class="filter-toggle"><input id="filter-ml" type="checkbox" checked> ML alerts</label>
        <label class="filter-toggle"><input id="filter-findings" type="checkbox" checked> IOC/findings</label>
        <label class="filter-toggle"><input id="filter-other" type="checkbox" checked> Other</label>
      </div>
      <label>
        <span class="empty">Search visible event fields</span>
        <input id="filter-search" class="filter-search" type="search" placeholder="process, IP, rule, container, file">
      </label>
      <label>
        <span class="empty">Confidence</span>
        <select id="filter-confidence" class="filter-select">
          <option value="all">All confidence levels</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <p class="filter-meta"><strong id="filtered-count">0</strong> of <span id="rendered-count">0</span> rendered events visible.</p>
    """


def _detail_shell() -> str:
    return """
      <div id="event-detail-panel" class="detail-panel" aria-live="polite">
        <p class="empty">Select an event row to inspect raw fields and the related activity window.</p>
      </div>
    """


def _recent_table(events: Iterable[Mapping[str, Any]]) -> str:
    event_list = list(events)
    rows = []
    for index, event in enumerate(event_list):
        severity = _confidence(event)
        endpoint = event["endpoint"]
        search_text = " ".join(
            str(event.get(field, ""))
            for field in (
                "timestamp",
                "kind",
                "rule_name",
                "rule_description",
                "severity",
                "event_type",
                "event_source",
                "endpoint",
                "src_ip",
                "dest_ip",
                "process",
                "binary",
                "command",
                "arguments_sample",
                "filename",
                "indicator",
                "container_id",
                "session",
                "session_key",
            )
        ).lower()
        rows.append(
            f'<tr class="event-row" tabindex="0" data-event-index="{index}" '
            f'data-kind="{_html(event["kind"] or "unknown")}" '
            f'data-confidence="{_html(severity)}" '
            f'data-search="{_html(search_text)}" '
            'title="Click for details and related events">'
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


def _event_payload_script(events: Iterable[Mapping[str, Any]]) -> str:
    payload = json.dumps(list(events), sort_keys=True, default=str)
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return (
        f'<script type="application/json" id="event-data">{payload}</script>\n'
        f"<script>{_dashboard_script()}</script>"
    )


def _dashboard_script() -> str:
    return r"""
(() => {
  const rows = Array.from(document.querySelectorAll(".event-row"));
  const eventData = document.getElementById("event-data");
  const detailPanel = document.getElementById("event-detail-panel");
  const countEl = document.getElementById("filtered-count");
  const renderedCountEl = document.getElementById("rendered-count");
  const filters = {
    ebpf: document.getElementById("filter-ebpf"),
    ml: document.getElementById("filter-ml"),
    findings: document.getElementById("filter-findings"),
    other: document.getElementById("filter-other"),
    confidence: document.getElementById("filter-confidence"),
    search: document.getElementById("filter-search"),
  };
  let events = [];

  try {
    events = JSON.parse(eventData?.textContent || "[]");
  } catch (_err) {
    events = [];
  }

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[char]));
  }

  function rowKindVisible(kind) {
    if (kind === "ebpf_event") return filters.ebpf?.checked;
    if (kind === "ml_alert") return filters.ml?.checked;
    if (kind === "finding") return filters.findings?.checked;
    return filters.other?.checked;
  }

  function applyEventFilters() {
    const query = (filters.search?.value || "").trim().toLowerCase();
    const confidence = filters.confidence?.value || "all";
    let visible = 0;

    rows.forEach((row) => {
      const kind = row.dataset.kind || "unknown";
      const rowConfidence = row.dataset.confidence || "unknown";
      const text = row.dataset.search || "";
      const matches =
        rowKindVisible(kind) &&
        (confidence === "all" || confidence === rowConfidence) &&
        (!query || text.includes(query));
      row.hidden = !matches;
      if (matches) visible += 1;
    });

    if (countEl) countEl.textContent = String(visible);
    if (renderedCountEl) renderedCountEl.textContent = String(rows.length);
  }

  function relatedEvents(selected, selectedIndex) {
    const keys = new Set(selected.related_keys || []);
    if (!keys.size) return [];
    return events
      .map((event, index) => ({ event, index }))
      .filter(({ event, index }) => (
        index !== selectedIndex &&
        (event.related_keys || []).some((key) => keys.has(key))
      ))
      .slice(0, 20);
  }

  function eventName(event) {
    return event.rule_name || event.event_type || event.rule_description || event.kind || "event";
  }

  function renderFieldGrid(event) {
    const fields = event.detail_fields || {};
    const entries = Object.entries(fields).filter(([, value]) => value !== "" && value !== null && value !== undefined);
    if (!entries.length) return '<p class="empty">No normalized detail fields were present.</p>';
    return '<div class="detail-fields">' + entries.map(([key, value]) => (
      `<div class="detail-field"><span>${escapeHtml(key)}</span><strong>${escapeHtml(value)}</strong></div>`
    )).join("") + "</div>";
  }

  function renderRelated(selected, selectedIndex) {
    const related = relatedEvents(selected, selectedIndex);
    if (!related.length) {
      return '<h3>Related Event Window</h3><p class="empty">No related rendered events share this session, container, pid, endpoint, or indicator.</p>';
    }
    const selectedItem = `
      <div class="related-item">
        <strong>${escapeHtml(eventName(selected))} (selected)</strong>
        <span>${escapeHtml(selected.timestamp)} · ${escapeHtml(selected.kind)} · ${escapeHtml(selected.endpoint || selected.process || "")}</span>
      </div>`;
    const relatedItems = related.map(({ event }) => `
      <div class="related-item">
        <strong>${escapeHtml(eventName(event))}</strong>
        <span>${escapeHtml(event.timestamp)} · ${escapeHtml(event.kind)} · ${escapeHtml(event.endpoint || event.process || "")}</span>
      </div>`).join("");
    return `<h3>Related Event Window</h3><div class="related-list">${selectedItem}${relatedItems}</div>`;
  }

  function renderEvent(index) {
    const event = events[index];
    if (!event || !detailPanel) return;
    rows.forEach((row) => row.classList.toggle("selected", Number(row.dataset.eventIndex) === index));
    const confidence = event.severity || event.severity_hint || "";
    const rawJson = JSON.stringify(event.raw_event || event, null, 2);
    detailPanel.innerHTML = `
      <h3>${escapeHtml(eventName(event))}</h3>
      <div class="detail-pills">
        <span class="detail-pill">${escapeHtml(event.kind || "unknown kind")}</span>
        <span class="detail-pill">${escapeHtml(event.event_source || "honeypot-ai")}</span>
        <span class="detail-pill">${escapeHtml(confidence || "unknown confidence")}</span>
      </div>
      ${renderFieldGrid(event)}
      ${renderRelated(event, index)}
      <h3>Raw Alert JSON</h3>
      <pre class="raw-json">${escapeHtml(rawJson)}</pre>
    `;
  }

  rows.forEach((row) => {
    const index = Number(row.dataset.eventIndex);
    row.addEventListener("click", () => renderEvent(index));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        renderEvent(index);
      }
    });
  });

  Object.values(filters).forEach((control) => {
    if (!control) return;
    control.addEventListener("input", applyEventFilters);
    control.addEventListener("change", applyEventFilters);
  });

  applyEventFilters();
  if (rows.length) renderEvent(Number(rows[0].dataset.eventIndex));
})();
"""


def _event_endpoint(event: Mapping[str, Any]) -> str:
    dest_ip = str(event.get("dest_ip") or "")
    dest_port = str(event.get("dest_port") or "")
    if dest_ip and dest_port:
        return f"{dest_ip}:{dest_port}"
    if dest_ip:
        return dest_ip
    endpoint = str(event.get("endpoint_hint") or "")
    if endpoint:
        return endpoint
    src_ip = str(event.get("src_ip") or "")
    src_port = str(event.get("src_port") or "")
    if src_ip and src_port:
        return f"{src_ip}:{src_port}"
    return src_ip


def _event_summary(event: Mapping[str, Any]) -> str:
    for field in ("rule_name", "rule_description", "event_type", "description", "reasons", "command", "filename"):
        value = str(event.get(field) or "")
        if value:
            return value
    return str(event.get("kind") or "event")


def _detail_fields(event: Mapping[str, Any]) -> dict[str, str]:
    labels = {
        "timestamp": "time",
        "kind": "pipeline",
        "event_type": "event type",
        "event_source": "source",
        "severity": "severity",
        "rule_level": "rule level",
        "endpoint": "endpoint",
        "src_ip": "source ip",
        "src_port": "source port",
        "dest_ip": "destination ip",
        "dest_port": "destination port",
        "process": "process",
        "binary": "binary",
        "command": "command",
        "arguments_sample": "arguments",
        "filename": "file",
        "access_type": "file access",
        "pid": "pid",
        "ppid": "ppid",
        "uid": "uid",
        "gid": "gid",
        "container_id": "container",
        "cgroup_id": "cgroup",
        "session": "session",
        "session_key": "session key",
        "indicator": "indicator",
        "ml_score": "ml score",
        "reasons": "reasons",
    }
    details: dict[str, str] = {}
    for field, label in labels.items():
        value = str(event.get(field) or "")
        if value:
            details[label] = value
    return details


def _related_keys(event: Mapping[str, Any]) -> list[str]:
    candidates = [
        ("session", event.get("session_key")),
        ("session", event.get("session")),
        ("container", event.get("container_id")),
        ("pid", event.get("pid")),
        ("endpoint", event.get("endpoint")),
        ("src", event.get("src_ip")),
        ("dest", event.get("dest_ip")),
        ("indicator", event.get("indicator")),
    ]
    keys: list[str] = []
    for label, value in candidates:
        text = str(value or "").strip()
        if text:
            keys.append(f"{label}:{text}")
    return list(dict.fromkeys(keys))


def _json_safe(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _raw_payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _field(event, "data.raw")
    if raw is None:
        raw = _field(event, "raw")
    if isinstance(raw, Mapping):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if isinstance(parsed, Mapping):
            return parsed
    return {}


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
