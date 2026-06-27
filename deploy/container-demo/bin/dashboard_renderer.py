#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from honeypot_ai.wazuh_preview import write_dashboard_preview


def _paths_from_env() -> list[Path]:
    raw = os.getenv(
        "DASHBOARD_EVENT_PATHS",
        "/data/alerts/wazuh-alerts.ndjson:/data/alerts/ml-alerts.ndjson",
    )
    return [Path(item) for item in raw.split(":") if item]


def main() -> int:
    event_paths = _paths_from_env()
    output = Path(os.getenv("DASHBOARD_OUTPUT", "/dashboard/index.html"))
    spec = os.getenv("DASHBOARD_SPEC", "/app/deploy/wazuh/dashboard/honeypot-ai-dashboard-spec.json")
    refresh_seconds = int(os.getenv("DASHBOARD_REFRESH_SECONDS", "5"))
    poll_seconds = float(os.getenv("RENDER_POLL_SECONDS", "2"))

    for path in event_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    print(f"Dashboard renderer writing {output} from {', '.join(str(p) for p in event_paths)}", flush=True)
    while True:
        try:
            result = write_dashboard_preview(
                event_paths,
                output,
                spec_path=spec,
                refresh_seconds=refresh_seconds,
            )
            print(
                "Dashboard events={events} high={high_confidence} ml/misp={misp_matches} ebpf={ebpf_events}".format(
                    **result
                ),
                flush=True,
            )
        except Exception as exc:
            print(f"dashboard renderer error: {exc}", file=sys.stderr, flush=True)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
