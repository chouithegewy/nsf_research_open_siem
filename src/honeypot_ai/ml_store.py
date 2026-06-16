from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping

from honeypot_ai.endpoint import EndpointWindow, window_to_record
from honeypot_ai.ml import MLAlert, alert_to_record


def init_ml_db(db_path: str | Path) -> None:
    import duckdb

    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ml_models (
                model_id TEXT PRIMARY KEY,
                kind TEXT,
                version TEXT,
                trained_at TEXT,
                feature_names TEXT,
                threshold DOUBLE,
                training_rows BIGINT,
                metrics TEXT,
                artifact_path TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS endpoint_windows (
                id TEXT PRIMARY KEY,
                model_id TEXT,
                endpoint TEXT,
                role TEXT,
                window_start TEXT,
                window_end TEXT,
                features TEXT,
                label TEXT,
                label_reasons TEXT,
                source_event_count BIGINT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ml_alerts (
                id TEXT PRIMARY KEY,
                model_id TEXT,
                endpoint TEXT,
                role TEXT,
                window_start TEXT,
                window_end TEXT,
                score DOUBLE,
                threshold DOUBLE,
                severity TEXT,
                reasons TEXT,
                features TEXT,
                created_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ebpf_events (
                id TEXT PRIMARY KEY,
                schema_version BIGINT,
                timestamp TEXT,
                host TEXT,
                event_type TEXT,
                pid BIGINT,
                ppid BIGINT,
                uid BIGINT,
                gid BIGINT,
                comm TEXT,
                "binary" TEXT,
                arguments_sample TEXT,
                argv_truncated BOOLEAN,
                cgroup_id TEXT,
                container_id TEXT,
                src_ip TEXT,
                src_port BIGINT,
                dest_ip TEXT,
                dest_port BIGINT,
                protocol TEXT,
                filename TEXT,
                access_type TEXT,
                severity_hint TEXT,
                raw TEXT
            )
            """
        )
        conn.execute("ALTER TABLE ebpf_events ADD COLUMN IF NOT EXISTS raw TEXT")
    finally:
        conn.close()


def insert_model_metadata(db_path: str | Path, metadata: Mapping[str, object]) -> None:
    import duckdb

    init_ml_db(db_path)
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO ml_models VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                str(metadata.get("model_id", "")),
                str(metadata.get("kind", "")),
                str(metadata.get("version", "")),
                str(metadata.get("trained_at", "")),
                json.dumps(metadata.get("feature_names", []), sort_keys=True),
                float(metadata.get("threshold", 0.0)),
                int(metadata.get("training_rows", 0)),
                json.dumps(metadata.get("metrics", {}), sort_keys=True),
                str(metadata.get("model_path", "")),
            ],
        )
    finally:
        conn.close()


def insert_endpoint_windows(
    db_path: str | Path,
    windows: Iterable[EndpointWindow],
    *,
    model_id: str | None = None,
) -> int:
    import duckdb

    init_ml_db(db_path)
    rows = []
    for window in windows:
        record = window_to_record(window)
        rows.append(
            [
                record["id"],
                model_id,
                record["endpoint"],
                record["role"],
                record["window_start"],
                record["window_end"],
                json.dumps(record["features"], sort_keys=True),
                record["label"],
                json.dumps(record["label_reasons"], sort_keys=True),
                record["source_event_count"],
            ]
        )
    if not rows:
        return 0
    conn = duckdb.connect(str(db_path))
    try:
        conn.executemany(
            """
            INSERT OR REPLACE INTO endpoint_windows VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    finally:
        conn.close()
    return len(rows)


def insert_ml_alerts(db_path: str | Path, alerts: Iterable[MLAlert]) -> int:
    import duckdb

    init_ml_db(db_path)
    rows = []
    for alert in alerts:
        record = alert_to_record(alert)
        rows.append(
            [
                record["id"],
                record["model_id"],
                record["endpoint"],
                record["role"],
                record["window_start"],
                record["window_end"],
                record["score"],
                record["threshold"],
                record["severity"],
                json.dumps(record["reasons"], sort_keys=True),
                json.dumps(record["features"], sort_keys=True),
                record["created_at"],
            ]
        )
    if not rows:
        return 0
    conn = duckdb.connect(str(db_path))
    try:
        conn.executemany(
            """
            INSERT OR REPLACE INTO ml_alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    finally:
        conn.close()
    return len(rows)
