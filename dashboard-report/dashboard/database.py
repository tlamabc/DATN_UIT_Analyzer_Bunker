"""Dashboard database access and analyzer control operations."""
from datetime import datetime, time
import pandas as pd
import psycopg2
import streamlit as st
from .config import APP_TZ, DB_DEFAULTS

def db_connect():
    return psycopg2.connect(**DB_DEFAULTS)

def ensure_tables(conn) -> None:
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyzer_control (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                scan_date DATE NOT NULL,
                reset_requested BOOLEAN NOT NULL DEFAULT FALSE,
                response_language VARCHAR(20) NOT NULL DEFAULT 'Vietnamese',
                process_state VARCHAR(20) NOT NULL DEFAULT 'Stopped',
                progress_percent NUMERIC(5,2) NOT NULL DEFAULT 0,
                scanned_lines BIGINT NOT NULL DEFAULT 0,
                events_analyzed BIGINT NOT NULL DEFAULT 0,
                current_file TEXT,
                last_scan_at TIMESTAMPTZ,
                last_error TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        additions = {
            "response_language": "VARCHAR(20) NOT NULL DEFAULT 'Vietnamese'",
            "process_state": "VARCHAR(20) NOT NULL DEFAULT 'Stopped'",
            "progress_percent": "NUMERIC(5,2) NOT NULL DEFAULT 0",
            "scanned_lines": "BIGINT NOT NULL DEFAULT 0",
            "events_analyzed": "BIGINT NOT NULL DEFAULT 0",
            "current_file": "TEXT",
            "last_scan_at": "TIMESTAMPTZ",
            "last_error": "TEXT",
            "reset_requested": "BOOLEAN NOT NULL DEFAULT FALSE",
        }
        for name, definition in additions.items():
            cursor.execute(f"ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS {name} {definition}")
        cursor.execute(
            "INSERT INTO analyzer_control (id, enabled, scan_date) VALUES (1, FALSE, %s) ON CONFLICT (id) DO NOTHING",
            (datetime.now(APP_TZ).date(),),
        )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vmaas_usage (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                model VARCHAR(255) NOT NULL,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0
            )
        """)

def analyzer_status() -> dict:
    with db_connect() as conn:
        ensure_tables(conn)
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT enabled, scan_date, response_language, process_state, progress_percent,
                       scanned_lines, events_analyzed, current_file, last_scan_at, last_error
                FROM analyzer_control WHERE id=1
            """)
            row = cursor.fetchone()
    return {
        "enabled": bool(row[0]), "scan_date": row[1], "language": "English" if str(row[2]).lower() == "english" else "Vietnamese",
        "state": row[3], "progress": float(row[4] or 0), "lines": int(row[5] or 0),
        "analyzed": int(row[6] or 0), "file": row[7] or "-", "last_scan": row[8], "error": row[9],
    }

def set_analyzer(enabled: bool, language: str) -> None:
    today = datetime.now(APP_TZ).date()
    with db_connect() as conn:
        ensure_tables(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT scan_date FROM analyzer_control WHERE id=1")
            old_scan_date = cursor.fetchone()[0]
            if enabled:
                reset = old_scan_date != today
                cursor.execute(
                    "UPDATE analyzer_control SET enabled=TRUE, scan_date=%s, reset_requested=%s, "
                    "response_language=%s, process_state='Starting', updated_at=NOW() WHERE id=1",
                    (today, reset, language),
                )
            else:
                cursor.execute(
                    "UPDATE analyzer_control SET enabled=FALSE, reset_requested=FALSE, process_state='Stopped', "
                    "response_language=%s, updated_at=NOW() WHERE id=1", (language,)
                )

def set_language(language: str) -> None:
    normalized = "English" if language == "English" else "Vietnamese"
    with db_connect() as conn:
        ensure_tables(conn)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE analyzer_control SET response_language=%s, updated_at=NOW() WHERE id=1", (normalized,))

def fetch_events(start: datetime, end: datetime) -> pd.DataFrame:
    with db_connect() as conn, conn.cursor() as cursor:
        ensure_tables(conn)
        cursor.execute(
            "SELECT id, timestamp, client_ip, raw_log, attack_type, severity, recommendation "
            "FROM security_events WHERE timestamp >= %s AND timestamp <= %s ORDER BY timestamp DESC LIMIT 10000",
            (start, end),
        )
        rows = cursor.fetchall()
        return pd.DataFrame.from_records(rows, columns=[col.name for col in cursor.description])

def fetch_token_usage(start: datetime, end: datetime) -> tuple[int, int, int, int, int]:
    today_start = datetime.combine(datetime.now(APP_TZ).date(), time.min, tzinfo=APP_TZ)
    with db_connect() as conn, conn.cursor() as cursor:
        ensure_tables(conn)
        cursor.execute(
            "SELECT COALESCE(SUM(prompt_tokens),0), COALESCE(SUM(completion_tokens),0), "
            "COALESCE(SUM(total_tokens),0), COUNT(*) FROM vmaas_usage WHERE created_at >= %s AND created_at <= %s",
            (start, end),
        )
        selected = tuple(int(v) for v in cursor.fetchone())
        cursor.execute("SELECT COALESCE(SUM(total_tokens),0) FROM vmaas_usage WHERE created_at >= %s", (today_start,))
        today_tokens = int(cursor.fetchone()[0])
    return (*selected[:3], selected[3], today_tokens)

