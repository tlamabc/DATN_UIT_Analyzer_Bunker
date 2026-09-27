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
            CREATE TABLE IF NOT EXISTS security_events (
                id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                client_ip VARCHAR(45), raw_log TEXT NOT NULL,
                classification VARCHAR(255) NOT NULL,
                risk_score VARCHAR(16) NOT NULL CHECK (risk_score IN ('Critical','High','Medium','Low')),
                explanation TEXT NOT NULL DEFAULT '',
                correlation TEXT NOT NULL DEFAULT '',
                recommendation TEXT NOT NULL
            )
        """)
        # Migrate an older deployment (attack_type/severity) onto the new AI-pipeline schema.
        cursor.execute("""
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_name='security_events' AND column_name='attack_type') THEN
                    ALTER TABLE security_events RENAME COLUMN attack_type TO classification;
                END IF;
                IF EXISTS (SELECT 1 FROM information_schema.columns
                           WHERE table_name='security_events' AND column_name='severity') THEN
                    ALTER TABLE security_events RENAME COLUMN severity TO risk_score;
                END IF;
            END $$;
        """)
        cursor.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS explanation TEXT NOT NULL DEFAULT ''")
        cursor.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS correlation TEXT NOT NULL DEFAULT ''")
        cursor.execute("CREATE INDEX IF NOT EXISTS security_events_timestamp_idx ON security_events (timestamp DESC)")
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
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyzer_console_logs (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                level VARCHAR(16) NOT NULL,
                logger VARCHAR(128) NOT NULL,
                message TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS analyzer_console_logs_created_at_idx ON analyzer_console_logs (created_at DESC)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS waf_request_observations (
                file_path TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                byte_offset BIGINT NOT NULL,
                occurred_at TIMESTAMPTZ NOT NULL,
                client_ip VARCHAR(45),
                blocked BOOLEAN NOT NULL DEFAULT FALSE,
                PRIMARY KEY (file_path, generation, byte_offset)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS waf_request_observations_occurred_at_idx ON waf_request_observations (occurred_at DESC)")

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
            "SELECT id, timestamp, client_ip, raw_log, classification, risk_score, explanation, correlation, recommendation "
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


def fetch_console_logs(limit: int = 100):
    with db_connect() as conn, conn.cursor() as cursor:
        cursor.execute(
            "SELECT created_at, level, logger, message FROM analyzer_console_logs "
            "ORDER BY id DESC LIMIT %s", (max(1, min(limit, 500)),),
        )
        return list(reversed(cursor.fetchall()))


def database_status() -> tuple[bool, str]:
    try:
        options = {**DB_DEFAULTS, "connect_timeout": 3}
        with psycopg2.connect(**options) as conn, conn.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        return True, "Connected"
    except psycopg2.Error as exc:
        return False, type(exc).__name__


def fetch_waf_metrics(start: datetime, end: datetime) -> dict[str, int | float]:
    with db_connect() as conn, conn.cursor() as cursor:
        ensure_tables(conn)
        cursor.execute(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE blocked), "
            "COUNT(DISTINCT client_ip) FILTER (WHERE blocked) "
            "FROM waf_request_observations WHERE occurred_at >= %s AND occurred_at <= %s",
            (start, end),
        )
        total_requests, blocked_requests, unique_attackers = (int(value or 0) for value in cursor.fetchone())
    rate = (100.0 * blocked_requests / total_requests) if total_requests else 0.0
    return {"total_requests": total_requests, "blocked_requests": blocked_requests,
            "unique_attackers": unique_attackers, "block_rate": rate}


def fetch_blocking_ips(start: datetime, end: datetime, limit: int = 100, ip_search: str = ""):
    with db_connect() as conn, conn.cursor() as cursor:
        ensure_tables(conn)
        query = (
            "SELECT client_ip, COUNT(*) AS blocked_requests, MAX(occurred_at) AS last_seen "
            "FROM waf_request_observations WHERE blocked=TRUE AND client_ip IS NOT NULL "
            "AND occurred_at >= %s AND occurred_at <= %s"
        )
        params: list[object] = [start, end]
        if ip_search:
            query += " AND client_ip ILIKE %s"
            params.append(f"%{ip_search}%")
        query += " GROUP BY client_ip ORDER BY blocked_requests DESC, last_seen DESC LIMIT %s"
        params.append(max(1, min(limit, 1000)))
        cursor.execute(query, params)
        return cursor.fetchall()
