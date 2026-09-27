"""PostgreSQL schema, event persistence, analyzer controls, and cursors."""
import os
from datetime import date, datetime
from typing import Any
import psycopg2
from .config import analyzer_timezone
from .log_parser import event_timestamp

def db_connect():
    return psycopg2.connect(host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=10)

def initialize_database() -> None:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("""
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
        cur.execute("""
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
        cur.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS explanation TEXT NOT NULL DEFAULT ''")
        cur.execute("ALTER TABLE security_events ADD COLUMN IF NOT EXISTS correlation TEXT NOT NULL DEFAULT ''")
        cur.execute("ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_severity_check")
        cur.execute("ALTER TABLE security_events DROP CONSTRAINT IF EXISTS security_events_risk_score_check")
        cur.execute(
            "ALTER TABLE security_events ADD CONSTRAINT security_events_risk_score_check "
            "CHECK (risk_score IN ('Critical','High','Medium','Low'))"
        )
        cur.execute("CREATE INDEX IF NOT EXISTS security_events_timestamp_idx ON security_events (timestamp DESC)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS analyzer_control (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                scan_date DATE NOT NULL,
                reset_requested BOOLEAN NOT NULL DEFAULT FALSE,
                response_language VARCHAR(20) NOT NULL DEFAULT 'Vietnamese',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS response_language VARCHAR(20) NOT NULL DEFAULT 'Vietnamese'")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS process_state VARCHAR(20) NOT NULL DEFAULT 'Stopped'")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS progress_percent NUMERIC(5,2) NOT NULL DEFAULT 0")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS scanned_lines BIGINT NOT NULL DEFAULT 0")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS events_analyzed BIGINT NOT NULL DEFAULT 0")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS current_file TEXT")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ")
        cur.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS last_error TEXT")
        cur.execute("""
            INSERT INTO analyzer_control (id, enabled, scan_date)
            VALUES (1, FALSE, %s) ON CONFLICT (id) DO NOTHING
        """, (datetime.now(analyzer_timezone()).date(),))
        cur.execute("""
            CREATE TABLE IF NOT EXISTS collector_offsets (
                file_path TEXT PRIMARY KEY,
                byte_offset BIGINT NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS vmaas_usage (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                model VARCHAR(255) NOT NULL,
                prompt_tokens INTEGER NOT NULL DEFAULT 0,
                completion_tokens INTEGER NOT NULL DEFAULT 0,
                total_tokens INTEGER NOT NULL DEFAULT 0
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS vmaas_usage_created_at_idx ON vmaas_usage (created_at DESC)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS analyzer_console_logs (
                id BIGSERIAL PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                level VARCHAR(16) NOT NULL,
                logger VARCHAR(128) NOT NULL,
                message TEXT NOT NULL
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS analyzer_console_logs_created_at_idx ON analyzer_console_logs (created_at DESC)")
        cur.execute("""
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
        cur.execute("ALTER TABLE waf_request_observations ADD COLUMN IF NOT EXISTS generation INTEGER NOT NULL DEFAULT 0")
        cur.execute("ALTER TABLE waf_request_observations DROP CONSTRAINT IF EXISTS waf_request_observations_pkey")
        cur.execute("ALTER TABLE waf_request_observations ADD CONSTRAINT waf_request_observations_pkey PRIMARY KEY (file_path, generation, byte_offset)")
        cur.execute("CREATE INDEX IF NOT EXISTS waf_request_observations_occurred_at_idx ON waf_request_observations (occurred_at DESC)")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS waf_observation_offsets (
                file_path TEXT PRIMARY KEY,
                byte_offset BIGINT NOT NULL DEFAULT 0,
                generation INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cur.execute("ALTER TABLE waf_observation_offsets ADD COLUMN IF NOT EXISTS generation INTEGER NOT NULL DEFAULT 0")
        cur.execute("DELETE FROM waf_request_observations WHERE occurred_at < NOW() - INTERVAL '60 days'")


def save_console_log(level: str, logger_name: str, message: str) -> None:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO analyzer_console_logs (level, logger, message) VALUES (%s, %s, %s)",
            (level[:16], logger_name[:128], message[:4000]),
        )


def load_waf_offsets() -> dict[str, int]:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT file_path, byte_offset, generation FROM waf_observation_offsets")
        return {path: (int(offset), int(generation)) for path, offset, generation in cur.fetchall()}


def save_waf_observations(file_path: str, generation: int,
                          observations: list[tuple[int, datetime, str | None, bool]], new_offset: int) -> None:
    with db_connect() as conn, conn.cursor() as cur:
        if observations:
            cur.executemany(
                "INSERT INTO waf_request_observations(file_path, generation, byte_offset, occurred_at, client_ip, blocked) "
                "VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT(file_path, generation, byte_offset) DO NOTHING",
                [(file_path, generation, offset, occurred_at, ip, blocked) for offset, occurred_at, ip, blocked in observations],
            )
        cur.execute(
            "INSERT INTO waf_observation_offsets(file_path, byte_offset, generation) VALUES (%s, %s, %s) "
            "ON CONFLICT(file_path) DO UPDATE SET byte_offset=EXCLUDED.byte_offset, "
            "generation=EXCLUDED.generation, updated_at=NOW()",
            (file_path, new_offset, generation),
        )

def save_event(raw: str, data: dict[str, Any], analysis: dict[str, str], usage: dict[str, int] | None) -> None:
    client_ip = data.get("client_ip") or data.get("remote_addr") or data.get("ip")
    client_ip = str(client_ip)[:45] if client_ip is not None else None
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO security_events "
            "(timestamp, client_ip, raw_log, classification, risk_score, explanation, correlation, recommendation) "
            "VALUES (COALESCE(%s, NOW()), %s, %s, %s, %s, %s, %s, %s)",
            (event_timestamp(data), client_ip, raw, analysis["classification"], analysis["risk_score"],
             analysis["explanation"], analysis["correlation"], analysis["recommendation"]),
        )
        if usage and usage.get("total_tokens", 0) > 0:
            cur.execute(
                "INSERT INTO vmaas_usage(model, prompt_tokens, completion_tokens, total_tokens) VALUES (%s,%s,%s,%s)",
                (os.getenv("VMAAS_MODEL", "unknown")[:255], usage["prompt_tokens"], usage["completion_tokens"], usage["total_tokens"]),
            )

def get_control() -> tuple[bool, date, bool, str]:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT enabled, scan_date, reset_requested, response_language FROM analyzer_control WHERE id=1")
        row = cur.fetchone()
    if not row:
        return False, datetime.now(analyzer_timezone()).date(), False, "Vietnamese"
    language = "English" if str(row[3]).lower() == "english" else "Vietnamese"
    return bool(row[0]), row[1], bool(row[2]), language

def clear_reset_request() -> None:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("UPDATE analyzer_control SET reset_requested=FALSE WHERE id=1")
        cur.execute("UPDATE analyzer_control SET progress_percent=0, scanned_lines=0, events_analyzed=0, last_error=NULL WHERE id=1")
        cur.execute("DELETE FROM collector_offsets")

def load_offsets() -> dict[str, int]:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT file_path, byte_offset FROM collector_offsets")
        return {path: int(offset) for path, offset in cur.fetchall()}

def save_offset(path: str, offset: int) -> None:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO collector_offsets(file_path, byte_offset) VALUES (%s, %s) "
            "ON CONFLICT(file_path) DO UPDATE SET byte_offset=EXCLUDED.byte_offset, updated_at=NOW()",
            (path, offset),
        )

def update_progress(state: str, current_file: str | None, percent: float, lines: int = 0,
                    events: int = 0, error: str | None = None) -> None:
    with db_connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE analyzer_control SET process_state=%s, current_file=%s, progress_percent=%s, "
            "scanned_lines=scanned_lines+%s, events_analyzed=events_analyzed+%s, last_scan_at=NOW(), "
            "last_error=%s WHERE id=1",
            (state, current_file, max(0.0, min(100.0, percent)), lines, events, error[:1000] if error else None),
        )

