"""SOC dashboard for AI-analyzed BunkerWeb security events."""
import os
from datetime import date, datetime, time, timedelta, timezone

import pandas as pd
import psycopg2
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="SOC Security Dashboard", page_icon="🛡️", layout="wide")


def app_timezone():
    return timezone(timedelta(hours=7), name="Asia/Ho_Chi_Minh")


def ensure_control_table(conn) -> None:
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyzer_control (
                id SMALLINT PRIMARY KEY CHECK (id = 1),
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                scan_date DATE NOT NULL,
                reset_requested BOOLEAN NOT NULL DEFAULT FALSE,
                response_language VARCHAR(20) NOT NULL DEFAULT 'Vietnamese',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        cursor.execute("ALTER TABLE analyzer_control ADD COLUMN IF NOT EXISTS response_language VARCHAR(20) NOT NULL DEFAULT 'Vietnamese'")
        cursor.execute(
            "INSERT INTO analyzer_control (id, enabled, scan_date) VALUES (1, FALSE, %s) "
            "ON CONFLICT (id) DO NOTHING",
            (datetime.now(app_timezone()).date(),),
        )


def analyzer_status() -> tuple[bool, date, str]:
    with psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=8,
    ) as conn:
        ensure_control_table(conn)
        with conn.cursor() as cursor:
            cursor.execute("SELECT enabled, scan_date, response_language FROM analyzer_control WHERE id=1")
            row = cursor.fetchone()
            language = "English" if str(row[2]).lower() == "english" else "Vietnamese"
            return bool(row[0]), row[1], language


def set_analyzer(enabled: bool, response_language: str) -> None:
    today = datetime.now(app_timezone()).date()
    with psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=8,
    ) as conn:
        ensure_control_table(conn)
        with conn.cursor() as cursor:
            if enabled:
                cursor.execute("SELECT scan_date FROM analyzer_control WHERE id=1")
                previous_scan_date = cursor.fetchone()[0]
                reset_requested = previous_scan_date != today
                cursor.execute(
                    "UPDATE analyzer_control SET enabled=TRUE, scan_date=%s, reset_requested=%s, "
                    "response_language=%s, updated_at=NOW() WHERE id=1",
                    (today, reset_requested, response_language),
                )
            else:
                cursor.execute(
                    "UPDATE analyzer_control SET enabled=FALSE, reset_requested=FALSE, response_language=%s, "
                    "updated_at=NOW() WHERE id=1", (response_language,)
                )


def set_response_language(response_language: str) -> None:
    language = "English" if response_language == "English" else "Vietnamese"
    with psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=8,
    ) as conn:
        ensure_control_table(conn)
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE analyzer_control SET response_language=%s, updated_at=NOW() WHERE id=1", (language,)
            )


def fetch_events() -> pd.DataFrame:
    local_today = datetime.now(app_timezone()).date()
    start_of_day = datetime.combine(local_today, time.min, tzinfo=app_timezone())
    with psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=8,
    ) as conn, conn.cursor() as cursor:
        ensure_control_table(conn)
        cursor.execute(
            "SELECT id, timestamp, client_ip, raw_log, attack_type, severity, recommendation "
            "FROM security_events WHERE timestamp >= %s ORDER BY timestamp DESC LIMIT 5000",
            (start_of_day,),
        )
        rows = cursor.fetchall()
        columns = [description.name for description in cursor.description]
        return pd.DataFrame.from_records(rows, columns=columns)


with st.container(border=True):
    st.subheader("Thông tin Đồ án Tốt nghiệp")
    st.markdown(
        "# TÌM HIỂU VÀ XÂY DỰNG HỆ THỐNG WEB APPLICATION FIREWALL OPEN SOURCE TÍCH HỢP AI PHÂN TÍCH TẤN CÔNG"
    )
    st.markdown("*AI-Enhanced Open Source WAF Security Assessment Lab*")
    st.markdown("**Đặng Thanh Lâm** (ID: 25410078)  ·  **Trương Tấn Đạt** (ID: 25410031)")

st.title("🛡️ SOC Security Dashboard")
today = datetime.now(app_timezone()).date()
st.caption(f"BunkerWeb security events since 00:00 today ({today.isoformat()}) · timezone Asia/Ho_Chi_Minh (UTC+07:00)")
@st.cache_data(ttl=30, show_spinner="Loading security events...")
def load_events() -> pd.DataFrame:
    return fetch_events()


try:
    events = load_events()
    running, scan_date, response_language = analyzer_status()
except Exception as exc:
    st.error("Could not connect to PostgreSQL. Check the database service and DB_* configuration.")
    st.exception(exc)
    st.stop()

language_options = ["Vietnamese", "English"]
language_labels = {"Vietnamese": "Tiếng Việt", "English": "English"}
selected_language = st.selectbox(
    "AI recommendation language",
    language_options,
    index=language_options.index(response_language),
    format_func=lambda value: language_labels[value],
)
button_start, button_stop, button_save_language, button_refresh = st.columns([1, 1, 1.5, 1])
if button_start.button("▶ Start Analyzer", type="primary"):
    try:
        set_analyzer(True, selected_language)
        st.cache_data.clear()
        st.success("Analyzer started. It will scan today's log entries on the configured interval.")
    except Exception as exc:
        st.error(f"Could not start analyzer: {exc}")
if button_stop.button("■ Stop Analyzer"):
    try:
        set_analyzer(False, selected_language)
        st.success("Analyzer stopped.")
    except Exception as exc:
        st.error(f"Could not stop analyzer: {exc}")
if button_save_language.button("Save language"):
    try:
        set_response_language(selected_language)
        st.success("AI recommendation language saved.")
    except Exception as exc:
        st.error(f"Could not save language: {exc}")
if button_refresh.button("↻ Refresh"):
    st.cache_data.clear()

scan_interval = int(os.getenv("ANALYZER_SCAN_INTERVAL_SECONDS", "600"))
st.info(
    f"Analyzer status: {'Running' if running else 'Stopped'} · "
    f"scan date: {scan_date.isoformat()} · interval: every {scan_interval} seconds · "
    f"max {os.getenv('ANALYZER_MAX_EVENTS_PER_SCAN', '3')} security events per scan"
)

total = len(events)
critical = int((events["severity"].str.lower() == "critical").sum()) if total else 0
high = int((events["severity"].str.lower() == "high").sum()) if total else 0
col1, col2, col3, col4 = st.columns(4)
col1.metric("Analyzed events", f"{total:,}")
col2.metric("Critical alerts", f"{critical:,}")
col3.metric("High alerts", f"{high:,}")
col4.metric("Critical + High", f"{critical + high:,}")

if events.empty:
    st.info("No analyzed security events yet. Check the collector and vMaaS configuration.")
else:
    left, right = st.columns(2)
    with left:
        st.subheader("Attack types")
        attack_counts = events["attack_type"].fillna("Unknown").value_counts().rename_axis("Attack type")
        st.bar_chart(attack_counts)
    with right:
        st.subheader("Events over time")
        timeline = events.assign(timestamp=pd.to_datetime(events["timestamp"], utc=True, errors="coerce"))
        timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size()
        st.line_chart(timeline.rename("Events"))

    st.subheader("Security events")
    severities = ["Critical", "High", "Medium", "Low"]
    selected = st.multiselect("Filter severity", severities, default=severities)
    visible = events[events["severity"].isin(selected)].copy()
    visible["timestamp"] = pd.to_datetime(visible["timestamp"], utc=True, errors="coerce")
    st.dataframe(
        visible[["timestamp", "client_ip", "attack_type", "severity", "recommendation", "raw_log"]],
        use_container_width=True, hide_index=True,
        column_config={
            "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss z"),
            "client_ip": st.column_config.TextColumn("Client IP"),
            "attack_type": st.column_config.TextColumn("Attack type"),
            "severity": st.column_config.TextColumn("Severity"),
            "recommendation": st.column_config.TextColumn("vMaaS recommendation", width="large"),
            "raw_log": st.column_config.TextColumn("Raw log", width="large"),
        },
    )
