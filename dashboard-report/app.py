"""SOC dashboard for AI-analyzed BunkerWeb security events."""
import os

import pandas as pd
import psycopg2
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
st.set_page_config(page_title="SOC Security Dashboard", page_icon="🛡️", layout="wide")


def fetch_events() -> pd.DataFrame:
    with psycopg2.connect(
        host=os.getenv("DB_HOST", "postgres_db"), port=int(os.getenv("DB_PORT", "5432")),
        user=os.getenv("DB_USER", "security"), password=os.getenv("DB_PASSWORD", ""),
        dbname=os.getenv("DB_NAME", "security_events"), connect_timeout=8,
    ) as conn:
        return pd.read_sql_query(
            "SELECT id, timestamp, client_ip, raw_log, attack_type, severity, recommendation "
            "FROM security_events ORDER BY timestamp DESC LIMIT 5000", conn,
        )


st.title("🛡️ SOC Security Dashboard")
st.caption("BunkerWeb events analyzed by vMaaS")
if st.button("↻ Refresh", type="primary"):
    st.cache_data.clear()


@st.cache_data(ttl=30, show_spinner="Loading security events...")
def load_events() -> pd.DataFrame:
    return fetch_events()


try:
    events = load_events()
except Exception as exc:
    st.error("Could not connect to PostgreSQL. Check the database service and DB_* configuration.")
    st.exception(exc)
    st.stop()

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
