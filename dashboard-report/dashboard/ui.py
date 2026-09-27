"""Streamlit page composition for analyzer controls and security reporting."""
from datetime import datetime, time
import pandas as pd
import streamlit as st
from .config import APP_TZ, safe_int_env
from .database import (analyzer_status, fetch_events, fetch_token_usage, set_analyzer, set_language)
from .pdf_report import make_pdf_report
from .theme import render_theme
from .vmaas_client import fetch_vmaas_models

def run_app() -> None:
    render_theme()
    with st.container(border=True):
        st.subheader("Thông tin Đồ án Tốt nghiệp")
        st.markdown("# TÌM HIỂU VÀ XÂY DỰNG HỆ THỐNG WEB APPLICATION FIREWALL OPEN SOURCE TÍCH HỢP AI PHÂN TÍCH TẤN CÔNG")
        st.markdown("*AI-Enhanced Open Source WAF Security Assessment Lab*")
        st.markdown("**Đặng Thanh Lâm** (ID: 25410078)  ·  **Trương Tấn Đạt** (ID: 25410031)")

    st.title("🛡️ SOC Security Dashboard")
    now = datetime.now(APP_TZ)
    today = now.date()
    st.caption("Windows XP Security Center · Date/time range is interpreted in Asia/Ho_Chi_Minh (UTC+07:00)")

    with st.container(border=True):
        st.subheader("Select analyst time range")
        date_cols = st.columns(4)
        start_date = date_cols[0].date_input("From date", value=today, key="range_start_date")
        start_time = date_cols[1].time_input("From time", value=time.min, key="range_start_time")
        end_date = date_cols[2].date_input("To date", value=today, key="range_end_date")
        end_time = date_cols[3].time_input("To time", value=now.time().replace(microsecond=0), key="range_end_time")
    range_start = datetime.combine(start_date, start_time, tzinfo=APP_TZ)
    range_end = datetime.combine(end_date, end_time, tzinfo=APP_TZ)
    if range_end < range_start:
        st.error("End date/time must be after start date/time.")
        st.stop()

    try:
        events = fetch_events(range_start, range_end)
        analyzer = analyzer_status()
        usage_range = fetch_token_usage(range_start, range_end)
    except Exception as exc:
        st.error("Could not load dashboard data. Check PostgreSQL connection and schema.")
        st.exception(exc)
        st.stop()

    with st.container(border=True):
        st.subheader("Analyzer Control Panel")
        languages = ["Vietnamese", "English"]
        language_labels = {"Vietnamese": "Tiếng Việt", "English": "English"}
        selected_language = st.selectbox("AI recommendation language", languages,
                                         index=languages.index(analyzer["language"]),
                                         format_func=lambda value: language_labels[value])
        controls = st.columns([1, 1, 1.5, 1])
        if controls[0].button("▶ Start Analyzer", type="primary", use_container_width=True):
            try:
                set_analyzer(True, selected_language)
                st.success("Analyzer started/resumed. It scans today's log entries on schedule.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not start analyzer: {exc}")
        if controls[1].button("■ Stop Analyzer", use_container_width=True):
            try:
                set_analyzer(False, selected_language)
                st.success("Analyzer stopped.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not stop analyzer: {exc}")
        if controls[2].button("Save AI language", use_container_width=True):
            try:
                set_language(selected_language)
                st.success("AI recommendation language saved.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not save language: {exc}")
        if controls[3].button("↻ Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

        state_cols = st.columns(4)
        state_cols[0].metric("Process", analyzer["state"])
        state_cols[1].metric("Analyzed events", f"{analyzer['analyzed']:,}")
        state_cols[2].metric("Lines scanned", f"{analyzer['lines']:,}")
        state_cols[3].metric("Progress", f"{analyzer['progress']:.1f}%")
        st.progress(min(100, max(0, int(analyzer["progress"]))), text=f"Current file: {analyzer['file']}")
        st.caption(f"Last scan: {analyzer['last_scan'] or 'Not yet scanned'} · Scan date: {analyzer['scan_date']} · "
                   f"Interval: {safe_int_env('ANALYZER_SCAN_INTERVAL_SECONDS', 600)} seconds · "
                   f"Limit: {safe_int_env('ANALYZER_MAX_EVENTS_PER_SCAN', 3)} events per scan")
        if analyzer["error"]:
            st.warning(f"Last analyzer issue: {analyzer['error']}")

    with st.container(border=True):
        st.subheader("vMaaS Service & Token Usage")
        vmaas = fetch_vmaas_models()
        usage_cols = st.columns(5)
        usage_cols[0].metric("vMaaS API", vmaas["status"])
        usage_cols[1].metric("Selected model", vmaas.get("model") or "Not configured")
        usage_cols[2].metric("Prompt tokens · range", f"{usage_range[0]:,}")
        usage_cols[3].metric("Completion tokens · range", f"{usage_range[1]:,}")
        usage_cols[4].metric("Total tokens · range", f"{usage_range[2]:,}")
        st.caption(f"Endpoint: {vmaas.get('endpoint', '—')} · Available models: {len(vmaas.get('models', []))} · "
                   f"Model configured: {'yes' if vmaas.get('selected_found') else 'not confirmed'} · "
                   f"Per-response output cap: {safe_int_env('VMAAS_MAX_TOKENS', 700)} tokens")
        if vmaas.get("facts"):
            st.caption("Selected model info: " + " · ".join(vmaas["facts"]))
        if vmaas.get("models"):
            with st.expander("Available vMaaS models"):
                st.code("\n".join(vmaas["models"]), language=None)
        if vmaas.get("detail"):
            st.warning(vmaas["detail"])
        daily_budget = safe_int_env("VMAAS_DAILY_TOKEN_BUDGET", 0)
        budget_cols = st.columns(3)
        budget_cols[0].metric("Tokens used today", f"{usage_range[4]:,}")
        if daily_budget:
            budget_cols[1].metric("Configured daily budget", f"{daily_budget:,}")
            budget_cols[2].metric("Estimated budget remaining", f"{max(0, daily_budget - usage_range[4]):,}")
            st.caption("Remaining is calculated from VMAAS_DAILY_TOKEN_BUDGET in .env; it is a configured budget, not a live vendor quota.")
        else:
            budget_cols[1].metric("Account quota remaining", "Not exposed")
            budget_cols[2].metric("Daily budget remaining", "Configure budget")
            st.caption("The documented vMaaS models endpoint reports available models, not account quota remaining. Today's token use is measured from API usage responses.")

    total = len(events)
    critical = int((events["severity"].str.lower() == "critical").sum()) if total else 0
    high = int((events["severity"].str.lower() == "high").sum()) if total else 0
    st.subheader("Security Overview · selected range")
    metric_cols = st.columns(4)
    metric_cols[0].metric("Security events", f"{total:,}")
    metric_cols[1].metric("Critical", f"{critical:,}")
    metric_cols[2].metric("High", f"{high:,}")
    metric_cols[3].metric("Critical + High", f"{critical + high:,}")

    if not events.empty:
        chart_cols = st.columns(2)
        with chart_cols[0]:
            st.subheader("Attack categories")
            st.bar_chart(events["attack_type"].fillna("Unknown").value_counts().rename_axis("Attack type"))
        with chart_cols[1]:
            st.subheader("Events over time")
            timeline = events.assign(timestamp=pd.to_datetime(events["timestamp"], utc=True, errors="coerce"))
            timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size()
            st.line_chart(timeline.rename("Events"))

    st.subheader("Security Event Details")
    severities = ["Critical", "High", "Medium", "Low"]
    selected_severities = st.multiselect("Severity filter", severities, default=severities)
    visible = events[events["severity"].isin(selected_severities)].copy()
    if visible.empty:
        st.info("No events in the selected range/filter.")
    else:
        visible["timestamp"] = pd.to_datetime(visible["timestamp"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
        st.dataframe(
            visible[["timestamp", "client_ip", "attack_type", "severity", "recommendation", "raw_log"]],
            use_container_width=True, hide_index=True,
            column_config={
                "timestamp": st.column_config.DatetimeColumn("Timestamp (UTC+07)", format="YYYY-MM-DD HH:mm:ss"),
                "client_ip": st.column_config.TextColumn("Client IP"),
                "attack_type": st.column_config.TextColumn("Attack type"),
                "severity": st.column_config.TextColumn("Severity"),
                "recommendation": st.column_config.TextColumn("vMaaS recommendation", width="large"),
                "raw_log": st.column_config.TextColumn("Raw log", width="large"),
            },
        )

    report_pdf = make_pdf_report(visible, range_start, range_end, usage_range)
    st.download_button(
        "📄 Download PDF Report", data=report_pdf,
        file_name=f"soc-security-report-{start_date:%Y%m%d}-{end_date:%Y%m%d}.pdf",
        mime="application/pdf", disabled=visible.empty,
    )
    if len(visible) > 300:
        st.caption("PDF includes the newest 300 visible events; dashboard table shows the selected range (up to 10,000 rows).")

    st.markdown("<div class='xp-footer'>Start · SOC Security Dashboard · vMaaS connected status and usage</div>", unsafe_allow_html=True)
