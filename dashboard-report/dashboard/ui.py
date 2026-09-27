"""Streamlit page composition for analyzer controls and security reporting."""
from datetime import datetime, time
import html
import pandas as pd
import streamlit as st
from .config import APP_TZ, safe_int_env
from .database import analyzer_status, fetch_console_logs, fetch_events, set_analyzer, set_language
from .pdf_report import make_pdf_report
from .theme import render_theme

def run_app() -> None:
    render_theme()
    st.markdown("""
    <div class="report-heading">
      <div class="report-kicker">Graduation project · Security assessment</div>
      <div class="report-title">SOC Security Assessment Report</div>
      <div class="report-subtitle">Tìm hiểu và xây dựng hệ thống Web Application Firewall open source tích hợp AI phân tích tấn công</div>
      <div class="report-meta"><i>AI-Enhanced Open Source WAF Security Assessment Lab</i><br>
      Đặng Thanh Lâm (ID: 25410078) &nbsp;·&nbsp; Trương Tấn Đạt (ID: 25410031)</div>
    </div>
    """, unsafe_allow_html=True)
    now = datetime.now(APP_TZ)
    today = now.date()

    with st.container(border=True):
        date_title, date_tz = st.columns([3, 2])
        date_title.subheader("Report period")
        date_tz.caption("All times shown in Asia/Ho_Chi_Minh (UTC+07:00)")
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
    except Exception as exc:
        st.error("Could not load dashboard data. Check PostgreSQL connection and schema.")
        st.exception(exc)
        st.stop()

    with st.container(border=True):
        st.subheader("AI analysis")
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

    @st.fragment(run_every="3s")
    def live_console() -> None:
        with st.container(border=True):
            console_title, console_state = st.columns([3, 1])
            console_title.subheader("Analyzer console")
            console_state.caption("● Live · refreshes every 3 seconds" if analyzer["enabled"] else "Analyzer stopped")
            records = fetch_console_logs(100)
            if not records:
                st.caption("No analyzer output yet. Start AI analysis to see collector activity here.")
                return
            lines = []
            for created_at, level, logger_name, message in records:
                stamp = created_at.astimezone(APP_TZ).strftime("%H:%M:%S") if created_at else "--:--:--"
                lines.append(
                    f'<div class="console-line"><span class="console-time">[{stamp}]</span> '
                    f'<span class="console-{str(level).lower()}">{html.escape(str(level))}</span> '
                    f'<span>{html.escape(str(logger_name))}</span> · {html.escape(str(message))}</div>'
                )
            st.markdown('<div class="console">' + "".join(lines) + "</div>", unsafe_allow_html=True)

    live_console()

    total = len(events)
    critical = int((events["severity"].str.lower() == "critical").sum()) if total else 0
    high = int((events["severity"].str.lower() == "high").sum()) if total else 0
    st.subheader("Security overview")
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

    st.subheader("Analyzed security events")
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

    report_pdf = make_pdf_report(visible, range_start, range_end)
    st.download_button(
        "📄 Download PDF Report", data=report_pdf,
        file_name=f"soc-security-report-{start_date:%Y%m%d}-{end_date:%Y%m%d}.pdf",
        mime="application/pdf", disabled=visible.empty,
    )
    if len(visible) > 300:
        st.caption("PDF includes the newest 300 visible events; dashboard table shows the selected range (up to 10,000 rows).")

    st.markdown("<div class='report-footer'>SOC Security Assessment Report · Generated from BunkerWeb events and vMaaS analysis</div>", unsafe_allow_html=True)
