"""Navigation and page composition for the SOC security monitoring console."""
from datetime import datetime, time
import os

import pandas as pd
import streamlit as st

from .config import APP_TZ, safe_int_env
from .database import analyzer_status, fetch_events
from .monitoring import change_analyzer_state, render_analysis_settings, render_live_console, render_process_controls
from .pdf_report import make_pdf_report
from .security_insights import suspicious_ip_candidates
from .theme import render_theme

PAGES = ["Overview", "Monitoring", "Events", "Configuration", "Reports"]


def _render_brand() -> None:
    st.markdown("""
    <div class="app-brand">
      <div class="brand-mark">BW</div>
      <div><div class="brand-name">BUNKERWEB <span>SECURITY MONITOR</span></div>
      <div class="brand-subtitle">AI-assisted web attack analysis</div></div>
    </div>
    """, unsafe_allow_html=True)


def _render_navigation() -> str:
    with st.sidebar:
        st.markdown("<div class='side-label'>WORKSPACE</div>", unsafe_allow_html=True)
        selected = st.radio("Navigation", PAGES, label_visibility="collapsed", key="navigation")
        st.markdown("<div class='side-label'>PROJECT</div>", unsafe_allow_html=True)
        st.caption("AI-Enhanced Open Source WAF Security Assessment Lab")
        st.markdown("<div class='side-footer'>Đặng Thanh Lâm · Trương Tấn Đạt</div>", unsafe_allow_html=True)
    return selected


def _render_time_filter() -> tuple[datetime, datetime, object, object]:
    now = datetime.now(APP_TZ)
    with st.container(border=True):
        st.markdown("<div class='section-eyebrow'>TIME RANGE · UTC+07</div>", unsafe_allow_html=True)
        fields = st.columns(4)
        start_date = fields[0].date_input("From", value=now.date(), key="range_start_date")
        start_time = fields[1].time_input("Start time", value=time.min, key="range_start_time")
        end_date = fields[2].date_input("To", value=now.date(), key="range_end_date")
        end_time = fields[3].time_input("End time", value=now.time().replace(microsecond=0), key="range_end_time")
    start = datetime.combine(start_date, start_time, tzinfo=APP_TZ)
    end = datetime.combine(end_date, end_time, tzinfo=APP_TZ)
    if end < start:
        st.error("End date/time must be after start date/time.")
        st.stop()
    return start, end, start_date, end_date


def _severity_counts(events: pd.DataFrame) -> tuple[int, int, int]:
    severity = events["severity"].astype(str).str.lower() if not events.empty else pd.Series(dtype=str)
    critical = int((severity == "critical").sum())
    high = int((severity == "high").sum())
    return critical, high, critical + high


def _render_overview(events: pd.DataFrame, analyzer: dict) -> None:
    st.markdown("## Security overview")
    critical, high, urgent = _severity_counts(events)
    cards = st.columns(4)
    cards[0].metric("Security events", f"{len(events):,}")
    cards[1].metric("Critical", f"{critical:,}")
    cards[2].metric("High", f"{high:,}")
    cards[3].metric("Analyzer", analyzer["state"])

    chart_col, ip_col = st.columns([1.2, 1])
    with chart_col:
        with st.container(border=True):
            st.markdown("### Event activity")
            if events.empty:
                st.info("No analyzed security events in this time range.")
            else:
                timeline = events.assign(timestamp=pd.to_datetime(events["timestamp"], utc=True, errors="coerce"))
                timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size()
                st.area_chart(timeline.rename("Events"), color="#24a6d9")
    with ip_col:
        with st.container(border=True):
            st.markdown("### IPs to review")
            candidates = suspicious_ip_candidates(events)
            st.caption("Candidates are ranked by repeated security events or any High/Critical event; verify before blocking.")
            if candidates.empty:
                st.info("No IP met the review criteria in this range.")
            else:
                st.dataframe(candidates, hide_index=True, use_container_width=True,
                             column_config={"client_ip": "Client IP", "event_count": "Events",
                                            "high_critical": "High / critical", "attack_types": "Attack types",
                                            "review_reason": "Why flagged",
                                            "last_seen": st.column_config.DatetimeColumn("Last seen", format="YYYY-MM-DD HH:mm")})

    if not events.empty:
        with st.container(border=True):
            st.markdown("### Attack categories")
            st.bar_chart(events["attack_type"].fillna("Unknown").value_counts().rename_axis("Attack type"), color="#24a6d9")


def _render_monitoring(analyzer: dict) -> None:
    st.markdown("## Process monitoring")
    state_col, action_col = st.columns([3, 1])
    with state_col:
        render_process_controls(analyzer)
    with action_col:
        with st.container(border=True):
            st.markdown("### Controls")
            selected_language = st.selectbox(
                "AI recommendation language", ["Vietnamese", "English"],
                index=0 if analyzer["language"] == "Vietnamese" else 1,
                format_func=lambda value: "Tiếng Việt" if value == "Vietnamese" else value,
                key="monitor-language",
            )
            if st.button("▶ Start analyzer", type="primary", use_container_width=True, disabled=analyzer["enabled"]):
                change_analyzer_state(True, selected_language)
                st.rerun()
            if st.button("■ Stop analyzer", use_container_width=True, disabled=not analyzer["enabled"]):
                change_analyzer_state(False, selected_language)
                st.rerun()
            st.caption("Reads configured BunkerWeb logs and sends matching security events to AI analysis.")
    render_live_console(analyzer)


def _render_events(events: pd.DataFrame) -> None:
    st.markdown("## Security events")
    chosen = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"],
                            default=["Critical", "High", "Medium", "Low"])
    visible = events[events["severity"].isin(chosen)].copy()
    if visible.empty:
        st.info("No events match the selected severities and time range.")
        return
    visible["timestamp"] = pd.to_datetime(visible["timestamp"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
    st.dataframe(visible[["timestamp", "client_ip", "attack_type", "severity", "recommendation", "raw_log"]],
                 use_container_width=True, hide_index=True,
                 column_config={"timestamp": st.column_config.DatetimeColumn("Time (UTC+07)", format="YYYY-MM-DD HH:mm:ss"),
                                "client_ip": "Client IP", "attack_type": "Attack type", "severity": "Severity",
                                "recommendation": st.column_config.TextColumn("AI recommendation", width="large"),
                                "raw_log": st.column_config.TextColumn("Source log", width="large")})


def _render_configuration(analyzer: dict) -> None:
    st.markdown("## Configuration")
    left, right = st.columns([1, 1.2])
    with left:
        render_analysis_settings(analyzer)
    with right:
        with st.container(border=True):
            st.markdown("### Collector settings")
            settings = [
                ("Log source", os.getenv("BUNKERWEB_LOG_GLOB", "/var/log/bunkerweb/access.log")),
                ("Scan interval", f"{safe_int_env('ANALYZER_SCAN_INTERVAL_SECONDS', 600)} seconds"),
                ("Maximum events per scan", str(safe_int_env("ANALYZER_MAX_EVENTS_PER_SCAN", 3))),
                ("Maximum lines per scan", f"{safe_int_env('ANALYZER_MAX_LINES_PER_SCAN', 2000):,}"),
                ("Control polling", f"{safe_int_env('ANALYZER_CONTROL_POLL_SECONDS', 5)} seconds"),
                ("Log timezone", "Asia/Ho_Chi_Minh (UTC+07:00)"),
            ]
            for label, value in settings:
                name_col, value_col = st.columns([1, 1.3])
                name_col.caption(label)
                value_col.code(value, language=None)
            st.caption("Runtime values come from the container environment. Change them in .env and recreate the service to apply.")


def _render_reports(events: pd.DataFrame, start: datetime, end: datetime, start_date, end_date) -> None:
    st.markdown("## Security report")
    critical, high, urgent = _severity_counts(events)
    cards = st.columns(4)
    cards[0].metric("Events", f"{len(events):,}")
    cards[1].metric("Critical", f"{critical:,}")
    cards[2].metric("High", f"{high:,}")
    cards[3].metric("Critical + High", f"{urgent:,}")
    st.caption(f"Report window: {start:%Y-%m-%d %H:%M} — {end:%Y-%m-%d %H:%M} (UTC+07:00)")
    report_pdf = make_pdf_report(events, start, end)
    st.download_button("Download PDF report", data=report_pdf,
                       file_name=f"soc-security-report-{start_date:%Y%m%d}-{end_date:%Y%m%d}.pdf",
                       mime="application/pdf", disabled=events.empty)


def run_app() -> None:
    render_theme()
    _render_brand()
    page = _render_navigation()
    start, end, start_date, end_date = _render_time_filter()
    try:
        events = fetch_events(start, end)
        analyzer = analyzer_status()
    except Exception as exc:
        st.error("Unable to load monitoring data. Check PostgreSQL and DB configuration.")
        st.exception(exc)
        st.stop()

    if page == "Overview":
        _render_overview(events, analyzer)
    elif page == "Monitoring":
        _render_monitoring(analyzer)
    elif page == "Events":
        _render_events(events)
    elif page == "Configuration":
        _render_configuration(analyzer)
    elif page == "Reports":
        _render_reports(events, start, end, start_date, end_date)

    st.markdown("<div class='report-footer'>BunkerWeb Security Monitor · SOC Assessment Lab</div>", unsafe_allow_html=True)
