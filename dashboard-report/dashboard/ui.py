"""SOC dashboard navigation, filters, monitoring views, and reports."""
from datetime import datetime, time
import html
import os

import pandas as pd
import plotly.express as px
import streamlit as st

from .config import APP_TZ, safe_int_env
from .database import (
    analyzer_status, database_status, fetch_blocking_ips, fetch_console_logs,
    fetch_events, fetch_waf_metrics, set_analyzer, set_language,
)
from .monitoring import render_process_controls
from .pdf_report import make_pdf_report
from .theme import render_theme

PAGES = ["Overview", "Monitoring", "Events", "Configuration", "Reports"]
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
CHART_COLORS = ["#f87171", "#fb923c", "#fbbf24", "#34d399", "#38bdf8", "#a78bfa"]


def _render_brand() -> None:
    st.markdown("""
    <div class="brand"><div class="brand-mark">BW</div><div>
    <div class="brand-name">BUNKERWEB <span>SOC MONITOR</span></div>
    <div class="brand-subtitle">AI-assisted web attack analysis</div></div></div>
    """, unsafe_allow_html=True)


def _sidebar_inputs(db_ok: bool, db_message: str):
    with st.sidebar:
        st.markdown("""
        <div class="side-brand"><div class="brand-mark">BW</div><div>
        <div class="side-brand-title">BUNKERWEB</div><div class="side-brand-caption">SOC SECURITY MONITOR</div>
        </div></div>
        """, unsafe_allow_html=True)
        st.markdown("<div class='side-label'>SYSTEM STATUS</div>", unsafe_allow_html=True)
        badge = "db-live" if db_ok else "db-down"
        symbol = "●" if db_ok else "●"
        st.markdown(f"<div class='{badge}'>{symbol} DATABASE {html.escape(db_message.upper())}</div>", unsafe_allow_html=True)
        st.markdown("<div class='side-label'>NAVIGATION</div>", unsafe_allow_html=True)
        page = st.radio("Sections", PAGES, label_visibility="collapsed", key="soc-navigation")
    return page


def _page_time_range(page: str):
    now = datetime.now(APP_TZ)
    key = page.lower()
    with st.container(border=True):
        st.markdown("<div class='section-eyebrow'>REPORT WINDOW · ASIA/HO_CHI_MINH (UTC+07)</div>", unsafe_allow_html=True)
        fields = st.columns([1.1, 1, 1.1, 1, .75])
        from_date = fields[0].date_input("From date", value=now.date(), key=f"{key}-from-date")
        from_time = fields[1].time_input("From time", value=time.min, key=f"{key}-from-time")
        to_date = fields[2].date_input("To date", value=now.date(), key=f"{key}-to-date")
        to_time = fields[3].time_input("To time", value=now.time().replace(microsecond=0), key=f"{key}-to-time")
        if fields[4].button("↻ Refresh", use_container_width=True, key=f"{key}-refresh"):
            st.cache_data.clear()
            st.rerun()
    start = datetime.combine(from_date, from_time, tzinfo=APP_TZ)
    end = datetime.combine(to_date, to_time, tzinfo=APP_TZ)
    if end < start:
        st.error("The end of the selected time range must be after its start.")
        st.stop()
    return start, end, from_date, to_date


def _render_page_heading(page: str) -> None:
    descriptions = {
        "Overview": "Attack activity, blocked requests and source IPs that need analyst review.",
        "Monitoring": "Analyzer process health, scan progress and live collector output.",
        "Events": "Search and investigate AI-enriched security incidents from BunkerWeb logs.",
        "Configuration": "Review collector runtime settings and recommendation language.",
        "Reports": "Export the selected security incident set for audit and review.",
    }
    st.markdown(
        f"<div class='page-heading'><div class='page-eyebrow'>SECURITY OPERATIONS CENTER</div>"
        f"<h1>{page}</h1><p>{descriptions[page]}</p></div>", unsafe_allow_html=True,
    )


def _filtered_events(events: pd.DataFrame, page: str) -> pd.DataFrame:
    with st.container(border=True):
        st.markdown("<div class='section-eyebrow'>INCIDENT FILTERS</div>", unsafe_allow_html=True)
        filter_cols = st.columns([1, 1.3, 1.1])
        present_severities = [value for value in SEVERITY_ORDER if value in set(events["severity"].dropna())]
        selected_severities = filter_cols[0].multiselect("Severity", present_severities, default=present_severities, key=f"{page}-severity-filter")
        attacks = sorted(str(value) for value in events["attack_type"].dropna().unique())
        selected_attacks = filter_cols[1].multiselect("Attack type", attacks, default=attacks, key=f"{page}-attack-filter")
        ip_search = filter_cols[2].text_input("Source IP", placeholder="Search IP address…", key=f"{page}-source-ip-filter").strip().lower()
    filtered = events[events["severity"].isin(selected_severities) & events["attack_type"].astype(str).isin(selected_attacks)].copy()
    if ip_search:
        filtered = filtered[filtered["client_ip"].fillna("").astype(str).str.lower().str.contains(ip_search, regex=False)]
    return filtered


def _metric_row(events: pd.DataFrame, waf: dict) -> tuple[int, int]:
    severity = events["severity"].astype(str).str.lower() if not events.empty else pd.Series(dtype=str)
    critical_high = int(severity.isin(["critical", "high"]).sum())
    cards = st.columns(4)
    cards[0].metric("Security events", f"{len(events):,}")
    cards[1].metric("Critical / High", f"{critical_high:,}")
    cards[2].metric("Unique attackers", f"{waf['unique_attackers']:,}")
    rate_label = f"{waf['block_rate']:.1f}%" if waf["total_requests"] else "No data"
    cards[3].metric("WAF block rate", rate_label, help="Blocked access.log requests divided by observed access.log requests in this time range.")
    st.caption(f"WAF observation: {waf['blocked_requests']:,} blocked of {waf['total_requests']:,} access requests · metrics use the selected time window.")
    return critical_high, len(events)


def _render_attack_donut(events: pd.DataFrame) -> None:
    if events.empty:
        st.info("No analyzed security incidents in this time range.")
        return
    counts = events["attack_type"].fillna("Unknown").value_counts().rename_axis("Attack type").reset_index(name="Incidents")
    figure = px.pie(counts, names="Attack type", values="Incidents", hole=.62,
                    color_discrete_sequence=CHART_COLORS)
    figure.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                         margin=dict(l=8, r=8, t=8, b=8), legend=dict(orientation="h", y=-.08),
                         font_color="#dce5ef", height=310)
    figure.update_traces(textposition="inside", textinfo="percent", marker_line_color="#111827", marker_line_width=2)
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})


def _render_attack_timeline(events: pd.DataFrame) -> None:
    if events.empty:
        st.info("No events to chart.")
        return
    timeline = events.assign(timestamp=pd.to_datetime(events["timestamp"], utc=True, errors="coerce"))
    timeline = timeline.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size()
    frame = timeline.rename("Incidents").reset_index()
    figure = px.area(frame, x="timestamp", y="Incidents", color_discrete_sequence=["#38bdf8"])
    figure.update_traces(line=dict(width=2), fillcolor="rgba(56,189,248,.18)")
    figure.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                         margin=dict(l=8, r=8, t=8, b=8), height=310, font_color="#dce5ef",
                         xaxis_title=None, yaxis_title="Incidents", showlegend=False)
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})


def _render_ip_matrix(start: datetime, end: datetime, ip_search: str = "") -> None:
    with st.container(border=True):
        st.markdown("### Blocked source IPs")
        st.caption("Derived from observed access.log requests flagged by WAF/security status or markers.")
        rows = fetch_blocking_ips(start, end, 100, ip_search)
        if not rows:
            st.info("No blocked source IPs were observed in the selected range.")
            return
        frame = pd.DataFrame(rows, columns=["Source IP", "Blocked requests", "Last seen"])
        frame["Review"] = frame["Blocked requests"].map(lambda count: "Repeated" if count >= 3 else "Review")
        st.dataframe(frame, use_container_width=True, hide_index=True,
                     column_config={"Source IP": st.column_config.TextColumn("Source IP"),
                                    "Blocked requests": st.column_config.NumberColumn("Blocked requests", format="%d"),
                                    "Last seen": st.column_config.DatetimeColumn("Last seen", format="YYYY-MM-DD HH:mm:ss"),
                                    "Review": st.column_config.TextColumn("Triage")})


def _render_overview(events: pd.DataFrame, waf: dict, start: datetime, end: datetime) -> None:
    st.markdown("### Metrics overview")
    st.caption("Traffic cards use independently observed access.log data. Charts and incident lists reflect the selected severity, attack type and source IP filters.")
    _metric_row(events, waf)
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("### Attack distribution")
            _render_attack_donut(events)
    with right:
        with st.container(border=True):
            st.markdown("### Incident trend")
            _render_attack_timeline(events)
    _render_ip_matrix(start, end, st.session_state.get("Overview-source-ip-filter", "").strip())


def _render_console() -> None:
    @st.fragment(run_every="3s")
    def console_fragment() -> None:
        logs = fetch_console_logs(120)
        if not logs:
            st.info("No analyzer output yet. Start the analyzer to stream collector activity here.")
            return
        lines = []
        for created_at, level, logger_name, message in logs:
            stamp = created_at.astimezone(APP_TZ).strftime("%Y-%m-%d %H:%M:%S") if created_at else "--"
            level_class = str(level).lower() if str(level).lower() in {"error", "warning", "info", "critical"} else "info"
            lines.append(
                f'<div class="console-line"><span class="console-time">[{stamp}]</span> '
                f'<span class="console-{level_class}">{html.escape(str(level).upper())}</span> '
                f'<span class="console-source">{html.escape(str(logger_name))}</span> · '
                f'{html.escape(str(message))}</div>'
            )
        st.markdown('<div class="console">' + "".join(lines) + "</div>", unsafe_allow_html=True)

    console_fragment()


def _render_monitoring(analyzer: dict) -> None:
    st.markdown("### Analyzer process")
    render_process_controls(analyzer)
    with st.container(border=True):
        st.markdown("### Process controls")
        columns = st.columns([2, 1, 1, 2])
        language = columns[0].selectbox("AI recommendation language", ["Vietnamese", "English"],
                                        index=0 if analyzer["language"] == "Vietnamese" else 1,
                                        format_func=lambda value: "Tiếng Việt" if value == "Vietnamese" else value,
                                        key="monitor-language")
        if columns[1].button("▶ Start analyzer", type="primary", use_container_width=True, disabled=analyzer["enabled"]):
            set_analyzer(True, language)
            st.rerun()
        if columns[2].button("■ Stop analyzer", use_container_width=True, disabled=not analyzer["enabled"]):
            set_analyzer(False, language)
            st.rerun()
        columns[3].caption("Security events are analyzed on the configured scan schedule.")
    with st.container(border=True):
        st.markdown("### Live analyzer console")
        st.caption("Auto-refreshes every 3 seconds while this page is open.")
        _render_console()


def _render_incident_inspector(event: pd.Series) -> None:
    st.markdown(f"### AI incident inspector · {event.get('attack_type', 'Security incident')}")
    st.markdown(f"**Severity:** <span class='severity-{str(event.get('severity', 'info')).lower()}'>{html.escape(str(event.get('severity') or 'Info'))}</span>　·　**Source IP:** `{html.escape(str(event.get('client_ip') or 'Unknown'))}`", unsafe_allow_html=True)
    raw_col, recommendation_col = st.columns([1, 1.2])
    with raw_col:
        with st.container(border=True):
            st.markdown("#### Raw log payload")
            st.code(str(event.get("raw_log") or "No raw log payload stored."), language=None)
    with recommendation_col:
        with st.container(border=True):
            st.markdown("#### Báo cáo đề xuất khắc phục từ AI")
            recommendation = str(event.get("recommendation") or "Chưa có khuyến nghị được lưu.")
            st.markdown(recommendation)


def _render_events(events: pd.DataFrame) -> None:
    st.markdown("### Security events matrix")
    if events.empty:
        st.info("No analyzed security events match the selected filters.")
        return
    display = events.copy().reset_index(drop=True)
    display["timestamp"] = pd.to_datetime(display["timestamp"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
    visible_columns = ["timestamp", "client_ip", "attack_type", "severity"]
    severity_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#34d399", "info": "#38bdf8"}
    styled_events = display[visible_columns].style.map(
        lambda value: f"color: {severity_colors.get(str(value).lower(), '#e5eaf2')}; font-weight: 700",
        subset=["severity"],
    )
    selection = st.dataframe(
        styled_events, use_container_width=True, hide_index=True, height=390,
        on_select="rerun", selection_mode="single-row", key="security-event-matrix",
        column_config={"timestamp": st.column_config.DatetimeColumn("Timestamp (UTC+07)", format="YYYY-MM-DD HH:mm:ss"),
                       "client_ip": st.column_config.TextColumn("Source IP"),
                       "attack_type": st.column_config.TextColumn("Attack type"),
                       "severity": st.column_config.TextColumn("Severity")},
    )
    selected_rows = selection.selection.rows
    if selected_rows and 0 <= selected_rows[0] < len(display):
        _render_incident_inspector(display.iloc[selected_rows[0]])
    else:
        st.caption("Select a row to open its raw payload and AI incident analysis.")


def _render_configuration(analyzer: dict) -> None:
    st.markdown("### Analysis configuration")
    left, right = st.columns([1, 1.2])
    with left:
        with st.container(border=True):
            st.markdown("#### AI recommendation language")
            current = analyzer["language"]
            chosen = st.selectbox("Incident recommendation language", ["Vietnamese", "English"],
                                  index=0 if current == "Vietnamese" else 1,
                                  format_func=lambda value: "Tiếng Việt" if value == "Vietnamese" else value,
                                  key="configured-language")
            if st.button("Save language", key="save-language"):
                set_language(chosen)
                st.success("Recommendation language saved.")
                st.rerun()
    with right:
        with st.container(border=True):
            st.markdown("#### Collector runtime")
            settings = [
                ("BunkerWeb log source", os.getenv("BUNKERWEB_LOG_GLOB", "/var/log/bunkerweb/access.log")),
                ("Scan interval", f"{safe_int_env('ANALYZER_SCAN_INTERVAL_SECONDS', 600)} seconds"),
                ("Events per scan", str(safe_int_env("ANALYZER_MAX_EVENTS_PER_SCAN", 3))),
                ("Lines per scan", f"{safe_int_env('ANALYZER_MAX_LINES_PER_SCAN', 2000):,}"),
                ("Control polling", f"{safe_int_env('ANALYZER_CONTROL_POLL_SECONDS', 5)} seconds"),
            ]
            for label, value in settings:
                name, val = st.columns([1, 1.4])
                name.caption(label)
                val.code(value, language=None)
            st.caption("Change runtime values in .env, then recreate the collector service.")


def _render_reports(events: pd.DataFrame, start: datetime, end: datetime, from_date, to_date) -> None:
    st.markdown("### Audit export")
    cards = st.columns(3)
    counts = events["severity"].astype(str).str.lower() if not events.empty else pd.Series(dtype=str)
    cards[0].metric("Filtered incidents", f"{len(events):,}")
    cards[1].metric("Critical", f"{int((counts == 'critical').sum()):,}")
    cards[2].metric("High", f"{int((counts == 'high').sum()):,}")
    if events.empty:
        st.info("No filtered incidents to export.")
        return
    export_columns = ["timestamp", "client_ip", "attack_type", "severity", "recommendation", "raw_log"]
    csv_data = events[export_columns].to_csv(index=False).encode("utf-8-sig")
    pdf_data = make_pdf_report(events, start, end)
    left, right = st.columns(2)
    left.download_button("Download filtered CSV", csv_data,
                         file_name=f"soc-events-{from_date:%Y%m%d}-{to_date:%Y%m%d}.csv", mime="text/csv",
                         use_container_width=True)
    right.download_button("Download PDF report", pdf_data,
                          file_name=f"soc-report-{from_date:%Y%m%d}-{to_date:%Y%m%d}.pdf",
                          mime="application/pdf", use_container_width=True)


def run_app() -> None:
    render_theme()
    db_ok, db_message = database_status()
    page = _sidebar_inputs(db_ok, db_message)
    if not db_ok:
        st.error(f"PostgreSQL is unavailable ({db_message}). Check the database service and DB configuration.")
        st.stop()

    _render_page_heading(page)
    timed_pages = {"Overview", "Events", "Reports"}
    if page in timed_pages:
        start, end, from_date, to_date = _page_time_range(page)
    else:
        start = end = from_date = to_date = None

    try:
        analyzer = analyzer_status()
        if page in timed_pages:
            all_events = fetch_events(start, end)
            events = _filtered_events(all_events, page)
        else:
            events = pd.DataFrame()
        waf = fetch_waf_metrics(start, end) if page == "Overview" else None
    except Exception as exc:
        st.error("Could not load SOC data. Check PostgreSQL connectivity and schema.")
        st.exception(exc)
        st.stop()
    if page == "Overview":
        _render_overview(events, waf, start, end)
    elif page == "Monitoring":
        _render_monitoring(analyzer)
    elif page == "Events":
        _render_events(events)
    elif page == "Configuration":
        _render_configuration(analyzer)
    elif page == "Reports":
        _render_reports(events, start, end, from_date, to_date)
    st.markdown("<div class='report-footer'>SOC Security Monitor · Đặng Thanh Lâm · Trương Tấn Đạt</div>", unsafe_allow_html=True)
