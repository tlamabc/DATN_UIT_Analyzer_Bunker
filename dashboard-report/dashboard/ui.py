"""SOC dashboard navigation, filters, monitoring views, and reports."""
from datetime import datetime, timedelta
import html

import pandas as pd
import plotly.express as px
import streamlit as st

from .config import APP_TZ
from .database import (
    analyzer_status, database_status, fetch_console_logs, fetch_events,
    set_analyzer, set_language,
)
from .monitoring import render_process_controls
from .pdf_report import make_pdf_report
from .security_insights import suspicious_ip_candidates
from .theme import render_theme

PAGES = ["Overview", "Monitoring", "Events", "Reports"]
PAGE_LABELS = {"Overview": "Tổng quan", "Monitoring": "Giám sát", "Events": "Sự kiện", "Reports": "Báo cáo"}
PAGE_SLUGS = {"Overview": "overview", "Monitoring": "monitoring", "Events": "events", "Reports": "reports"}
PAGE_ICONS = {"Overview": "▦", "Monitoring": "◷", "Events": "≡", "Reports": "▤"}
RISK_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
CHART_COLORS = ["#f87171", "#fb923c", "#fbbf24", "#34d399", "#38bdf8", "#a78bfa"]
LIVE_WINDOWS = {"15 phút": timedelta(minutes=15), "1 giờ": timedelta(hours=1),
                "24 giờ": timedelta(hours=24), "7 ngày": timedelta(days=7)}


def _render_brand() -> None:
    st.markdown("""
    <div class="brand"><div class="brand-mark">BW</div><div>
    <div class="brand-name">BUNKERWEB <span>SOC MONITOR</span></div>
    <div class="brand-subtitle">AI-assisted web attack analysis</div></div></div>
    """, unsafe_allow_html=True)


def _sidebar_inputs(db_ok: bool, db_message: str):
    page_slugs = {slug: page for page, slug in PAGE_SLUGS.items()}
    selected = str(st.query_params.get("page", "overview")).lower()
    return page_slugs.get(selected, "Overview")


def _rolling_window(page: str) -> tuple[datetime, datetime, str]:
    selected = st.selectbox("Cửa sổ dữ liệu", list(LIVE_WINDOWS), index=2, key=f"{page}-live-window")
    end = datetime.now(APP_TZ)
    return end - LIVE_WINDOWS[selected], end, selected


def _render_page_heading(page: str) -> None:
    descriptions = {
        "Overview": "Ưu tiên sự kiện AI, dấu hiệu tấn công lặp lại và hành động cần analyst xác minh.",
        "Monitoring": "Tình trạng bộ phân tích AI, tiến độ đọc log và hoạt động thu thập trực tiếp.",
        "Events": "Điều tra sự kiện BunkerWeb đã được AI phân loại, giải thích và đề xuất xử lý.",
        "Reports": "Báo cáo sự cố cập nhật liên tục, phục vụ bàn giao và kiểm toán SOC.",
    }
    with st.container(key="soc-sticky-header"):
        status_class = "db-live" if st.session_state.get("db-connected", True) else "db-down"
        status_label = "ĐANG KẾT NỐI" if st.session_state.get("db-connected", True) else "MẤT KẾT NỐI"
        st.markdown(f"<div class='soc-topline'><strong>BUNKERWEB · SOC</strong><span class='{status_class}'>● CƠ SỞ DỮ LIỆU · {status_label}</span></div>",
                    unsafe_allow_html=True)
        nav_items = []
        for option in PAGES:
            active = " is-active" if option == page else ""
            nav_items.append(
                f'<a class="soc-nav-item{active}" href="?page={PAGE_SLUGS[option]}" '
                f'aria-current="{"page" if option == page else "false"}" title="{html.escape(PAGE_LABELS[option])}">'
                f'<span class="soc-nav-icon" aria-hidden="true">{PAGE_ICONS[option]}</span>'
                f'<span class="soc-nav-label">{html.escape(PAGE_LABELS[option])}</span></a>'
            )
        st.markdown('<nav class="soc-menubar" aria-label="Điều hướng SOC">' + "".join(nav_items) + "</nav>",
                    unsafe_allow_html=True)
        st.markdown(
            f"<div class='page-heading'><div class='page-eyebrow'>TRUNG TÂM ĐIỀU HÀNH AN NINH</div>"
            f"<h1>{PAGE_LABELS[page]}</h1><p>{descriptions[page]}</p></div>", unsafe_allow_html=True,
        )


def _filtered_events(events: pd.DataFrame, page: str) -> pd.DataFrame:
    with st.container(border=True):
        st.markdown("<div class='section-eyebrow'>BỘ LỌC SỰ KIỆN</div>", unsafe_allow_html=True)
        filter_cols = st.columns(2)
        present_risk_scores = [value for value in RISK_ORDER if value in set(events["risk_score"].dropna())]
        selected_risk_scores = filter_cols[0].multiselect("Mức độ rủi ro", present_risk_scores, default=present_risk_scores, key=f"{page}-risk-filter")
        classifications = sorted(str(value) for value in events["classification"].dropna().unique())
        selected_classifications = filter_cols[1].multiselect("Phân loại", classifications, default=classifications, key=f"{page}-classification-filter")
        ip_search = st.text_input("Địa chỉ IP nguồn", placeholder="Tìm IP…", key=f"{page}-source-ip-filter").strip().lower()
    filtered = events[events["risk_score"].isin(selected_risk_scores) & events["classification"].astype(str).isin(selected_classifications)].copy()
    if ip_search:
        filtered = filtered[filtered["client_ip"].fillna("").astype(str).str.lower().str.contains(ip_search, regex=False)]
    return filtered


def _metric_row(events: pd.DataFrame, candidates: pd.DataFrame) -> None:
    risk_score = events["risk_score"].astype(str).str.lower() if not events.empty else pd.Series(dtype=str)
    critical_high = int(risk_score.isin(["critical", "high"]).sum())
    cards = st.columns(2)
    cards[0].metric("Sự kiện AI phân tích", f"{len(events):,}")
    cards[1].metric("Mức cao / nghiêm trọng", f"{critical_high:,}")
    followup = st.columns(2)
    followup[0].metric("IP nguồn duy nhất", f"{events['client_ip'].nunique():,}" if not events.empty else "0")
    followup[1].metric("IP cần analyst rà soát", f"{len(candidates):,}")


def _render_classification_donut(events: pd.DataFrame) -> None:
    if events.empty:
        st.info("Không có sự kiện bảo mật AI trong cửa sổ đang chọn.")
        return
    counts = events["classification"].fillna("Chưa phân loại").value_counts().rename_axis("Phân loại").reset_index(name="Sự kiện")
    figure = px.pie(counts, names="Phân loại", values="Sự kiện", hole=.62,
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
    frame = timeline.rename("Sự kiện").reset_index()
    figure = px.area(frame, x="timestamp", y="Sự kiện", color_discrete_sequence=["#38bdf8"])
    figure.update_traces(line=dict(width=2), fillcolor="rgba(56,189,248,.18)")
    figure.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                         margin=dict(l=8, r=8, t=8, b=8), height=310, font_color="#dce5ef",
                         xaxis_title=None, yaxis_title="Sự kiện", showlegend=False)
    st.plotly_chart(figure, use_container_width=True, config={"displayModeBar": False})


def _render_ip_triage(candidates: pd.DataFrame) -> None:
    with st.container(border=True):
        st.markdown("### IP cần ưu tiên rà soát")
        st.caption("Tương quan trên sự kiện AI: IP có ít nhất 3 sự kiện hoặc có sự kiện mức cao/nghiêm trọng.")
        if candidates.empty:
            st.info("Chưa có IP nào vượt ngưỡng ưu tiên trong cửa sổ đang chọn.")
            return
        display = candidates.rename(columns={
            "client_ip": "IP nguồn", "event_count": "Số sự kiện", "high_critical": "Cao / nghiêm trọng",
            "attack_types": "Loại sự kiện", "review_reason": "Lý do ưu tiên", "last_seen": "Ghi nhận gần nhất",
        }).copy()
        display["Ghi nhận gần nhất"] = pd.to_datetime(display["Ghi nhận gần nhất"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
        st.dataframe(display, use_container_width=True, hide_index=True,
                     column_config={"IP nguồn": st.column_config.TextColumn("IP nguồn"),
                                    "Số sự kiện": st.column_config.NumberColumn("Sự kiện", format="%d"),
                                    "Cao / nghiêm trọng": st.column_config.NumberColumn("Cao / nghiêm trọng", format="%d"),
                                    "Loại sự kiện": st.column_config.NumberColumn("Loại", format="%d"),
                                    "Lý do ưu tiên": st.column_config.TextColumn("Lý do ưu tiên"),
                                    "Ghi nhận gần nhất": st.column_config.DatetimeColumn("Gần nhất", format="HH:mm:ss · DD/MM/YYYY")})


def _render_ai_recommendations(events: pd.DataFrame) -> None:
    with st.container(border=True):
        st.markdown("### Hàng đợi xử lý do AI đề xuất")
        if events.empty:
            st.info("Chưa có sự kiện để tạo hàng đợi xử lý.")
            return
        priority = events[events["risk_score"].astype(str).str.lower().isin(["critical", "high"])].head(8).copy()
        if priority.empty:
            st.info("Không có sự kiện mức cao hoặc nghiêm trọng trong cửa sổ đang chọn.")
            return
        priority["timestamp"] = pd.to_datetime(priority["timestamp"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
        priority = priority.rename(columns={"timestamp": "Thời điểm", "client_ip": "IP nguồn",
                                            "classification": "Phân loại", "risk_score": "Mức độ",
                                            "recommendation": "Đề xuất xử lý (AI)"})
        st.dataframe(priority[["Thời điểm", "IP nguồn", "Phân loại", "Mức độ", "Đề xuất xử lý (AI)"]],
                     use_container_width=True, hide_index=True, height=320,
                     column_config={"Thời điểm": st.column_config.DatetimeColumn("Thời điểm", format="HH:mm:ss · DD/MM/YYYY"),
                                    "IP nguồn": st.column_config.TextColumn("IP nguồn"),
                                    "Phân loại": st.column_config.TextColumn("Phân loại"),
                                    "Mức độ": st.column_config.TextColumn("Mức độ"),
                                    "Đề xuất xử lý (AI)": st.column_config.TextColumn("Đề xuất xử lý (AI)", width="large")})


def _render_overview(events: pd.DataFrame) -> None:
    st.markdown("### Tình hình sự cố")
    candidates = suspicious_ip_candidates(events)
    _metric_row(events, candidates)
    left, right = st.columns(2)
    with left:
        with st.container(border=True):
            st.markdown("### Phân loại sự kiện")
            _render_classification_donut(events)
    with right:
        with st.container(border=True):
            st.markdown("### Xu hướng sự kiện")
            _render_attack_timeline(events)
    _render_ip_triage(candidates)
    _render_ai_recommendations(events)


def _render_console() -> None:
    @st.fragment(run_every="3s")
    def console_fragment() -> None:
        logs = fetch_console_logs(120)
        if not logs:
            st.info("Chưa có hoạt động thu thập. Hãy khởi động bộ phân tích để xem log trực tiếp.")
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


def _render_monitoring() -> None:
    st.markdown("### Tình trạng bộ phân tích")

    @st.fragment(run_every="5s")
    def process_fragment() -> None:
        current = analyzer_status()
        render_process_controls(current)
        with st.container(border=True):
            st.markdown("### Điều khiển bộ phân tích")
            st.caption("Phân tích và đề xuất luôn sử dụng tiếng Việt.")
            start_col, stop_col = st.columns(2)
            if start_col.button("▶ Khởi động", type="primary", use_container_width=True, disabled=current["enabled"]):
                set_analyzer(True, "Vietnamese")
                st.rerun()
            if stop_col.button("■ Dừng", use_container_width=True, disabled=not current["enabled"]):
                set_analyzer(False, "Vietnamese")
                st.rerun()

    process_fragment()
    with st.container(border=True):
        st.markdown("### Nhật ký collector trực tiếp")
        st.caption("Tự cập nhật mỗi 3 giây.")
        _render_console()


def _render_incident_inspector(event: pd.Series) -> None:
    st.markdown(f"### Phân tích sự kiện · {event.get('classification', 'Sự kiện bảo mật')}")
    st.markdown(
        f"**Mức độ rủi ro:** <span class='severity-{str(event.get('risk_score', 'info')).lower()}'>"
        f"{html.escape(str(event.get('risk_score') or 'Info'))}</span>　·　"
        f"**Source IP:** `{html.escape(str(event.get('client_ip') or 'Unknown'))}`",
        unsafe_allow_html=True,
    )
    st.caption("AI hỗ trợ điều tra và đề xuất; chính sách chặn vẫn do WAF thực thi.")

    pipeline_cols = st.columns(2)
    pipeline_cols[0].markdown("**Sự kiện**")
    pipeline_cols[1].markdown("**Thu thập**")
    pipeline_cols[0].markdown("**Phân tích**")
    pipeline_cols[1].markdown("**Mô hình AI**")

    classification_col, risk_col = st.columns(2)
    with classification_col:
        with st.container(border=True):
            st.markdown("#### Phân loại sự kiện")
            st.markdown(html.escape(str(event.get("classification") or "Chưa phân loại.")))
    with risk_col:
        with st.container(border=True):
            st.markdown("#### Mức độ rủi ro")
            risk_value = str(event.get("risk_score") or "Info")
            st.markdown(f"<span class='severity-{risk_value.lower()}' style='font-size:1.1rem'>{html.escape(risk_value)}</span>", unsafe_allow_html=True)

    explanation_col, correlation_col = st.columns(2)
    with explanation_col:
        with st.container(border=True):
            st.markdown("#### Giải thích và bối cảnh")
            st.markdown(str(event.get("explanation") or "Chưa có giải thích được lưu."))
    with correlation_col:
        with st.container(border=True):
            st.markdown("#### Tương quan tấn công")
            st.markdown(str(event.get("correlation") or "Chưa có phân tích tương quan."))

    with st.container(border=True):
        st.markdown("#### Đề xuất hành động xử lý")
        st.markdown(str(event.get("recommendation") or "Chưa có khuyến nghị được lưu."))

    with st.container(border=True):
        st.markdown("#### Log gốc")
        st.code(str(event.get("raw_log") or "Không có log gốc được lưu."), language=None)


def _render_events(events: pd.DataFrame) -> None:
    st.markdown("### Danh sách sự kiện bảo mật")
    if events.empty:
        st.info("Không có sự kiện AI nào khớp với bộ lọc.")
        return
    display = events.copy().reset_index(drop=True)
    display["timestamp"] = pd.to_datetime(display["timestamp"], utc=True, errors="coerce").dt.tz_convert(APP_TZ)
    visible_columns = ["timestamp", "client_ip", "classification", "risk_score"]
    risk_colors = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#34d399", "info": "#38bdf8"}
    styled_events = display[visible_columns].style.map(
        lambda value: f"color: {risk_colors.get(str(value).lower(), '#e5eaf2')}; font-weight: 700",
        subset=["risk_score"],
    )
    selection = st.dataframe(
        styled_events, use_container_width=True, hide_index=True, height=390,
        on_select="rerun", selection_mode="single-row", key="security-event-matrix",
        column_config={"timestamp": st.column_config.DatetimeColumn("Thời điểm (UTC+07)", format="DD/MM/YYYY HH:mm:ss"),
                   "client_ip": st.column_config.TextColumn("IP nguồn"),
                   "classification": st.column_config.TextColumn("Phân loại"),
                   "risk_score": st.column_config.TextColumn("Mức độ")},
    )
    selected_rows = selection.selection.rows
    if selected_rows and 0 <= selected_rows[0] < len(display):
        _render_incident_inspector(display.iloc[selected_rows[0]])
    else:
        st.caption("Chọn một dòng để xem log gốc, phân tích và đề xuất của AI.")


def _render_reports(events: pd.DataFrame, start: datetime, end: datetime, window: str) -> None:
    st.markdown("### Báo cáo sự cố trực tiếp")
    st.caption(f"Cửa sổ {window} · {start:%d/%m/%Y %H:%M} đến {end:%d/%m/%Y %H:%M} (UTC+07)")
    cards = st.columns(2)
    counts = events["risk_score"].astype(str).str.lower() if not events.empty else pd.Series(dtype=str)
    cards[0].metric("Sự kiện trong cửa sổ", f"{len(events):,}")
    cards[1].metric("Nghiêm trọng", f"{int((counts == 'critical').sum()):,}")
    st.metric("Mức cao", f"{int((counts == 'high').sum()):,}")
    if events.empty:
        st.info("Chưa có sự kiện phù hợp để xuất báo cáo.")
        return
    export_columns = ["timestamp", "client_ip", "classification", "risk_score", "explanation", "correlation", "recommendation", "raw_log"]
    csv_data = events[export_columns].to_csv(index=False).encode("utf-8-sig")
    pdf_data = make_pdf_report(events, start, end)
    left, right = st.columns(2)
    left.download_button("Tải dữ liệu sự kiện CSV", csv_data,
                         file_name=f"soc-events-{start:%Y%m%d-%H%M}-{end:%Y%m%d-%H%M}.csv", mime="text/csv",
                         use_container_width=True)
    right.download_button("Tải báo cáo PDF", pdf_data,
                          file_name=f"soc-report-{start:%Y%m%d-%H%M}-{end:%Y%m%d-%H%M}.pdf",
                          mime="application/pdf", use_container_width=True)


@st.fragment(run_every="10s")
def _render_live_data(page: str) -> None:
    start, end, window = _rolling_window(page)
    st.markdown(f"<span class='db-live'>● TRỰC TIẾP</span>　Cập nhật lúc {end:%H:%M:%S} · UTC+07",
                unsafe_allow_html=True)
    try:
        events = _filtered_events(fetch_events(start, end), page)
    except Exception as exc:
        st.error("Không thể tải sự kiện. Kiểm tra kết nối PostgreSQL.")
        st.exception(exc)
        return
    if page == "Overview":
        _render_overview(events)
    elif page == "Events":
        _render_events(events)
    else:
        _render_reports(events, start, end, window)


def run_app() -> None:
    render_theme()
    db_ok, db_message = database_status()
    st.session_state["db-connected"] = db_ok
    page = _sidebar_inputs(db_ok, db_message)
    if not db_ok:
        st.error(f"Không kết nối được PostgreSQL ({db_message}). Kiểm tra dịch vụ cơ sở dữ liệu.")
        st.stop()
    try:
        if analyzer_status()["language"] != "Vietnamese":
            set_language("Vietnamese")
    except Exception as exc:
        st.error("Không thể đọc cấu hình bộ phân tích AI từ PostgreSQL.")
        st.exception(exc)
        st.stop()

    _render_page_heading(page)
    if page == "Overview":
        _render_live_data(page)
    elif page == "Monitoring":
        _render_monitoring()
    elif page == "Events":
        _render_live_data(page)
    elif page == "Reports":
        _render_live_data(page)
    st.markdown("<div class='report-footer'>SOC · Phân tích sự kiện và hỗ trợ điều tra bảo mật</div>", unsafe_allow_html=True)
