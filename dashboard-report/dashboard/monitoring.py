"""Analyzer process controls and live collector console components."""
import html

import streamlit as st

from .config import APP_TZ, safe_int_env
from .database import fetch_console_logs, set_analyzer, set_language


def render_process_controls(analyzer: dict) -> None:
    with st.container(border=True):
        st.subheader("Analyzer process")
        metrics = st.columns(4)
        metrics[0].metric("Process state", analyzer["state"])
        metrics[1].metric("Events analyzed", f"{analyzer['analyzed']:,}")
        metrics[2].metric("Log lines scanned", f"{analyzer['lines']:,}")
        metrics[3].metric("Current file progress", f"{analyzer['progress']:.1f}%")
        st.progress(min(100, max(0, int(analyzer["progress"]))), text=f"Current log: {analyzer['file']}")
        st.caption(
            f"Last scan: {analyzer['last_scan'] or 'Not yet scanned'} · Scan date: {analyzer['scan_date']} · "
            f"Interval: {safe_int_env('ANALYZER_SCAN_INTERVAL_SECONDS', 600)}s · "
            f"Limit: {safe_int_env('ANALYZER_MAX_EVENTS_PER_SCAN', 3)} events / scan"
        )
        if analyzer["error"]:
            st.warning(f"Last analyzer issue: {analyzer['error']}")


def render_live_console(analyzer: dict) -> None:
    @st.fragment(run_every="3s")
    def console_fragment() -> None:
        with st.container(border=True):
            title, live = st.columns([3, 1])
            title.subheader("Collector console")
            live.markdown("`● LIVE`" if analyzer["enabled"] else "`○ STOPPED`")
            records = fetch_console_logs(100)
            if not records:
                st.caption("No collector output yet. Start the analyzer to stream process activity here.")
                return
            lines = []
            for created_at, level, logger_name, message in records:
                stamp = created_at.astimezone(APP_TZ).strftime("%Y-%m-%d %H:%M:%S") if created_at else "--"
                level_class = str(level).lower() if str(level).lower() in {"error", "warning", "info", "critical"} else "info"
                lines.append(
                    f'<div class="console-line"><span class="console-time">{stamp}</span> '
                    f'<span class="console-{level_class}">{html.escape(str(level).upper())}</span> '
                    f'<span class="console-source">{html.escape(str(logger_name))}</span> '
                    f'{html.escape(str(message))}</div>'
                )
            st.markdown('<div class="console">' + "".join(lines) + "</div>", unsafe_allow_html=True)

    console_fragment()


def render_analysis_settings(analyzer: dict) -> None:
    with st.container(border=True):
        st.subheader("Analysis settings")
        languages = ["Vietnamese", "English"]
        labels = {"Vietnamese": "Tiếng Việt", "English": "English"}
        selected = st.selectbox(
            "Recommendation language", languages, index=languages.index(analyzer["language"]),
            format_func=lambda value: labels[value],
        )
        if st.button("Save language", key="save-analysis-language"):
            set_language(selected)
            st.success("Analysis language saved.")
            st.rerun()


def change_analyzer_state(enabled: bool, language: str) -> None:
    set_analyzer(enabled, language)
