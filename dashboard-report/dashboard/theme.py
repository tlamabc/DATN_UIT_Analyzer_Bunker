"""Clean Windows 10-inspired report theme."""
import streamlit as st


def render_theme() -> None:
    st.set_page_config(page_title="SOC Security Assessment Report", page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        :root { --ink:#172b4d; --muted:#62748a; --blue:#1769aa; --line:#dce3eb; --surface:#fff; }
        [data-testid="stAppViewContainer"] { background:#f3f6fa; color:var(--ink); }
        [data-testid="stHeader"] { display:none; height:0; }
        [data-testid="stToolbar"] { display:none; }
        [data-testid="stMainBlockContainer"] { max-width:1440px; padding:1.4rem 2rem 3rem; }
        [data-testid="stMainBlockContainer"] > div { gap:1rem; }
        h1,h2,h3 { color:var(--ink) !important; letter-spacing:-.025em; }
        h1 { font-size:2rem !important; }
        h2 { font-size:1.35rem !important; }
        [data-testid="stMetric"] { background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:16px 18px; box-shadow:0 1px 2px #172b4d0a; }
        [data-testid="stMetricLabel"] { color:var(--muted); }
        [data-testid="stMetricValue"] { color:var(--ink); }
        [data-testid="stVerticalBlockBorderWrapper"] { background:var(--surface); border:1px solid var(--line); border-radius:12px; box-shadow:0 2px 8px #172b4d0a; }
        .stButton > button, .stDownloadButton > button { border-radius:7px; min-height:2.5rem; font-weight:600; }
        .stButton > button[kind="primary"] { background:#1769aa; border-color:#1769aa; }
        [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:8px; }
        [data-testid="stProgressBar"] > div > div { background:#1769aa; }
        .report-heading { border-bottom:1px solid var(--line); padding:0 0 1rem; margin-bottom:1.2rem; }
        .report-kicker { color:#1769aa; font-size:.76rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
        .report-title { color:#172b4d; font-size:1.7rem; line-height:1.25; font-weight:750; margin:.35rem 0; }
        .report-subtitle { color:#62748a; font-size:.96rem; }
        .report-meta { color:#62748a; font-size:.85rem; margin-top:.8rem; }
        .console { background:#111827; color:#d1d5db; border-radius:9px; padding:12px 14px; font:12px/1.55 Consolas,Monaco,monospace; max-height:330px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff12; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#94a3b8; } .console-error { color:#fca5a5; } .console-warning { color:#fcd34d; } .console-info { color:#bfdbfe; }
        .report-footer { color:#718096; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.8rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
