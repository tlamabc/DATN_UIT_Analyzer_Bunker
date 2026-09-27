"""Dark observability theme for the security report dashboard."""
import streamlit as st


def render_theme() -> None:
    st.set_page_config(page_title="SOC Security Assessment Report", page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        :root { --ink:#e6edf5; --muted:#94a3b8; --blue:#28a9e0; --line:#26384b; --surface:#111e2c; }
        [data-testid="stAppViewContainer"] { background:#0b1420; color:var(--ink); }
        [data-testid="stHeader"] { display:none; height:0; }
        [data-testid="stToolbar"] { display:none; }
        [data-testid="stMainBlockContainer"] { max-width:1600px; padding:1.2rem 1.8rem 3rem; }
        [data-testid="stMainBlockContainer"] > div { gap:.85rem; }
        h1,h2,h3 { color:var(--ink) !important; letter-spacing:-.02em; }
        h1 { font-size:2rem !important; }
        h2 { font-size:1.2rem !important; }
        p, label, [data-testid="stCaptionContainer"] { color:var(--muted); }
        [data-testid="stMetric"] { background:#142333; border:1px solid var(--line); border-radius:5px; padding:13px 16px; box-shadow:none; }
        [data-testid="stMetricLabel"] { color:var(--muted); }
        [data-testid="stMetricValue"] { color:#f1f5f9; }
        [data-testid="stVerticalBlockBorderWrapper"] { background:var(--surface); border:1px solid var(--line); border-radius:6px; box-shadow:none; }
        .stButton > button, .stDownloadButton > button { background:#182a3b; color:#e6edf5; border:1px solid #30465c; border-radius:4px; min-height:2.35rem; font-weight:600; }
        .stButton > button:hover, .stDownloadButton > button:hover { background:#203b52; border-color:#28a9e0; color:white; }
        .stButton > button[kind="primary"] { background:#0879ad; border-color:#1294c9; }
        [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:5px; }
        [data-testid="stProgressBar"] > div > div { background:#21a1d2; }
        input, textarea, [data-baseweb="select"] > div { background:#0d1926 !important; color:var(--ink) !important; border-color:#30465c !important; border-radius:4px !important; }
        .report-heading { border-bottom:1px solid var(--line); padding:0 0 .85rem; margin-bottom:.5rem; }
        .report-kicker { color:#39b5e5; font-size:.72rem; font-weight:700; letter-spacing:.12em; text-transform:uppercase; }
        .report-title { color:#f1f5f9; font-size:1.55rem; line-height:1.25; font-weight:700; margin:.25rem 0; }
        .report-subtitle { color:#bac7d5; font-size:.9rem; }
        .report-meta { color:#8294a8; font-size:.8rem; margin-top:.55rem; }
        .console { background:#080f17; color:#cbd5e1; border:1px solid #26384b; border-radius:4px; padding:12px 14px; font:12px/1.6 Consolas,Monaco,monospace; height:300px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff0d; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#718096; } .console-error { color:#ff7272; } .console-warning { color:#f3c969; } .console-info { color:#58b8e8; }
        .report-footer { color:#718096; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.8rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
