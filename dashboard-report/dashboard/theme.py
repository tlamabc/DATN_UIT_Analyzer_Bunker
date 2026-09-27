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
        [data-testid="stMainBlockContainer"] { max-width:1320px; margin:0 auto; padding:1.25rem 2rem 3rem; }
        [data-testid="stMainBlockContainer"] > div { gap:.8rem; }
        [data-testid="stSidebar"] { background:#fff; border-right:1px solid #e6e9ed; }
        [data-testid="stSidebar"] > div:first-child { padding:1.2rem .9rem; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#de6d24; }
        [data-testid="stSidebar"] [role="radiogroup"] { gap:.35rem; }
        [data-testid="stSidebar"] [role="radio"] { background:#fff; border:1px solid transparent; border-left:3px solid transparent; border-radius:4px; padding:.58rem .62rem; }
        [data-testid="stSidebar"] [role="radio"]:hover { background:#fff7f1; border-color:#f5dcc8; border-left-color:#e8782f; }
        [data-testid="stSidebar"] [role="radio"] p { color:#d96c24 !important; font-weight:600; }
        [data-testid="stSidebar"] [role="radio"][aria-checked="true"] { background:#fff2e8; border-color:#f2d2b8; border-left-color:#e8782f; }
        [data-testid="stSidebar"] [role="radio"][aria-checked="true"] p { color:#b9500d !important; font-weight:750; }
        [data-testid="stSidebar"] [role="radio"] > label > div:first-child { display:none; }
        [data-testid="stSidebar"] [data-baseweb="radio"] { background:#fff; border:1px solid transparent; border-left:3px solid transparent; border-radius:4px; padding:.58rem .62rem; color:#d96c24; }
        [data-testid="stSidebar"] [data-baseweb="radio"]:hover { background:#fff7f1; border-color:#f5dcc8; border-left-color:#e8782f; }
        [data-testid="stSidebar"] [data-baseweb="radio"]:has(input:checked) { background:#fff2e8; border-color:#f2d2b8; border-left-color:#e8782f; color:#b9500d; font-weight:750; }
        [data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child { display:none; }
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
        .app-brand { display:flex; align-items:center; gap:.8rem; border-bottom:1px solid var(--line); padding:.15rem 0 .85rem; margin-bottom:.6rem; }
        .brand-mark { display:grid; place-items:center; width:42px; height:42px; background:#0879ad; border:1px solid #39b5e5; border-radius:7px; color:#fff; font-size:1rem; font-weight:800; }
        .brand-name { color:#edf4fb; font-size:1rem; font-weight:750; letter-spacing:.04em; }
        .brand-name span { color:#42b8e6; font-size:.72rem; margin-left:.4rem; }
        .brand-subtitle { color:#8396aa; font-size:.78rem; margin-top:.12rem; }
        .side-label { color:#c45d18; font-size:.68rem; font-weight:750; letter-spacing:.12em; margin:.8rem 0 .35rem; }
        .side-footer { color:#d96c24; font-size:.72rem; border-top:1px solid #f0e2d8; margin-top:1rem; padding-top:.7rem; }
        .section-eyebrow { color:#6f879b; font-size:.68rem; font-weight:750; letter-spacing:.12em; margin-bottom:.4rem; }
        .console { background:#080f17; color:#cbd5e1; border:1px solid #26384b; border-radius:4px; padding:12px 14px; font:12px/1.6 Consolas,Monaco,monospace; height:300px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff0d; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#718096; } .console-error { color:#ff7272; } .console-warning { color:#f3c969; } .console-info { color:#58b8e8; }
        .console-source { color:#8fb7cc; }
        .report-footer { color:#718096; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.8rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
