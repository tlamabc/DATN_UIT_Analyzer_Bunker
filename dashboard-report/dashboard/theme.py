"""Cybersecurity SOC design tokens and dashboard styling."""
import streamlit as st


def render_theme() -> None:
    st.set_page_config(page_title="SOC Security Operations", page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        :root { --bg:#0b0f19; --panel:#111827; --panel2:#151e2d; --line:#1f2937; --text:#e5eaf2;
          --muted:#91a0b5; --orange:#fb923c; --cyan:#38bdf8; --critical:#f87171; --high:#fb923c;
          --medium:#fbbf24; --safe:#34d399; }
        [data-testid="stAppViewContainer"] { background:var(--bg); color:var(--text); }
        [data-testid="stHeader"], [data-testid="stToolbar"] { display:none; height:0; }
        [data-testid="stMainBlockContainer"] { max-width:1480px; margin:0 auto; padding:1.25rem 2rem 3rem; }
        [data-testid="stMainBlockContainer"] > div { gap:.9rem; }
        [data-testid="stSidebar"] { background:#0e1522; border-right:1px solid var(--line); }
        [data-testid="stSidebar"] > div:first-child { padding:1.15rem .85rem; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#cbd5e1; }
        [data-testid="stSidebar"] [role="radiogroup"] { gap:.3rem; }
        [data-testid="stSidebar"] [data-baseweb="radio"] { border:1px solid transparent; border-left:3px solid transparent; border-radius:6px; padding:.6rem .65rem; color:#aab6c5; }
        [data-testid="stSidebar"] [data-baseweb="radio"]:hover { background:#172235; color:#fff; }
        [data-testid="stSidebar"] [data-baseweb="radio"]:has(input:checked) { background:#221c1a; border-color:#463128; border-left-color:var(--orange); color:#fdba74; font-weight:700; }
        [data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child { display:none; }
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color:#75849a; }
        h1,h2,h3 { color:#f2f5fa !important; letter-spacing:-.02em; }
        h1 { font-size:1.85rem !important; } h2 { font-size:1.3rem !important; } h3 { font-size:1rem !important; }
        p,label,[data-testid="stCaptionContainer"] { color:var(--muted); }
        [data-testid="stVerticalBlockBorderWrapper"] { background:linear-gradient(145deg,#131c2a,#101722); border:1px solid #263244; border-radius:10px; box-shadow:0 6px 22px #0002; }
        [data-testid="stMetric"] { background:#141e2c; border:1px solid #263244; border-radius:9px; padding:13px 15px; }
        [data-testid="stMetricLabel"] { color:#9aa9bc; } [data-testid="stMetricValue"] { color:#f3f6fb; font-size:1.55rem; }
        .stButton > button,.stDownloadButton > button { background:#172235; color:#e5eaf2; border:1px solid #344258; border-radius:6px; min-height:2.4rem; font-weight:650; }
        .stButton > button:hover,.stDownloadButton > button:hover { background:#202e43; border-color:#fb923c; color:#fff; }
        .stButton > button[kind="primary"] { background:#c65d20; border-color:#ea7a32; color:#fff; }
        [data-testid="stDataFrame"] { border:1px solid #263244; border-radius:7px; }
        [data-testid="stProgressBar"] > div > div { background:#fb923c; }
        input,textarea,[data-baseweb="select"] > div { background:#111827 !important; color:#e5eaf2 !important; border-color:#344258 !important; border-radius:6px !important; }
        .brand { display:flex; align-items:center; gap:.8rem; border-bottom:1px solid var(--line); padding:.1rem 0 .9rem; margin-bottom:.5rem; }
        .brand-mark { display:grid; place-items:center; width:40px; height:40px; background:#271d19; border:1px solid #65412d; border-radius:9px; color:#fb923c; font-weight:850; }
        .brand-name { color:#f4f7fb; font-size:1rem; font-weight:800; letter-spacing:.04em; }
        .brand-name span { color:#fb923c; font-size:.7rem; margin-left:.35rem; }
        .brand-subtitle { color:#91a0b5; font-size:.78rem; margin-top:.12rem; }
        .side-label,.page-eyebrow,.section-eyebrow { color:#fb923c; font-size:.67rem; font-weight:750; letter-spacing:.13em; }
        .side-label { margin:.8rem 0 .35rem; } .section-eyebrow { margin-bottom:.35rem; }
        .side-footer { color:#75849a; font-size:.72rem; border-top:1px solid var(--line); margin-top:1rem; padding-top:.75rem; }
        .page-heading { margin:.25rem 0 .1rem; } .page-heading p { margin-top:-.45rem; }
        .console { background:#070b12; color:#dce5ef; border:1px solid #273244; border-radius:7px; padding:13px 15px; font:12px/1.65 Consolas,Monaco,monospace; height:320px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff10; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#718096; } .console-error,.console-critical { color:#f87171; } .console-warning { color:#fbbf24; }
        .console-info { color:#38bdf8; } .console-source { color:#a9bad0; }
        .severity-critical { color:#f87171; font-weight:750; } .severity-high { color:#fb923c; font-weight:700; }
        .severity-medium { color:#fbbf24; } .severity-low { color:#34d399; }
        .db-live { color:#34d399; font-weight:700; } .db-down { color:#f87171; font-weight:700; }
        .report-footer { color:#64748b; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.76rem; }
        </style>
        """, unsafe_allow_html=True,
    )
