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
        [data-testid="stAppViewContainer"] { background:var(--bg); color:var(--text); overflow-x:hidden; }
        [data-testid="stHeader"], [data-testid="stToolbar"] { display:none; height:0; }
        [data-testid="stMainBlockContainer"] { width:100%; max-width:1600px; margin:0 auto; padding:clamp(.55rem,1.5vw,1.25rem) clamp(.55rem,1.5vw,1.5rem) 2rem; }
        [data-testid="stMainBlockContainer"] > div { gap:.9rem; }
        [data-testid="stSidebar"] { display:none; }
        h1,h2,h3 { color:#f2f5fa !important; letter-spacing:0; overflow-wrap:anywhere; }
        h1 { font-size:1.85rem !important; } h2 { font-size:1.3rem !important; } h3 { font-size:1rem !important; }
        p,label,[data-testid="stCaptionContainer"] { color:var(--muted); }
        [data-testid="stVerticalBlockBorderWrapper"] { min-width:0; background:transparent; border:0; border-radius:0; box-shadow:none; }
        [data-testid="stVerticalBlockBorderWrapper"] > div { min-width:0; padding:0; }
        [data-testid="stMarkdownContainer"], [data-testid="stColumn"], [data-testid="stMetric"] { min-width:0; overflow-wrap:anywhere; }
        [data-testid="stMetric"] { height:100%; background:#141e2c; border:0; border-left:2px solid #fb923c; border-radius:0; padding:10px 14px; }
        [data-testid="stMetricLabel"] { color:#9aa9bc; white-space:normal; overflow-wrap:anywhere; } [data-testid="stMetricValue"] { color:#f3f6fb; font-size:clamp(1rem,1.7vw,1.45rem); overflow-wrap:anywhere; }
        .stButton > button,.stDownloadButton > button { background:#172235; color:#e5eaf2; border:1px solid #344258; border-radius:6px; min-height:2.4rem; font-weight:650; }
        .stButton > button:hover,.stDownloadButton > button:hover { background:#202e43; border-color:#fb923c; color:#fff; }
        .stButton > button[kind="primary"] { background:#c65d20; border-color:#ea7a32; color:#fff; }
        [data-testid="stDataFrame"] { border:1px solid #263244; border-radius:7px; }
        [data-testid="stProgressBar"] > div > div { background:#fb923c; }
        input,textarea,[data-baseweb="select"] > div { background:#111827 !important; color:#e5eaf2 !important; border-color:#344258 !important; border-radius:6px !important; }
        .brand { display:flex; align-items:center; gap:.8rem; border-bottom:1px solid var(--line); padding:.1rem 0 .9rem; margin-bottom:.5rem; }
        .brand-mark { display:grid; place-items:center; width:40px; height:40px; background:#271d19; border:1px solid #65412d; border-radius:9px; color:#fb923c; font-weight:850; }
        .side-brand { display:flex; align-items:center; gap:.65rem; border-bottom:1px solid var(--line); padding:.2rem .15rem .9rem; margin-bottom:.75rem; }
        .side-brand-title { color:#f4f7fb; font-size:.92rem; font-weight:800; letter-spacing:.04em; }
        .side-brand-caption { color:#fb923c; font-size:.62rem; font-weight:750; letter-spacing:.1em; margin-top:.12rem; }
        .brand-name { color:#f4f7fb; font-size:1rem; font-weight:800; letter-spacing:.04em; }
        .brand-name span { color:#fb923c; font-size:.7rem; margin-left:.35rem; }
        .brand-subtitle { color:#91a0b5; font-size:.78rem; margin-top:.12rem; }
        .side-label,.page-eyebrow,.section-eyebrow { color:#fb923c; font-size:.67rem; font-weight:750; letter-spacing:.13em; }
        .side-label { margin:.8rem 0 .35rem; } .section-eyebrow { margin-bottom:.35rem; }
        .side-footer { color:#75849a; font-size:.72rem; border-top:1px solid var(--line); margin-top:1rem; padding-top:.75rem; }
        .st-key-soc-sticky-header { position:sticky; top:0; z-index:1000; background:rgba(11,15,25,.97); border-bottom:1px solid #263244; padding:.2rem 0 .55rem; margin-bottom:.8rem; backdrop-filter:blur(12px); }
        .soc-topline { display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:.35rem .75rem; padding:.2rem 0 .55rem; color:#e5eaf2; font-size:.8rem; }
        .soc-topline span { white-space:normal; text-align:right; }
        [data-testid="stRadio"] [role="radiogroup"] { display:grid !important; width:min(100%,760px); margin:.25rem auto .85rem; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.55rem; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] { box-sizing:border-box; display:flex; min-width:0; min-height:50px; align-items:center; gap:.5rem; margin:0; padding:.5rem .7rem; color:#cbd5e1; background:#111827; border:1px solid #344258; border-radius:6px; white-space:nowrap; transition:background .16s ease,border-color .16s ease,transform .16s ease,box-shadow .16s ease; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] label,
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] p,
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] span { color:#fff !important; font-weight:700 !important; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] > div:first-child { display:none; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"]:has(input:checked) { color:#fff; background:#c65d20; border-color:#fb923c; font-weight:700; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"]:hover { color:#fff; background:#202e43; border-color:#fb923c; transform:translateY(-2px); box-shadow:0 6px 16px #0005; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"]:has(input:checked):hover { background:#e2732f; }
        [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] > div:last-child { min-width:0; white-space:nowrap; }
        .page-heading { margin:.1rem 0 0; } .page-heading p { margin:.1rem 0 0; line-height:1.4; }
        .console { background:#070b12; color:#dce5ef; border:1px solid #273244; border-radius:7px; padding:13px 15px; font:12px/1.65 Consolas,Monaco,monospace; height:320px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff10; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#718096; } .console-error,.console-critical { color:#f87171; } .console-warning { color:#fbbf24; }
        .console-info { color:#38bdf8; } .console-source { color:#a9bad0; }
        .severity-critical { color:#f87171; font-weight:750; } .severity-high { color:#fb923c; font-weight:700; }
        .severity-medium { color:#fbbf24; } .severity-low { color:#34d399; }
        [data-testid="stMarkdownContainer"] h4 { color:#fdba74 !important; }
        .db-live { color:#34d399; font-weight:700; } .db-down { color:#f87171; font-weight:700; }
        .report-footer { color:#64748b; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.76rem; }
        [data-testid="stHorizontalBlock"] { display:grid !important; width:100%; grid-template-columns:repeat(auto-fit,minmax(min(100%,560px),1fr)); gap:clamp(.6rem,1.2vw,1rem); align-items:stretch; }
        [data-testid="stHorizontalBlock"] > [data-testid="column"] { width:100% !important; min-width:0 !important; max-width:100%; flex:none !important; }
        [data-testid="stDataFrame"], [data-testid="stPlotlyChart"] { max-width:100%; min-width:0; }
        @media (max-width: 760px) {
          [data-testid="stRadio"] [role="radiogroup"] { width:min(100%,440px); grid-template-columns:repeat(2,minmax(0,1fr)); gap:.45rem; }
          [data-testid="stRadio"] [role="radiogroup"] [data-baseweb="radio"] { min-height:46px; padding:.45rem .6rem; }
          .soc-topline { font-size:.68rem; }
        }
        @media (max-width: 640px) {
          .brand-name { font-size:.88rem; }
          h1 { font-size:1.45rem !important; }
          .page-heading p { line-height:1.45; }
        }
        </style>
        """, unsafe_allow_html=True,
    )
