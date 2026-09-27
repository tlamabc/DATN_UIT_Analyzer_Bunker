"""Shared light SOC monitoring design system."""
import streamlit as st


def render_theme() -> None:
    st.set_page_config(page_title="BunkerWeb Security Monitor", page_icon="🛡️", layout="wide")
    st.markdown(
        """
        <style>
        :root {
          --ink:#243247; --muted:#718096; --orange:#e87524; --orange-soft:#fff3e8;
          --line:#e5e9ef; --surface:#fff; --canvas:#f5f7fa; --green:#20875a;
        }
        [data-testid="stAppViewContainer"] { background:var(--canvas); color:var(--ink); }
        [data-testid="stHeader"], [data-testid="stToolbar"] { display:none; height:0; }
        [data-testid="stMainBlockContainer"] { max-width:1320px; margin:0 auto; padding:1.4rem 2rem 3rem; }
        [data-testid="stMainBlockContainer"] > div { gap:1rem; }
        [data-testid="stSidebar"] { background:#fff; border-right:1px solid var(--line); }
        [data-testid="stSidebar"] > div:first-child { padding:1.15rem .85rem; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#c7651f; }
        [data-testid="stSidebar"] [role="radiogroup"] { gap:.3rem; }
        [data-testid="stSidebar"] [data-baseweb="radio"] {
          background:#fff; border:1px solid transparent; border-left:3px solid transparent;
          border-radius:6px; padding:.62rem .7rem; color:#596779; transition:all .15s ease;
        }
        [data-testid="stSidebar"] [data-baseweb="radio"]:hover { background:#fff8f2; color:#bd5c18; }
        [data-testid="stSidebar"] [data-baseweb="radio"]:has(input:checked) {
          background:var(--orange-soft); border-color:#f5dcc8; border-left-color:var(--orange);
          color:#bd5c18; font-weight:700;
        }
        [data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child { display:none; }
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] { color:#8a96a5; }
        h1,h2,h3 { color:var(--ink) !important; letter-spacing:-.02em; }
        h1 { font-size:1.9rem !important; }
        h2 { font-size:1.38rem !important; }
        h3 { font-size:1rem !important; }
        p, label, [data-testid="stCaptionContainer"] { color:var(--muted); }
        [data-testid="stVerticalBlockBorderWrapper"] {
          background:var(--surface); border:1px solid var(--line); border-radius:10px;
          box-shadow:0 2px 7px rgba(31,45,61,.035);
        }
        [data-testid="stMetric"] { background:#fff; border:1px solid var(--line); border-radius:8px; padding:13px 15px; }
        [data-testid="stMetricLabel"] { color:#718096; }
        [data-testid="stMetricValue"] { color:#243247; font-size:1.55rem; }
        .stButton > button, .stDownloadButton > button {
          background:#fff; color:#4b596b; border:1px solid #d9e0e8; border-radius:6px;
          min-height:2.45rem; font-weight:650; transition:all .15s ease;
        }
        .stButton > button:hover, .stDownloadButton > button:hover { background:#fff8f2; border-color:#e87524; color:#bd5c18; }
        .stButton > button[kind="primary"] { background:#e87524; border-color:#e87524; color:#fff; }
        .stButton > button[kind="primary"]:hover { background:#cf6218; color:#fff; }
        [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:7px; }
        [data-testid="stProgressBar"] > div > div { background:#e87524; }
        input, textarea, [data-baseweb="select"] > div { background:#fff !important; color:#243247 !important; border-color:#d9e0e8 !important; border-radius:6px !important; }
        .app-brand { display:flex; align-items:center; gap:.8rem; padding:.1rem 0 1rem; margin-bottom:.45rem; border-bottom:1px solid var(--line); }
        .brand-mark { display:grid; place-items:center; width:42px; height:42px; background:#fff3e8; border:1px solid #f2d5bd; border-radius:9px; color:#d5681d; font-size:1rem; font-weight:800; }
        .brand-name { color:#243247; font-size:1rem; font-weight:780; letter-spacing:.035em; }
        .brand-name span { color:#dd6e20; font-size:.7rem; margin-left:.4rem; letter-spacing:.08em; }
        .brand-subtitle { color:#8591a0; font-size:.78rem; margin-top:.12rem; }
        .side-label { color:#a4aeba; font-size:.67rem; font-weight:750; letter-spacing:.13em; margin:.8rem 0 .35rem; }
        .side-footer { color:#8a96a5; font-size:.72rem; border-top:1px solid var(--line); margin-top:1rem; padding-top:.75rem; }
        .page-heading { display:flex; justify-content:space-between; align-items:end; gap:1rem; margin:.25rem 0 .1rem; }
        .page-eyebrow { color:#df7023; font-size:.68rem; font-weight:750; letter-spacing:.12em; text-transform:uppercase; }
        .section-eyebrow { color:#8d98a6; font-size:.67rem; font-weight:750; letter-spacing:.12em; margin-bottom:.35rem; }
        .console { background:#18212b; color:#e5ebf1; border:1px solid #303d49; border-radius:7px; padding:13px 15px; font:12px/1.65 Consolas,Monaco,monospace; height:310px; overflow-y:auto; }
        .console-line { border-bottom:1px solid #ffffff12; padding:3px 0; white-space:pre-wrap; word-break:break-word; }
        .console-time { color:#9aa7b3; } .console-error { color:#ff8278; } .console-warning { color:#f5c56a; }
        .console-info { color:#75c3ef; } .console-critical { color:#ff665c; } .console-source { color:#b5c5d3; }
        .report-footer { color:#98a2af; border-top:1px solid var(--line); margin-top:2rem; padding-top:.8rem; font-size:.78rem; }
        </style>
        """,
        unsafe_allow_html=True,
    )
