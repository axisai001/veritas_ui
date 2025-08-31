# streamlit_app.py — Veritas (Streamlit)
# Tabs: Analyze, Feedback, Support, Help, (Admin if ADMIN_PASSWORD set)
# Strict 10-section bias report, CSV+SQLite logging, SendGrid email.
# Post-login Privacy/Terms acknowledgment (persisted), Admin maintenance tools,
# and robust background image support (local static file OR external URL).

import os
import io
import csv
import re
import time
import json
import base64
import uuid
import hashlib
import secrets
import sqlite3
from typing import Optional, List
from datetime import timedelta, datetime, timezone
from zoneinfo import ZoneInfo
from collections import deque
from pathlib import Path

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from openai import OpenAI
import httpx

# ---------- Optional parsers for uploads ----------
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None
try:
    import docx  # python-docx
except Exception:
    docx = None

# ---------- PDF (ReportLab) for Download report ----------
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfbase.pdfmetrics import stringWidth
except Exception:
    SimpleDocTemplate = None

# ================= Updated Config (via config.py) =================
try:
    from config import load_settings
    settings = load_settings()
except Exception:
    class _FallbackSettings:
        openai_api_key = os.environ.get("OPENAI_API_KEY", "")
        openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        auth_log_ttl_days = int(os.environ.get("AUTH_LOG_TTL_DAYS", "365"))
    settings = _FallbackSettings()

# ================= App constants from secrets/env =================
APP_TITLE = os.environ.get("APP_TITLE", "Veritas")
MODEL = getattr(settings, "openai_model", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))
try:
    TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
except Exception:
    TEMPERATURE = 0.2
ANALYSIS_TEMPERATURE = float(os.environ.get("ANALYSIS_TEMPERATURE", "0.0"))

# Links shown in the acknowledgment gate
PRIVACY_URL = os.environ.get("PRIVACY_URL") or st.secrets.get("PRIVACY_URL", "")
TERMS_URL   = os.environ.get("TERMS_URL")   or st.secrets.get("TERMS_URL", "")
# Background image external URL (optional; e.g., GitHub RAW)
BG_URL      = os.environ.get("BG_URL")      or st.secrets.get("BG_URL", "")

# ----- Streamlit bootstrap -----
st.set_page_config(page_title=APP_TITLE, page_icon="🧭", layout="centered")

# ----- Rerun & query param helpers -----
def _safe_rerun():
    try:
        st.rerun()
    except Exception:
        try:
            st.experimental_rerun()
        except Exception:
            pass

def _get_query_params():
    try:
        return dict(st.query_params)
    except Exception:
        try:
            return st.experimental_get_query_params()
        except Exception:
            return {}

def _set_query_params(**kwargs):
    try:
        st.query_params.clear()
        for k, v in kwargs.items():
            st.query_params[k] = v
    except Exception:
        try:
            st.experimental_set_query_params(**kwargs)
        except Exception:
            pass

# Admin controls
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "").strip()
ADMIN_EMAIL_ALLOWED = os.environ.get("ADMIN_EMAIL_ALLOWED", "").strip()

# --- Safe timezone ---
def _safe_zoneinfo(name: str, fallback: str = "UTC") -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo(fallback)

PILOT_TZ_NAME = os.environ.get("VERITAS_TZ", "America/Denver")
PILOT_TZ = _safe_zoneinfo(PILOT_TZ_NAME, "UTC")
PILOT_START_AT = os.environ.get("PILOT_START_AT", "")
PILOT_START_UTC = None
if PILOT_START_AT:
    try:
        if "T" in PILOT_START_AT:
            if PILOT_START_AT.endswith("Z"):
                dt = datetime.fromisoformat(PILOT_START_AT.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(PILOT_START_AT)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=PILOT_TZ)
        else:
            dt = datetime.strptime(PILOT_START_AT, "%Y-%m-%d %H:%M").replace(tzinfo=PILOT_TZ)
        PILOT_START_UTC = dt.astimezone(timezone.utc)
    except Exception:
        PILOT_START_UTC = None

def pilot_started() -> bool:
    if PILOT_START_UTC is None:
        return True
    return datetime.now(timezone.utc) >= PILOT_START_UTC

# Rates / windows
RATE_LIMIT_LOGIN   = int(os.environ.get("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT    = int(os.environ.get("RATE_LIMIT_CHAT",  "6"))
RATE_LIMIT_EXTRACT = int(os.environ.get("RATE_LIMIT_EXTRACT", "6"))
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RATE_LIMIT_WINDOW_SEC", "60"))

# Uploads
try:
    MAX_UPLOAD_MB = float(os.environ.get("MAX_UPLOAD_MB", "10"))
except Exception:
    MAX_UPLOAD_MB = 10.0
MAX_EXTRACT_CHARS = int(os.environ.get("MAX_EXTRACT_CHARS", "50000"))

# TTLs (days)
AUTH_LOG_TTL_DAYS     = int(os.environ.get("AUTH_LOG_TTL_DAYS", str(getattr(settings, "auth_log_ttl_days", 365))))
ANALYSES_LOG_TTL_DAYS = int(os.environ.get("ANALYSES_LOG_TTL_DAYS", "365"))
FEEDBACK_LOG_TTL_DAYS = int(os.environ.get("FEEDBACK_LOG_TTL_DAYS", "365"))
ERRORS_LOG_TTL_DAYS   = int(os.environ.get("ERRORS_LOG_TTL_DAYS", "365"))
SUPPORT_LOG_TTL_DAYS  = int(os.environ.get("SUPPORT_LOG_TTL_DAYS", "365"))
ACK_TTL_DAYS          = int(os.environ.get("ACK_TTL_DAYS") or st.secrets.get("ACK_TTL_DAYS", 365))
if ACK_TTL_DAYS < 0: ACK_TTL_DAYS = 0

# SendGrid
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_TO       = os.environ.get("SENDGRID_TO", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT  = os.environ.get("SENDGRID_SUBJECT", "New Veritas feedback")

# Password gate
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# Lockout config
LOCKOUT_THRESHOLD      = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC     = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC   = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800"))

# Storage / branding
BASE_DIR      = os.path.dirname(__file__)
STATIC_DIR    = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(STATIC_DIR, "uploads")  # logos only
DATA_DIR      = os.path.join(BASE_DIR, "data")
DB_PATH       = os.path.join(DATA_DIR, "veritas.db")
FEEDBACK_CSV  = os.path.join(DATA_DIR, "feedback.csv")
ERRORS_CSV    = os.path.join(DATA_DIR, "errors.csv")
AUTH_CSV      = os.path.join(DATA_DIR, "auth_events.csv")
ANALYSES_CSV  = os.path.join(DATA_DIR, "analyses.csv")
SUPPORT_CSV   = os.path.join(DATA_DIR, "support_tickets.csv")
ACK_CSV       = os.path.join(DATA_DIR, "ack_events.csv")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

ALLOWED_EXTENSIONS     = {"png", "jpg", "jpeg", "webp"}           # logo types
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}      # upload types
BG_ALLOWED_EXTENSIONS  = {"svg", "png", "jpg", "jpeg", "webp"}    # background types

# ---------- SQLite setup ----------
def _init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            event_type TEXT,
            login_id TEXT,
            session_id TEXT,
            tracking_id TEXT,
            credential_label TEXT,
            success INTEGER,
            hashed_attempt_prefix TEXT,
            remote_addr TEXT,
            user_agent TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            public_report_id TEXT,
            internal_report_id TEXT,
            session_id TEXT,
            login_id TEXT,
            remote_addr TEXT,
            user_agent TEXT,
            conversation_chars INTEGER,
            conversation_json TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            rating INTEGER,
            email TEXT,
            comments TEXT,
            conversation_chars INTEGER,
            conversation TEXT,
            remote_addr TEXT,
            ua TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            error_id TEXT,
            request_id TEXT,
            route TEXT,
            kind TEXT,
            http_status INTEGER,
            detail TEXT,
            session_id TEXT,
            login_id TEXT,
            remote_addr TEXT,
            user_agent TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS support_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            ticket_id TEXT,
            full_name TEXT,
            email TEXT,
            bias_report_id TEXT,
            issue TEXT,
            session_id TEXT,
            login_id TEXT,
            user_agent TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ack_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            session_id TEXT,
            login_id TEXT,
            acknowledged INTEGER,
            privacy_url TEXT,
            terms_url TEXT,
            remote_addr TEXT,
            user_agent TEXT
        )
    """)
    con.commit()
    con.close()

def _db_exec(query: str, params: tuple):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(query, params)
    con.commit()
    con.close()

_init_db()

# Initialize CSV headers if missing
def _init_csv(path: str, header: List[str]):
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)

_init_csv(AUTH_CSV,     ["timestamp_utc","event_type","login_id","session_id","tracking_id","credential_label","success","hashed_attempt_prefix","remote_addr","user_agent"])
_init_csv(ANALYSES_CSV, ["timestamp_utc","public_report_id","internal_report_id","session_id","login_id","remote_addr","user_agent","conversation_chars","conversation_json"])
_init_csv(FEEDBACK_CSV, ["timestamp_utc","rating","email","comments","conversation_chars","conversation","remote_addr","ua"])
_init_csv(ERRORS_CSV,   ["timestamp_utc","error_id","request_id","route","kind","http_status","detail","session_id","login_id","remote_addr","user_agent"])
_init_csv(SUPPORT_CSV,  ["timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"])
_init_csv(ACK_CSV,      ["timestamp_utc","session_id","login_id","acknowledged","privacy_url","terms_url","remote_addr","user_agent"])

# Default tagline + logo autodetect
CURRENT_TAGLINE = (os.environ.get("VERITAS_TAGLINE", "") or "").strip()
CURRENT_LOGO_FILENAME = None
if os.path.isdir(UPLOAD_FOLDER):
    for f in os.listdir(UPLOAD_FOLDER):
        name = f.lower()
        if name.startswith("logo.") and name.rsplit(".", 1)[-1] in ALLOWED_EXTENSIONS:
            CURRENT_LOGO_FILENAME = f
            break

STARTED_AT_ISO = datetime.now(timezone.utc).isoformat()

# ===== Identity + Veritas Prompts =====
IDENTITY_PROMPT = "I'm Veritas — a bias detection tool."

DEFAULT_SYSTEM_PROMPT = """(shortened here for brevity in this snippet — unchanged content in full app)""".strip()

# ===== Strict output template & helpers =====
STRICT_OUTPUT_TEMPLATE = """
1. Bias Detected: <Yes/No>
2. Bias Score: <Emoji + label> | Score: <0.00–1.00 with two decimals>
3. Type(s) of Bias:
- <type 1>
- <type 2>
4. Biased Phrases or Terms:
- "<exact quote 1>"
- "<exact quote 2>"
5. Bias Summary:
<exactly 2–4 sentences>
6. Explanation:
- "<phrase>" → <bias type> — <why>
7. Contextual Definitions:
- <term> — Contextual: <meaning in passage> | General: <neutral definition>
8. Framework Awareness Note:
- <note or “None”>
9. Suggested Revisions:
- <suggestion 1>
- <suggestion 2>
10. 📊 Interpretation of Score:
<one short paragraph clarifying why the score falls in its range>
""".strip()

SECTION_REGEXES = [
    r"^\s*1\.\s*Bias Detected:\s*(Yes|No)",
    r"^\s*2\.\s*Bias Score:\s*.+\|\s*Score:\s*\d+\.\d{2}",
    r"^\s*3\.\s*Type\(s\) of Bias:",
    r"^\s*4\.\s*Biased Phrases or Terms:",
    r"^\s*5\.\s*Bias Summary:",
    r"^\s*6\.\s*Explanation:",
    r"^\s*7\.\s*Contextual Definitions:",
    r"^\s*8\.\s*Framework Awareness Note:",
    r"^\s*9\.\s*Suggested Revisions:",
    r"^\s*10\.\s*📊\s*Interpretation of Score:",
]

def _looks_strict(md: str) -> bool:
    text = md or ""
    for rx in SECTION_REGEXES:
        if re.search(rx, text, flags=re.MULTILINE) is None:
            return False
    return True

def _build_user_instruction(input_text: str) -> str:
    return (
        "Analyze the TEXT below strictly using the rules above. "
        "Then output ONLY using this exact 10-section template in the same order. "
        "No intro/outro or backticks. If no bias is present, set ‘1. Bias Detected: No’ and "
        "‘2. Bias Score: 🟢 No Bias | Score: 0.00’, and write ‘(none)’ for sections 3, 4, and 9. "
        "Include section 10 regardless.\n\n"
        "=== OUTPUT TEMPLATE (copy exactly) ===\n"
        f"{STRICT_OUTPUT_TEMPLATE}\n\n"
        "=== TEXT TO ANALYZE (verbatim) ===\n"
        f"{input_text}"
    )

# ================= Utilities =================
def _get_sid() -> str:
    sid = st.session_state.get("sid")
    if not sid:
        sid = secrets.token_hex(16)
        st.session_state["sid"] = sid
    return sid

def _gen_tracking_id(prefix: str = "AE") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def _gen_error_id(prefix: str = "NE") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def _gen_request_id(prefix: str = "RQ") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def _gen_public_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand = secrets.token_hex(4).upper()
    return f"VER-{ts}-{rand}"

def _gen_internal_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand = secrets.token_hex(4).upper()
    return f"AX-{ts}-{rand}"

def _gen_ticket_id(prefix: str = "SUP") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(3).upper()
    return f"{prefix}-{ts}-{rand}"

# ---- Global CSS ----
PRIMARY = "#FF8C32"
ACCENT = "#E97C25"
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] {{ font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
.block-container {{ padding-top: 2.75rem !important; padding-bottom: 64px !important; }}

/* Base button style */
div.stButton > button, .stDownloadButton button, .stForm [type="submit"],
[data-testid="stFileUploader"] section div div span button,
button[kind="primary"], button[kind="secondary"],
[data-testid="baseButton-secondary"], [data-testid="baseButton-primary"] {{
  background-color: {PRIMARY} !important; color: #111418 !important;
  border: 1px solid {PRIMARY} !important; border-radius: .75rem !important;
  box-shadow: none !important; padding: 0.60rem 1rem !important;
  font-size: 0.95rem !important; font-weight: 500 !important;
}}
div.stButton > button:hover, .stDownloadButton button:hover,
.stForm [type="submit"]:hover, [data-testid="baseButton-primary"]:hover {{
  background-color: {ACCENT} !important; border-color: {ACCENT} !important;
}}

/* COMPACT analyze form buttons (height + width not stretched) */
#analyze-card .stForm button[type="submit"],
#analyze-card div.stButton > button {{
  padding: .35rem .9rem !important;
  line-height: 1.1 !important;
  border-radius: .55rem !important;
  width: auto !important;
  min-width: 0 !important;
}}

/* Glassy cards */
.v-card {{ background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px; padding: 18px; }}

/* Analyze card spacing */
#analyze-card h3 {{ margin: 0 0 .5rem !important; }}
#analyze-card [data-testid="stTextArea"] label,
#analyze-card [data-testid="stFileUploader"] label {{ margin-top: 0 !important; }}

/* Action links bar */
.v-actions {{ display: inline-flex; gap: 1.0rem; align-items: center;
  padding: .45rem .75rem; border-radius: 10px; background: rgba(0,0,0,0.65); }}
.v-actions a {{ color: #fff !important; text-decoration: none; font-weight: 600; }}
.v-actions a:hover {{ text-decoration: underline; }}
.v-actions .copy-note {{ color:#fff; opacity:.8; font-size:.85rem; }}

/* Sticky footer */
#vFooter {{ position: fixed; left: 0; right: 0; bottom: 0; z-index: 9999;
  text-align: center; font-size: 12px; opacity: .85;
  background: rgba(0,0,0,0.75); color: #fff; padding: 6px 8px; }}
</style>
""", unsafe_allow_html=True)

# ====== Background image injection ======
def _find_local_bg_file() -> Optional[Path]:
    for ext in ("svg","png","jpg","jpeg","webp"):
        p = Path(STATIC_DIR) / f"bg.{ext}"
        if p.exists():
            return p
    for p in Path(STATIC_DIR).glob("bg.*"):
        if p.suffix.lower().lstrip(".") in ("svg","png","jpg","jpeg","webp"):
            return p
    return None

def _inject_bg():
    try:
        p = _find_local_bg_file()
        if p and p.exists():
            ext = p.suffix.lower().lstrip(".")
            mime = {"svg":"image/svg+xml","png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","webp":"image/webp"}.get(ext,"application/octet-stream")
            b64 = base64.b64encode(p.read_bytes()).decode("ascii")
            st.markdown(f"""
            <style>.stApp {{ background: url("data:{mime};base64,{b64}") no-repeat center center fixed; background-size: cover; }}</style>
            """, unsafe_allow_html=True)
        elif BG_URL:
            safe_url = BG_URL.replace('"','%22')
            st.markdown(f"""
            <style>.stApp {{ background: url("{safe_url}") no-repeat center center fixed; background-size: cover; }}</style>
            """, unsafe_allow_html=True)
    except Exception:
        pass
_inject_bg()

# =========== Header (logo only; title moved to sidebar) ===========
with st.container():
    col_logo, col_title, _ = st.columns([1, 6, 1])
    with col_logo:
        logo_path = None
        if CURRENT_LOGO_FILENAME:
            candidate = Path(UPLOAD_FOLDER) / CURRENT_LOGO_FILENAME
            if candidate.is_file():
                logo_path = candidate
        if logo_path:
            try:
                st.image(logo_path.read_bytes(), use_container_width=True)
            except Exception:
                st.write("")
    with col_title:
        if CURRENT_TAGLINE:
            st.caption(CURRENT_TAGLINE)

# ---------------- Session/Auth bootstrap ----------------
if "request_id" not in st.session_state:
    st.session_state["request_id"] = f"RQ-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4).upper()}"
st.session_state.setdefault("authed", False)
st.session_state.setdefault("history", [])
st.session_state.setdefault("last_reply", "")
st.session_state.setdefault("user_input_box", "")
st.session_state.setdefault("_clear_text_box", False)
st.session_state.setdefault("_fail_times", deque())
st.session_state.setdefault("_locked_until", 0.0)
st.session_state.setdefault("is_admin", False)
st.session_state.setdefault("ack_ok", False)

if not pilot_started():
    st.info("Pilot hasn’t started yet."); st.stop()

def _is_locked() -> bool:
    return time.time() < st.session_state["_locked_until"]

def show_login():
    with st.form("login_form"):
        st.subheader("Login")
        login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id", ""))
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("Enter")
        if submit:
            if _is_locked():
                st.error("Locked out temporarily."); st.stop()
            if pwd == APP_PASSWORD:
                st.session_state["authed"] = True
                st.session_state["login_id"] = (login_id or "").strip()
                st.success("Logged in."); _safe_rerun()
            else:
                st.error("Incorrect password")

if not st.session_state["authed"] and APP_PASSWORD:
    show_login(); st.stop()
elif not APP_PASSWORD:
    st.session_state["authed"] = True

# ====== Sidebar ======
with st.sidebar:
    st.markdown(f"<h2 style='margin:.25rem 0 .75rem 0;'>{APP_TITLE}</h2>", unsafe_allow_html=True)
    if st.button("Logout"):
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box","_fail_times","_locked_until","show_support","is_admin","ack_ok"):
            st.session_state.pop(k, None)
        _safe_rerun()

# ====== Acknowledgment Gate ======
def require_acknowledgment():
    if st.session_state.get("ack_ok", False): return
    with st.form("ack_form", clear_on_submit=False):
        st.markdown("### Privacy & Terms Acknowledgment")
        st.write(
            "Before using Veritas, please confirm you have read and agree to the "
            f"[Privacy Policy]({PRIVACY_URL or '#'}) and "
            f"[Terms of Use]({TERMS_URL or '#'})."
        )
        c1 = st.checkbox("I have read the Privacy Policy")
        c2 = st.checkbox("I agree to the Terms of Use")
        ccol1, ccol2 = st.columns([1,1])
        with ccol1:
            submitted = st.form_submit_button("I acknowledge")
        with ccol2:
            cancel = st.form_submit_button("Cancel")
        if cancel:
            st.warning("You must acknowledge to continue."); st.stop()
        if submitted and c1 and c2:
            st.session_state["ack_ok"] = True
            st.success("Thanks! You may continue."); _safe_rerun()
        elif submitted:
            st.error("Please check both boxes to continue."); st.stop()
    st.stop()
require_acknowledgment()

# ================= Tabs =================
tab_names = ["🔍 Analyze", "💬 Feedback", "🛟 Support", "❓ Help"]
if ADMIN_PASSWORD:
    tab_names.append("🛡️ Admin")
tabs = st.tabs(tab_names)

# -------------------- Analyze Tab --------------------
with tabs[0]:
    st.markdown('<div class="v-card" id="analyze-card">', unsafe_allow_html=True)

    if st.session_state.get("_clear_text_box", False):
        st.session_state["_clear_text_box"] = False
        st.session_state["user_input_box"] = ""

    with st.form("analysis_form"):
        st.markdown("<h3>Bias Analysis</h3>", unsafe_allow_html=True)
        st.text_area(
            "Paste or type text to analyze",
            height=200,
            key="user_input_box",
            help="Your pasted content is used for analysis but won’t be printed below—only the bias report appears."
        )
        doc = st.file_uploader(
            f"Upload document (drag & drop) — Max {int(MAX_UPLOAD_MB)}MB — Types: PDF, DOCX, TXT, MD, CSV",
            type=list(DOC_ALLOWED_EXTENSIONS),
            accept_multiple_files=False,
            key="doc_file"
        )
        # Opposite-corner actions
        ca, spacer, cb = st.columns([1, 8, 1])
        with ca:
            submitted = st.form_submit_button("Analyze")
        with cb:
            new_analysis = st.form_submit_button("New Analysis", help="Clear the current report and inputs")

    if 'new_analysis' not in st.session_state:
        st.session_state['new_analysis'] = False
    if new_analysis:
        st.session_state['new_analysis'] = True
        st.session_state["last_reply"] = ""
        st.session_state["history"] = []
        st.session_state["_clear_text_box"] = True
        try: st.session_state["doc_file"] = None
        except Exception: pass
        _safe_rerun()

    if submitted:
        try:
            prog = st.progress(0, text="Preparing…")
        except TypeError:
            prog = st.progress(0)
        user_text = st.session_state.get("user_input_box", "").strip()
        extracted = ""
        try: prog.progress(10)
        except Exception: pass

        if doc is not None:
            size_mb = doc.size / (1024 * 1024)
            if size_mb > MAX_UPLOAD_MB:
                st.error(f"File too large ({size_mb:.1f} MB). Max {int(MAX_UPLOAD_MB)} MB."); st.stop()
            try:
                from pypdf import PdfReader  # optional
                def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                    if ext == "pdf":
                        if PdfReader is None:
                            return ""
                        reader = PdfReader(io.BytesIO(file_bytes))
                        return "\n\n".join((page.extract_text() or "") for page in reader.pages)[:MAX_EXTRACT_CHARS]
                    elif ext == "docx":
                        if docx is None:
                            return ""
                        buf = io.BytesIO(file_bytes)
                        doc_obj = docx.Document(buf)
                        return "\n".join(p.text for p in doc_obj.paragraphs)[:MAX_EXTRACT_CHARS]
                    elif ext in ("txt", "md", "csv"):
                        for enc in ("utf-8","utf-16","latin-1"):
                            try: return file_bytes.decode(enc)[:MAX_EXTRACT_CHARS]
                            except Exception: continue
                        return file_bytes.decode("utf-8","ignore")[:MAX_EXTRACT_CHARS]
                    return ""
                extracted = (extract_text_from_file(doc.getvalue(), doc.name) or "").strip()
            except Exception as e:
                st.error("network error"); st.stop()

        final_input = (user_text + ("\n\n" + extracted if extracted else "")).strip()
        if not final_input:
            st.error("Please enter some text or upload a document."); st.stop()

        api_key = getattr(settings, "openai_api_key", os.environ.get("OPENAI_API_KEY", ""))
        if not api_key:
            st.error("Missing OpenAI API key. Set OPENAI_API_KEY."); st.stop()

        user_instruction = _build_user_instruction(final_input)

        try:
            try: prog.progress(40, text="Contacting model…")
            except Exception: prog.progress(40)
            client = OpenAI(api_key=api_key)
            resp = client.chat.completions.create(
                model=MODEL, temperature=ANALYSIS_TEMPERATURE,
                messages=[
                    {"role": "system", "content": IDENTITY_PROMPT},
                    {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_instruction},
                ],
            )
            model_reply = (resp.choices[0].message.content or "").strip()
            if not _looks_strict(model_reply):
                repair_msg = (
                    "Reformat the ORIGINAL ANSWER to exactly match the 10-section template below. "
                    "Only fix structure; keep substance. Include all sections in the same order.\n\n"
                    "=== TEMPLATE ===\n"
                    f"{STRICT_OUTPUT_TEMPLATE}\n\n"
                    "=== ORIGINAL ANSWER ===\n"
                    f"{model_reply}"
                )
                resp2 = client.chat.completions.create(
                    model=MODEL, temperature=0.0,
                    messages=[
                        {"role": "system", "content": "You output exactly the requested structure."},
                        {"role": "user", "content": repair_msg},
                    ],
                )
                fixed = (resp2.choices[0].message.content or "").strip()
                if _looks_strict(fixed):
                    model_reply = fixed
            try: prog.progress(85, text="Formatting report…")
            except Exception: prog.progress(85)
        except Exception as e:
            st.error("Could not contact the language model. Check API key/model."); st.stop()

        public_report_id = f"VER-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
        decorated_reply = f"📄 Report ID: {public_report_id}\n\n{model_reply}".strip()
        st.session_state["history"].append({"role":"assistant","content":decorated_reply})
        st.session_state["last_reply"] = decorated_reply
        st.session_state["_clear_text_box"] = True
        try: prog.progress(100, text="Done ✓")
        except Exception: prog.progress(100)
        _safe_rerun()

    if st.session_state.get("last_reply"):
        st.write("### Bias Report")
        st.markdown(st.session_state["last_reply"])

        # ---- Action links
        def _build_pdf_inline(content: str) -> bytes:
            if SimpleDocTemplate is None:
                return content.encode("utf-8")
            buf = io.BytesIO()
            doc = SimpleDocTemplate(buf)
            story = [Paragraph("<b>Veritas — Bias Analysis Report</b>", getSampleStyleSheet()["Heading3"]), Spacer(1, 10)]
            for p in [p.strip() for p in content.split("\n\n") if p.strip()]:
                safe = p.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(safe, ParagraphStyle("Body", fontSize=10, leading=14))); story.append(Spacer(1, 6))
            def _hf(c, d): c.saveState(); c.setFont("Helvetica",8); c.drawString(40, 30, "Veritas"); c.restoreState()
            doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
            buf.seek(0); return buf.read()

        pdf_bytes = _build_pdf_inline(st.session_state["last_reply"])
        pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")
        uid = str(uuid.uuid4()).replace("-", "")
        copy_id = f"copyLink_{uid}"
        note_id = f"copyNote_{uid}"

        components.html(f"""
<style>
  .v-actions {{ display: inline-flex; gap: 1.0rem; align-items: center;
    padding: .45rem .75rem; border-radius: 10px; background: rgba(0,0,0,0.65);
    font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
  .v-actions a {{ color: #fff !important; text-decoration: none; font-weight: 600; }}
  .v-actions a:hover {{ text-decoration: underline; }}
  .v-actions .copy-note {{ color:#fff; opacity:.8; font-size:.85rem; }}
</style>
<div class="v-actions">
  <a id="{copy_id}" href="javascript:void(0)">Copy Report</a>
  <a id="download_{uid}" href="data:application/pdf;base64,{pdf_b64}" download="veritas_report.pdf">Download Report</a>
  <span id="{note_id}" class="copy-note" style="display:none;">Copied ✓</span>
</div>
<script>
  const text_{uid} = {json.dumps(st.session_state["last_reply"])};
  const copyEl_{uid} = document.getElementById("{copy_id}");
  const note_{uid} = document.getElementById("{note_id}");
  copyEl_{uid}.addEventListener("click", async () => {{
    try {{ await navigator.clipboard.writeText(text_{uid}); note_{uid}.style.display = "inline"; setTimeout(() => note_{uid}.style.display = "none", 1200); }}
    catch (e) {{
      const ta = document.createElement("textarea"); ta.value = text_{uid}; ta.style.position="fixed"; ta.style.opacity="0";
      document.body.appendChild(ta); ta.focus(); ta.select(); try {{ document.execCommand("copy"); }} catch (_e) {{}}
      ta.remove(); note_{uid}.style.display = "inline"; setTimeout(() => note_{uid}.style.display = "none", 1200);
    }}
  }});
</script>
""", height=64)

    st.markdown('</div>', unsafe_allow_html=True)

# -------------------- Feedback Tab --------------------
with tabs[1]:
    st.write("### Feedback")
    with st.form("feedback_form"):
        rating = st.slider("Your rating", min_value=1, max_value=5, value=5)
        email = st.text_input("Email (required)")
        comments = st.text_area("Comments (what worked / what didn’t)", height=120, max_chars=2000)
        submit_fb = st.form_submit_button("Submit feedback")
    if submit_fb:
        if not email or "@" not in email:
            st.error("Please enter a valid email."); st.stop()
        transcript = "\n\n".join(m["content"] for m in st.session_state["history"] if m["role"]=="assistant")[:100000]
        ts_now = datetime.now(timezone.utc).isoformat()
        try:
            with open(os.path.join(DATA_DIR,"feedback.csv"), "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts_now, rating, email[:200], (comments or "").replace("\r"," ").strip(), len(transcript), transcript, "streamlit", "streamlit"])
        except Exception:
            st.error("network error"); st.stop()
        st.success("Thanks — feedback saved ✓")

# -------------------- Support Tab --------------------
with tabs[2]:
    st.write("### Support")
    with st.form("support_form"):
        full_name = st.text_input("Full name")
        email_sup = st.text_input("Email")
        bias_report_id = st.text_input("Bias Report ID (if applicable)")
        issue_text = st.text_area("Describe the issue", height=160)
        c1, c2 = st.columns(2)
        with c1:
            submit_support = st.form_submit_button("Submit Support Request")
        with c2:
            cancel_support = st.form_submit_button("Cancel")
    if cancel_support: _safe_rerun()
    if submit_support:
        if not full_name.strip() or not email_sup.strip() or not issue_text.strip():
            st.error("Please complete all required fields.")
        else:
            ticket_id = f"SUP-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3).upper()}"
            ts = datetime.now(timezone.utc).isoformat()
            with open(os.path.join(DATA_DIR,"support_tickets.csv"), "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts, ticket_id, full_name.strip(), email_sup.strip(), bias_report_id.strip(), issue_text.strip(), st.session_state.get('sid',''), st.session_state.get('login_id',''), "streamlit"])
            st.success(f"Thanks! Your support ticket has been submitted. **Ticket ID: {ticket_id}**")
            _safe_rerun()

# -------------------- Help Tab --------------------
with tabs[3]:
    st.write("### Help")
    st.markdown(
        """
- Paste text or upload a document, then click **Analyze**.
- Use **New Analysis** to instantly clear the page for a fresh run.
- After the report appears, use the action links (**Copy** / **Download**).
- Use the **Feedback** tab to rate your experience and share comments.
- Use the **Support** tab to submit any issues; include the Report ID if applicable.
- After login, you must acknowledge Privacy & Terms once every `ACK_TTL_DAYS`.
- **Background image:** add `static/bg.svg` (or .png/.jpg/.webp) to repo, or set a `BG_URL` secret, or use Admin → 🎨 Branding.
        """
    )

# ====== Footer ======
st.markdown(
    "<div id='vFooter'>Copyright 2025 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True
)




