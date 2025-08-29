# streamlit_app.py — Veritas (Streamlit) with Email + SQLite storage + Lockout
import os
import io
import csv
import re
import time
import json
import hashlib
import secrets
import sqlite3
from typing import Optional
from datetime import timedelta, datetime, timezone
from zoneinfo import ZoneInfo
from collections import deque
from pathlib import Path

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
    SimpleDocTemplate = None  # will error politely if missing

# ================= Updated Config (via config.py) =================
# Provide a minimal loader fallback if you don't have config.py
try:
    from config import load_settings
    settings = load_settings()  # requires OPENAI_API_KEY available to it
except Exception:
    class _FallbackSettings:
        openai_api_key = os.environ.get("OPENAI_API_KEY", "")
        openai_model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo-0125")
        auth_log_ttl_days = int(os.environ.get("AUTH_LOG_TTL_DAYS", "365"))
    settings = _FallbackSettings()

# ================= App constants from secrets/env =================
APP_TITLE = os.environ.get("APP_TITLE", "Veritas — Pilot Test")
MODEL = getattr(settings, "openai_model", os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo-0125"))
try:
    TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
except Exception:
    TEMPERATURE = 0.2

# --- Safe timezone loader ---
def _safe_zoneinfo(name: str, fallback: str = "UTC") -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo(fallback)

PILOT_TZ_NAME = os.environ.get("VERITAS_TZ", "America/Denver")
PILOT_TZ = _safe_zoneinfo(PILOT_TZ_NAME, "UTC")
PILOT_START_AT = os.environ.get("PILOT_START_AT", "")  # e.g., "2025-09-15 08:00" or ISO

def _parse_pilot_start_to_utc(s: str):
    if not s:
        return None
    try:
        if "T" in s:
            if s.endswith("Z"):
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            else:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=PILOT_TZ)
        else:
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M").replace(tzinfo=PILOT_TZ)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

PILOT_START_UTC = _parse_pilot_start_to_utc(PILOT_START_AT)

def pilot_started() -> bool:
    if PILOT_START_UTC is None:
        return True
    return datetime.now(timezone.utc) >= PILOT_START_UTC

# Rates / windows
RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT  = int(os.environ.get("RATE_LIMIT_CHAT",  "6"))
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

# SendGrid (email)
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_TO       = os.environ.get("SENDGRID_TO", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT  = os.environ.get("SENDGRID_SUBJECT", "New Veritas feedback")

# Password gate (optional)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# Lockout config
LOCKOUT_THRESHOLD      = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))       # failed attempts
LOCKOUT_WINDOW_SEC     = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))    # 15 min
LOCKOUT_DURATION_SEC   = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800")) # 30 min

# Storage / branding
BASE_DIR     = os.path.dirname(__file__)
STATIC_DIR   = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER= os.path.join(STATIC_DIR, "uploads")  # logos only
DATA_DIR     = os.path.join(BASE_DIR, "data")
DB_PATH      = os.path.join(DATA_DIR, "veritas.db")
FEEDBACK_CSV = os.path.join(DATA_DIR, "feedback.csv")
ERRORS_CSV   = os.path.join(DATA_DIR, "errors.csv")
AUTH_CSV     = os.path.join(DATA_DIR, "auth_events.csv")
ANALYSES_CSV = os.path.join(DATA_DIR, "analyses.csv")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

ALLOWED_EXTENSIONS     = {"png", "jpg", "jpeg", "webp"}           # logo types
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}      # upload types

# ---------- SQLite setup ----------
def _init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            event_type TEXT,        -- login_success, login_failed, logout, login_lockout
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
    con.commit()
    con.close()

def _db_exec(query: str, params: tuple):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(query, params)
    con.commit()
    con.close()

_init_db()

# Initialize CSV headers if missing (kept for redundancy/export)
if not os.path.exists(AUTH_CSV):
    with open(AUTH_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc","event_type","login_id","session_id","tracking_id",
            "credential_label","success","hashed_attempt_prefix","remote_addr","user_agent"
        ])

if not os.path.exists(ANALYSES_CSV):
    with open(ANALYSES_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc","public_report_id","internal_report_id","session_id","login_id",
            "remote_addr","user_agent","conversation_chars","conversation_json"
        ])

if not os.path.exists(FEEDBACK_CSV):
    with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc","rating","email","comments","conversation_chars","conversation","remote_addr","ua"
        ])

if not os.path.exists(ERRORS_CSV):
    with open(ERRORS_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc","error_id","request_id","route","kind","http_status","detail",
            "session_id","login_id","remote_addr","user_agent"
        ])

# Default tagline + logo autodetect
CURRENT_TAGLINE = (os.environ.get("VERITAS_TAGLINE", "") or "").strip()
CURRENT_LOGO_FILENAME = None
if os.path.isdir(UPLOAD_FOLDER):
    for f in os.listdir(UPLOAD_FOLDER):
        name = f.lower()
        if name.startswith("logo.") and name.rsplit(".", 1)[-1] in ALLOWED_EXTENSIONS:
            CURRENT_LOGO_FILENAME = f
            break

# Startup marker
STARTED_AT_ISO = datetime.now(timezone.utc).isoformat()

# ===== Identity + Veritas Prompts =====
IDENTITY_PROMPT = "I'm Veritas — a bias detection tool."

DEFAULT_SYSTEM_PROMPT = """
[Truncated here for brevity — keep your full prompt exactly as in your current file]
""".strip()  # <-- replace with your full prompt text (you already have it above)

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

def _safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")

def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "pdf":
        if PdfReader is None:
            return ""
        reader = PdfReader(io.BytesIO(file_bytes))
        parts = []
        for page in reader.pages:
            try:
                parts.append(page.extract_text() or "")
            except Exception:
                continue
        return "\n\n".join(parts)[:MAX_EXTRACT_CHARS]
    elif ext == "docx":
        if docx is None:
            return ""
        buf = io.BytesIO(file_bytes)
        doc_obj = docx.Document(buf)
        text = "\n".join(p.text for p in doc_obj.paragraphs)
        return text[:MAX_EXTRACT_CHARS]
    elif ext in ("txt", "md", "csv"):
        return _safe_decode(file_bytes)[:MAX_EXTRACT_CHARS]
    return ""

# ---- Error logging + unified user message ----
def log_error_event(kind: str, route: str, http_status: int, detail: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        eid = _gen_error_id()
        rid = st.session_state.get("request_id") or _gen_request_id()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"
        ua = "streamlit"
        safe_detail = (detail or "")[:500]
        # CSV
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua])
        # DB
        _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                 (ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua))
        print(f"[{ts}] ERROR {eid} (req {rid}) {route} {kind} {http_status} :: {safe_detail}")
        return eid
    except Exception as e:
        print("Error log failure:", repr(e))
        return None

def network_error():
    st.error("network error")

# ---- Rate limit (per session) ----
def rate_limiter(key: str, limit: int, window_sec: int) -> bool:
    dq_map = st.session_state.setdefault("_rate_map", {})
    dq = dq_map.get(key)
    now = time.time()
    if dq is None:
        dq = deque()
        dq_map[key] = dq
    cutoff = now - window_sec
    while dq and dq[0] < cutoff:
        dq.popleft()
    if len(dq) >= limit:
        log_error_event(kind="RATE_LIMIT", route=key, http_status=429, detail=f"limit={limit}/{window_sec}s")
        return False
    dq.append(now)
    return True

def log_auth_event(event_type: str, success: bool, login_id: str = "", credential_label: str = "APP_PASSWORD", attempted_secret: Optional[str] = None):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        tid = _gen_tracking_id()
        addr = "streamlit"
        ua = "streamlit"
        hashed_prefix = ""
        if attempted_secret and not success:
            hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8")).hexdigest()[:12]
        row = [ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, success, hashed_prefix, addr, ua]
        # CSV
        with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        # DB
        _db_exec("""INSERT INTO auth_events (timestamp_utc,event_type,login_id,session_id,tracking_id,credential_label,success,hashed_attempt_prefix,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                 (ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, 1 if success else 0, hashed_prefix, addr, ua))
        st.session_state["last_tracking_id"] = tid
        return tid
    except Exception as e:
        print("Auth log error:", repr(e))
        return None

def log_analysis(public_id: str, internal_id: str, assistant_text: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"
        ua = "streamlit"
        conv_obj = {"assistant_reply": assistant_text}
        conv_json = json.dumps(conv_obj, ensure_ascii=False)
        conv_chars = len(conv_json)
        # CSV
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json])
        # DB
        _db_exec("""INSERT INTO analyses (timestamp_utc,public_report_id,internal_report_id,session_id,login_id,remote_addr,user_agent,conversation_chars,conversation_json)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                 (ts, public_report_id, internal_report_id, sid, login_id, addr, ua, conv_chars, conv_json))
    except Exception as e:
        print("Analysis log error:", repr(e))

# ---- Pruning (TTL) ----
def _prune_csv_by_ttl(path: str, ttl_days: int):
    try:
        if ttl_days <= 0 or not os.path.exists(path):
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)
        with open(path, "r", encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        if not rows:
            return
        header, data = rows[0], rows[1:]
        kept = []
        for row in data:
            try:
                ts = datetime.fromisoformat(row[0])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                kept.append(row)
                continue
            if ts >= cutoff:
                kept.append(row)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(kept)
    except Exception as e:
        log_error_event(kind="PRUNE", route="boot", http_status=200, detail=repr(e))

# Prune at app start (runs once per process)
_prune_csv_by_ttl(AUTH_CSV, AUTH_LOG_TTL_DAYS)
_prune_csv_by_ttl(ANALYSES_CSV, ANALYSES_LOG_TTL_DAYS)
_prune_csv_by_ttl(FEEDBACK_CSV, FEEDBACK_LOG_TTL_DAYS)
_prune_csv_by_ttl(ERRORS_CSV, ERRORS_LOG_TTL_DAYS)

# ================= Streamlit UI =================
st.set_page_config(page_title=APP_TITLE, page_icon="🧭", layout="centered")

# Global CSS
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif !important;
    }

    div.stButton > button,
    div.stDownloadButton > button,
    [data-testid="stFileUploader"] section div div span button,
    .stForm [type="submit"],
    button[kind="primary"], button[kind="secondary"],
    [data-testid="baseButton-secondary"], [data-testid="baseButton-primary"] {
        background-color: #FF8C32 !important;
        color: #111418 !important;
        border: 1px solid #FF8C32 !important;
        border-radius: 0.5rem !important;
        box-shadow: none !important;

        padding: 0.50rem 1rem !important;
        font-size: 0.95rem !important;
        font-weight: 400 !important;
        text-align: center !important;
        width: 100% !important;
    }
    div.stButton > button:hover,
    div.stDownloadButton > button:hover,
    [data-testid="stFileUploader"] section div div span button:hover,
    .stForm [type=submit]:hover,
    button[kind="primary"]:hover, button[kind="secondary"]:hover,
    [data-testid="baseButton-secondary"]:hover, [data-testid="baseButton-primary"]:hover {
        background-color: #E97C25 !important;
        border-color: #E97C25 !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Header with logo + tagline
col_logo, col_title = st.columns([1, 6])
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
            pass

with col_title:
    st.markdown("<h1 style='text-align:center;margin:0;'>Veritas — Pilot Test</h1>", unsafe_allow_html=True)
    if CURRENT_TAGLINE:
        st.caption(CURRENT_TAGLINE)

# Session request_id
if "request_id" not in st.session_state:
    st.session_state["request_id"] = _gen_request_id()

# Auth/session state init
st.session_state.setdefault("authed", False)
st.session_state.setdefault("history", [])     # ONLY assistant messages stored here
st.session_state.setdefault("last_reply", "")
st.session_state.setdefault("user_input_box", "")
st.session_state.setdefault("_clear_text_box", False)

# Lockout state (per session)
st.session_state.setdefault("_fail_times", deque())  # timestamps of failed logins
st.session_state.setdefault("_locked_until", 0.0)    # epoch seconds

# Pilot countdown
if not pilot_started():
    st.info("Pilot hasn’t started yet.")
    if PILOT_START_UTC:
        now = datetime.now(timezone.utc)
        remaining = PILOT_START_UTC - now
        secs = int(max(0, remaining.total_seconds()))
        dd = secs // 86400
        hh = (secs % 86400) // 3600
        mm = (secs % 3600) // 60
        ss = secs % 60
        local_str = PILOT_START_UTC.astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
        st.write(f"Opens on **{local_str}** · Countdown: **{dd}d {hh:02}:{mm:02}:{ss:02}**")
        st.stop()

# Login panel (only if APP_PASSWORD set)
def _is_locked() -> bool:
    return time.time() < st.session_state["_locked_until"]

def _note_failed_login(attempted_secret: str = ""):
    # prune old failures
    now = time.time()
    dq = st.session_state["_fail_times"]
    cutoff = now - LOCKOUT_WINDOW_SEC
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)
    # log failed
    log_auth_event("login_failed", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD", attempted_secret=attempted_secret)
    # lock if threshold reached
    if len(dq) >= LOCKOUT_THRESHOLD:
        st.session_state["_locked_until"] = now + LOCKOUT_DURATION_SEC
        log_auth_event("login_lockout", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD")

def show_login():
    with st.form("login_form"):
        st.subheader("Login")
        login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id", ""))
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("Enter")
        if submit:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60)
                secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                network_error()
                st.stop()
            if pwd == APP_PASSWORD:
                st.session_state["authed"] = True
                st.session_state["login_id"] = (login_id or "").strip()
                st.session_state["_fail_times"].clear()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=st.session_state["login_id"], credential_label="APP_PASSWORD")
                st.success("Logged in.")
                st.rerun()
            else:
                _note_failed_login(attempted_secret=pwd)
                st.error("Incorrect password")

if not st.session_state["authed"] and APP_PASSWORD:
    show_login()
    st.stop()
elif not APP_PASSWORD:
    _get_sid()
    if "login_id" not in st.session_state:
        st.session_state["login_id"] = ""
    log_auth_event("login_success", True, login_id="", credential_label="NO_PASSWORD")
    st.session_state["authed"] = True

# ================= Sidebar (admin hidden) =================
with st.sidebar:
    if st.button("Logout"):
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label="APP_PASSWORD")
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box","_fail_times","_locked_until"):
            st.session_state.pop(k, None)
        st.rerun()
    st.subheader("Session")
    st.write(f"Report time zone: **{PILOT_TZ_NAME}**")

# ===== Chat / Analysis UI =====
st.divider()
st.subheader("Bias Analysis")

# Clear text box only after a completed run
if st.session_state.get("_clear_text_box", False):
    st.session_state["_clear_text_box"] = False
    st.session_state["user_input_box"] = ""

with st.form("analysis_form"):
    st.text_area(
        "Paste or type text to analyze",
        height=180,
        key="user_input_box",
        help="Your pasted content is used for analysis but won’t be printed below—only the bias report appears."
    )
    doc = st.file_uploader(
        f"Upload document (drag & drop) — Max {int(MAX_UPLOAD_MB)}MB — Types: PDF, DOCX, TXT, MD, CSV",
        type=list(DOC_ALLOWED_EXTENSIONS),
        accept_multiple_files=False
    )
    submitted = st.form_submit_button("Analyze")

    if submitted:
        if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
            network_error()
            st.stop()

        # Gather inputs
        user_text = st.session_state.get("user_input_box", "").strip()
        extracted = ""
        if doc is not None:
            size_mb = doc.size / (1024 * 1024)
            if size_mb > MAX_UPLOAD_MB:
                st.error(f"File too large ({size_mb:.1f} MB). Max {int(MAX_UPLOAD_MB)} MB.")
                st.stop()
            try:
                with st.spinner("Extracting…"):
                    extracted = extract_text_from_file(doc.getvalue(), doc.name)
                    extracted = (extracted or "").strip()
            except Exception as e:
                log_error_event(kind="EXTRACT", route="/extract", http_status=500, detail=repr(e))
                network_error()
                st.stop()

        final_input = (user_text + ("\n\n" + extracted if extracted else "")).strip()
        if not final_input:
            st.error("Please enter some text or upload a document.")
            st.stop()

        # Call model (report-only UI)
        try:
            with st.spinner("Analyzing…"):
                client = OpenAI(api_key=getattr(settings, "openai_api_key", os.environ.get("OPENAI_API_KEY", "")))
                resp = client.chat.completions.create(
                    model=MODEL,
                    temperature=TEMPERATURE,
                    messages=[
                        {"role": "system", "content": IDENTITY_PROMPT},
                        {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                        {"role": "user", "content": final_input},
                    ],
                )
                model_reply = resp.choices[0].message.content or ""
        except Exception as e:
            log_error_event(kind="OPENAI", route="/chat", http_status=502, detail=repr(e))
            network_error()
            st.stop()

        # Prepare report-only output
        public_report_id = _gen_public_report_id()
        internal_report_id = _gen_internal_report_id()
        decorated_reply = f"📄 Report ID: {public_report_id}\n\n{model_reply}".strip()

        # Save only the assistant reply in visible history
        st.session_state["history"].append({"role":"assistant","content":decorated_reply})
        st.session_state["last_reply"] = decorated_reply

        # Persist analysis snapshot (assistant only)
        try:
            log_analysis(public_report_id, internal_report_id, decorated_reply)
        except Exception as e:
            log_error_event(kind="ANALYSIS_LOG", route="/chat", http_status=200, detail=repr(e))

        # Clear input box on next render
        st.session_state["_clear_text_box"] = True
        st.rerun()

# ===== Bias Report (ONLY assistant output) =====
if st.session_state.get("last_reply"):
    st.write("### Bias Report")
    st.markdown(st.session_state["last_reply"])

    # ===== Report Action Buttons (only when a report exists) =====
    st.divider()
    col1, col2, col3 = st.columns(3)

    with col1:
        # Copy Report (HTML/JS)
        components.html(
            f"""
<style>
  .copy-btn {{
    width: 100%;
    display: inline-block;
    cursor: pointer;
    background: #FF8C32;
    color: #111418;
    border: 1px solid #FF8C32;
    padding: 0.50rem 1rem;
    border-radius: 0.5rem;
    font-size: 0.95rem;
    font-weight: 400;
    line-height: 1.6;
    font-family: inherit;
    text-align: center;
  }}
  .copy-btn:hover {{ background:#E97C25; border-color:#E97C25; }}
  .copy-note {{ font-size: 12px; opacity: .75; margin-top: 6px; }}
</style>
<button id="copyBtn" class="copy-btn">Copy Report</button>
<div id="copyNote" class="copy-note" style="display:none;">Copied ✓</div>
<script>
  const text = {json.dumps(st.session_state["last_reply"])};
  const btn = document.getElementById("copyBtn");
  const note = document.getElementById("copyNote");
  btn.addEventListener("click", async () => {{
    try {{
      await navigator.clipboard.writeText(text);
      note.style.display = "block";
      setTimeout(() => note.style.display = "none", 1200);
    }} catch (e) {{
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try {{ document.execCommand("copy"); }} catch (_e) {{}}
      ta.remove();
      note.style.display = "block";
      setTimeout(() => note.style.display = "none", 1200);
    }}
  }});
</script>
            """,
            height=90,
        )

    with col2:
        if st.button("Clear Report"):
            st.session_state["history"] = []
            st.session_state["last_reply"] = ""
            st.rerun()

    with col3:
        # Download Report (PDF)
        try:
            if st.session_state["last_reply"]:
                def build_pdf_bytes(content: str) -> bytes:
                    if SimpleDocTemplate is None:
                        raise RuntimeError("PDF engine not available. Install 'reportlab'.")
                    buf = io.BytesIO()
                    doc = SimpleDocTemplate(
                        buf, pagesize=letter,
                        leftMargin=0.8*inch, rightMargin=0.8*inch,
                        topMargin=0.9*inch, bottomMargin=0.9*inch
                    )
                    styles = getSampleStyleSheet()
                    base = styles["Normal"]
                    base.leading = 14
                    base.fontName = "Helvetica"
                    body = ParagraphStyle("Body", parent=base, fontSize=10)
                    h = ParagraphStyle("H", parent=base, fontSize=12, spaceAfter=8, leading=14)

                    story = []
                    title = APP_TITLE + " — Bias Analysis Report"
                    ts = datetime.now().astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
                    story.append(Paragraph(f"<b>{title}</b>", h))
                    story.append(Paragraph(f"<i>Generated {ts}</i>", base))
                    story.append(Spacer(1, 10))

                    for p in [p.strip() for p in content.split("\n\n") if p.strip()]:
                        safe = p.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                        story.append(Paragraph(safe, body))
                        story.append(Spacer(1, 6))

                    def _header_footer(canvas, doc_):
                        canvas.saveState()
                        w, h = letter
                        footer = f"Veritas — {datetime.now().strftime('%Y-%m-%d')}"
                        page = f"Page {doc_.page}"
                        canvas.setFont("Helvetica", 8)
                        canvas.drawString(0.8*inch, 0.55*inch, footer)
                        pw = stringWidth(page, "Helvetica", 8)
                        canvas.drawString(w - 0.8*inch - pw, 0.55*inch, page)
                        canvas.restoreState()

                    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
                    buf.seek(0)
                    return buf.read()

                pdf_bytes = build_pdf_bytes(st.session_state["last_reply"])
                st.download_button("Download Report (PDF)", data=pdf_bytes, file_name="veritas_report.pdf", mime="application/pdf")
        except Exception as e:
            log_error_event(kind="PDF", route="/download", http_status=500, detail=repr(e))
            st.error("network error")

# ===== Feedback (stores only assistant content in transcript) =====
st.divider()
st.subheader("Feedback")
with st.form("feedback_form"):
    rating = st.slider("Your rating", min_value=1, max_value=5, value=5)
    email = st.text_input("Email (required)")
    comments = st.text_area("Comments (what worked / what didn’t)", height=120, max_chars=2000)
    submit_fb = st.form_submit_button("Submit feedback")
    if submit_fb:
        if not rate_limiter("feedback", RATE_LIMIT_EXTRACT, RATE_LIMIT_WINDOW_SEC):
            network_error()
            st.stop()
        EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if not email or not EMAIL_RE.match(email):
            st.error("Please enter a valid email.")
            st.stop()

        # transcript includes only assistant output
        lines = []
        for m in st.session_state["history"]:
            if m["role"] == "assistant":
                lines.append("Assistant: " + m["content"])
        transcript = "\n\n".join(lines)[:100000]
        conv_chars = len(transcript)

        ts_now = datetime.now(timezone.utc).isoformat()
        row = [
            ts_now,
            rating, email[:200], (comments or "").replace("\r", " ").strip(),
            conv_chars, transcript,
            "streamlit", "streamlit"
        ]
        # CSV
        try:
            with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(row)
        except Exception as e:
            log_error_event(kind="FEEDBACK", route="/feedback", http_status=500, detail=repr(e))
            network_error()
            st.stop()
        # DB
        try:
            _db_exec("""INSERT INTO feedback (timestamp_utc,rating,email,comments,conversation_chars,conversation,remote_addr,ua)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (ts_now, rating, email[:200], (comments or "").replace("\r", " ").strip(), conv_chars, transcript, "streamlit", "streamlit"))
        except Exception as e:
            log_error_event(kind="FEEDBACK_DB", route="/feedback", http_status=200, detail=repr(e))

        # ---- Email (required fields) ----
        if not (SENDGRID_API_KEY and SENDGRID_TO and SENDGRID_FROM):
            st.error("Feedback email not sent — please configure SENDGRID_API_KEY, SENDGRID_FROM, and SENDGRID_TO.")
        else:
            try:
                timestamp = ts_now
                conv_preview = transcript[:2000]
                plain = (
                    f"New Veritas feedback\nTime (UTC): {timestamp}\nRating: {rating}/5\n"
                    f"From user email: {email}\nComments:\n{comments}\n\n"
                    f"--- Report (first 2,000 chars) ---\n{conv_preview}\n\n"
                    f"IP: streamlit\nUser-Agent: streamlit\n"
                )
                html_body = (
                    f"<h3>New Veritas feedback</h3>"
                    f"<p><strong>Time (UTC):</strong> {timestamp}</p>"
                    f"<p><strong>Rating:</strong> {rating}/5</p>"
                    f"<p><strong>From user email:</strong> {email}</p>"
                    f"<p><strong>Comments:</strong><br>{(comments or '').replace(chr(10), '<br>')}</p>"
                    f"<hr><p><strong>Report (first 2,000 chars):</strong><br>"
                    f"<pre style='white-space:pre-wrap'>{conv_preview}</pre></p>"
                    f"<hr><p><strong>IP:</strong> streamlit<br><strong>User-Agent:</strong> streamlit</p>"
                )
                payload = {
                    "personalizations": [{"to": [{"email": SENDGRID_TO}]}],
                    "from": {"email": SENDGRID_FROM, "name": "Veritas"},
                    "subject": SENDGRID_SUBJECT,
                    "content": [{"type": "text/plain", "value": plain}, {"type": "text/html", "value": html_body}],
                }
                with httpx.Client(timeout=12) as client:
                    r = client.post(
                        "https://api.sendgrid.com/v3/mail/send",
                        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"},
                        json=payload,
                    )
                if r.status_code not in (200, 202):
                    log_error_event(kind="SENDGRID", route="/feedback", http_status=r.status_code, detail=r.text)
                    st.error("Feedback saved but email failed to send.")
                else:
                    st.success("Thanks — feedback saved and emailed ✓")
            except Exception as e:
                log_error_event(kind="SENDGRID_EXC", route="/feedback", http_status=200, detail=repr(e))
                st.error("Feedback saved but email failed to send.")

# Footer
st.caption(f"Started at (UTC): {STARTED_AT_ISO}")




