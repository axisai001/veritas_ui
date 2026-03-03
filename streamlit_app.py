# streamlit_app.py — Veritas (Streamlit) — v4 Governance Baseline
# Output schema: plain text only
# Required sections: Objective Findings + Advisory Guidance (always present)
# No per-report disclaimers. No Fact/Bias/Explanation fields. No scoring/labels.
# Analysis ID displayed at application level (not part of analytical output).
#
# Includes:
# - User/Admin login gate (password-gated)
# - Privacy/Terms acknowledgment gate for non-admins (persisted)
# - Refusal routing (refusal_router.py) + refusal telemetry (CSV + SQLite)
# - Analysis logging (CSV + SQLite) WITHOUT storing full user text
# - PDF/DOCX/TXT/MD/CSV text extraction
# - Post-analysis feedback form (CSV + SQLite) tied to Analysis ID
#
# Dependencies:
#   streamlit, openai, pandas, python-docx, pypdf

import os
import io
import re
import csv
import time
import hmac
import uuid
import json
import hashlib
import secrets
import sqlite3
import unicodedata
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
from openai import OpenAI

# =============================================================================
# VER-B2B-007 — Internal Console Isolation Guardrail (fail-closed, but no crash)
# =============================================================================
def _get_setting(name: str, default: str = "") -> str:
    """Env-first, then Streamlit secrets. Returns stripped string."""
    v = (os.getenv(name) or "").strip()
    if v:
        return v
    try:
        v = (st.secrets.get(name) or "").strip()
    except Exception:
        v = ""
    return v or default

APP_MODE = _get_setting("APP_MODE", "")
BYPASS = _get_setting("INTERNAL_CONSOLE_BYPASS", "0")

if APP_MODE != "internal_console" and BYPASS != "1":
    st.set_page_config(page_title="Veritas", layout="centered")
    st.error("Internal console is disabled in this environment.")
    st.caption(
        "Set APP_MODE=internal_console (env or Streamlit Secrets) to enable this Streamlit UI."
    )
    st.stop()

# Refusal Router (required companion file)
from refusal_router import check_refusal, render_refusal, RefusalResult

# =============================================================================
# CONFIG
# =============================================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"

for p in (DATA_DIR, STATIC_DIR, UPLOAD_DIR):
    p.mkdir(parents=True, exist_ok=True)

APP_TITLE = (_get_setting("APP_TITLE", "Veritas")).strip()

# OpenAI
MODEL_NAME = (_get_setting("OPENAI_MODEL", "") or "gpt-4.1-mini").strip()
TEMPERATURE = float(_get_setting("OPENAI_TEMPERATURE", "0.2"))

# --- Trial Feedback (toggleable) ---
INSTITUTIONAL_TRIAL_MODE = (_get_setting("INSTITUTIONAL_TRIAL_MODE", "1")).strip() == "1"
MAX_FEEDBACK_COMMENT_CHARS = int(_get_setting("MAX_FEEDBACK_COMMENT_CHARS", "2000"))

# --- ENFORCED OpenAI key wiring (Env-first fallback + secrets) ---
def _get_openai_api_key() -> str:
    api_key = (_get_setting("OPENAI_API_KEY", "") or "").strip()
    return api_key

def get_openai_client() -> OpenAI:
    api_key = _get_openai_api_key()
    if not api_key:
        # Streamlit will redact raw RuntimeError details, so show it cleanly instead.
        st.error("OPENAI_API_KEY is not configured for this instance.")
        st.caption("Set OPENAI_API_KEY in Streamlit Secrets or environment variables.")
        st.stop()
    return OpenAI(api_key=api_key)

# Auth (set via Streamlit secrets or environment variables)
APP_PASSWORD = (_get_setting("APP_PASSWORD", "")).strip()
ADMIN_PASSWORD = (_get_setting("ADMIN_PASSWORD", "")).strip()

# Optional admin email allowlist (recommended for B2B admin access)
ADMIN_EMAILS = set()
_raw_admin_emails = (_get_setting("ADMIN_EMAILS", "")).strip()
if _raw_admin_emails:
    ADMIN_EMAILS = {e.strip().lower() for e in _raw_admin_emails.split(",") if e.strip()}

# Privacy / Terms (optional but used for acknowledgment gate)
PRIVACY_URL = (_get_setting("PRIVACY_URL", "")).strip()
TERMS_URL = (_get_setting("TERMS_URL", "")).strip()

# Upload limits
MAX_UPLOAD_MB = float(_get_setting("MAX_UPLOAD_MB", "10"))
MAX_EXTRACT_CHARS = int(_get_setting("MAX_EXTRACT_CHARS", "50000"))
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}

# Logging (CSV + SQLite)
DB_PATH = str(DATA_DIR / "veritas.db")

# Ensure ALL modules (tenant_store, admin tools, etc.) use the SAME DB
# IMPORTANT: must be set BEFORE importing tenant_store.
os.environ["DB_PATH"] = DB_PATH  # force single source of truth

ANALYSES_CSV = str(DATA_DIR / "analyses.csv")
ERRORS_CSV = str(DATA_DIR / "errors.csv")
AUTH_CSV = str(DATA_DIR / "auth_events.csv")
ACK_CSV = str(DATA_DIR / "ack_events.csv")
REFUSALS_CSV = str(DATA_DIR / "refusal_telemetry.csv")
FEEDBACK_CSV = str(DATA_DIR / "feedback_events.csv")

# Rate limiting + lockout
RATE_LIMIT_LOGIN = int(_get_setting("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT = int(_get_setting("RATE_LIMIT_CHAT", "6"))
RATE_LIMIT_WINDOW_SEC = int(_get_setting("RATE_LIMIT_WINDOW_SEC", "60"))

LOCKOUT_THRESHOLD = int(_get_setting("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC = int(_get_setting("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC = int(_get_setting("LOCKOUT_DURATION_SEC", "1800"))

# TTL pruning
TTL_DAYS_DEFAULT = int(_get_setting("LOG_TTL_DAYS", "365"))

# =============================================================================
# TENANT / B2B IMPORTS (AFTER DB_PATH IS FORCED)
# =============================================================================
from tenant_store import (
    init_tenant_tables,
    verify_tenant_key,
    current_period_yyyy,
    get_usage,
    increment_usage,
    admin_create_tenant,
    suspend_tenant,
    rotate_key,
    admin_get_tenant,
    admin_list_tenant_keys,
    admin_get_usage,
    admin_usage_snapshot,
)

# =============================================================================
# VERITAS v4 SYSTEM PROMPT (STRICT)
# =============================================================================
DEFAULT_SYSTEM_PROMPT = """
OUTPUT FORMAT (STRICT):
Return plain text ONLY (no JSON). Use EXACTLY these two section headings, spelled exactly as shown, each on its own line:

Objective Findings
<1–6 bullet points. Text-bound, descriptive. No determinations. No labels like “Bias Detected”, “Evidence”, “Explanation”, “Fact”, “Revision”. No scoring. No category labels.>

Advisory Guidance
<1–6 bullet points. Implementation-oriented guidance intended for the customer. Must be non-prescriptive (no “must/required”). Use “Consider/May/Optionally”. No disclaimers.>

PROHIBITED:
- Any of the following anywhere in the output: "Fact:", "Bias:", "Bias Detected:", "Explanation:", "Evidence:", "Revision:", "{", "}", "JSON"
- Any disclaimer language inside the report
- Any numeric scoring, labels, or categories
- Any authoritative determinations ("this is biased", "this violates", "non-compliant", etc.)

REQUIRED:
- Both sections must always appear (even if minimal).
""".strip()

# =============================================================================
# STREAMLIT PAGE
# =============================================================================
st.set_page_config(page_title=APP_TITLE, layout="centered")

st.markdown(
    """
    <style>

    /* ============================= */
    /* GLOBAL DARK ROYAL BLUE THEME */
    /* ============================= */

    html, body, [data-testid="stAppViewContainer"] {
        background-color: #0B1F3B !important;
        color: #FFFFFF !important;
    }

    .stApp {
        background-color: #0B1F3B !important;
        color: #FFFFFF !important;
    }

    /* ============================= */
    /* REMOVE STREAMLIT GREEN HEADER */
    /* ============================= */

    header[data-testid="stHeader"] {
        background-color: #0B1F3B !important;
        height: 0px !important;
    }

    header[data-testid="stHeader"] > div {
        background-color: #0B1F3B !important;
    }

    /* Remove toolbar / footer */
    [data-testid="stToolbar"] { visibility: hidden !important; height: 0 !important; }
    #MainMenu { visibility: hidden !important; }
    footer { visibility: hidden !important; }

    /* ============================= */
    /* SIDEBAR */
    /* ============================= */

    section[data-testid="stSidebar"] {
        background-color: #08172B !important;
    }

    /* ============================= */
    /* BUTTONS (BRIGHT ORANGE) */
    /* ============================= */

    div.stButton > button {
        background-color: #FF7A00 !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        border-radius: 6px !important;
        border: none !important;
    }

    div.stButton > button:hover {
        background-color: #E06600 !important;
    }
    
    /* ============================= */
    /* FORM SUBMIT BUTTONS (ORANGE) */
    /* ============================= */

    div[data-testid="stFormSubmitButton"] > button {
        background-color: #FF7A00 !important;
        color: #FFFFFF !important;
        font-weight: 700 !important;
        border-radius: 6px !important;
        border: none !important;
    }

    div[data-testid="stFormSubmitButton"] > button:hover {
    background-color: #E06600 !important;
    }

    /* ============================= */
    /* INPUT FIELDS */
    /* ============================= */

    input, textarea {
        background-color: #132B4F !important;
        color: #FFFFFF !important;
        border-radius: 6px !important;
        border: 1px solid #1E3A66 !important;
    }

    /* Fix password visibility icon background */
    button[kind="secondary"] {
        background-color: #132B4F !important;
    }

    /* ============================= */
    /* RADIO BUTTONS (NEUTRAL) */
    /* ============================= */

    div[role="radiogroup"] label {
        color: #FFFFFF !important;
        background-color: transparent !important;
    }

    input[type="radio"]:checked + div {
        background-color: transparent !important;
        border-color: #FFFFFF !important;
    }

    /* ============================= */
    /* TABS */
    /* ============================= */

    button[role="tab"] {
        background-color: #132B4F !important;
        color: #FFFFFF !important;
    }

    /* ============================= */
    /* DATAFRAMES */
    /* ============================= */

    .stDataFrame {
        background-color: #132B4F !important;
    }

    /* ============================= */
    /* LOGIN TITLE CLASS */
    /* ============================= */

    .login-title {
        color: #FF7A00 !important;
        font-weight: 800 !important;
        margin-bottom: 0.5rem !important;
    }

    </style>
    """,
    unsafe_allow_html=True,
)

# =============================================================================
# UTILITIES
# =============================================================================
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()

def _safe_preview(text: str, max_chars: int = 220) -> str:
    t = (text or "").replace("\n", " ").strip()
    return (t[:max_chars] + "…") if len(t) > max_chars else t

def _safe_rerun() -> None:
    try:
        st.rerun()
    except Exception:
        try:
            st.experimental_rerun()
        except Exception:
            pass

def _norm(s: str) -> str:
    return unicodedata.normalize("NFC", str(s)).strip()

def ensure_session_id() -> str:
    sid = st.session_state.get("sid")
    if not sid:
        sid = secrets.token_hex(16)
        st.session_state["sid"] = sid
    return sid

def new_request_id(prefix: str = "RQ") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    rid = f"{prefix}-{ts}-{rand}"
    st.session_state["request_id"] = rid
    return rid

# =============================================================================
# DB / CSV INIT
# =============================================================================
def _init_csv(path: str, header: List[str]) -> None:
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)

def _db_exec(sql: str, params: Tuple[Any, ...] = ()) -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(sql, params)
    con.commit()
    con.close()

def _init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            event_type TEXT,
            login_id TEXT,
            session_id TEXT,
            request_id TEXT,
            credential_label TEXT,
            success INTEGER,
            hashed_attempt_prefix TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            analysis_id TEXT,
            session_id TEXT,
            login_id TEXT,
            model TEXT,
            elapsed_seconds REAL,
            input_chars INTEGER,
            input_preview TEXT,
            input_sha256 TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            request_id TEXT,
            route TEXT,
            kind TEXT,
            http_status INTEGER,
            detail TEXT,
            session_id TEXT,
            login_id TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS ack_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            ack_key TEXT,
            session_id TEXT,
            login_id TEXT,
            acknowledged INTEGER,
            privacy_url TEXT,
            terms_url TEXT
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS refusal_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_utc TEXT,
            analysis_id TEXT,
            source TEXT,
            category TEXT,
            reason TEXT,
            input_len INTEGER,
            input_sha256 TEXT
        )
    """)

    # NEW: Feedback events (post-analysis)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feedback_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT,
            analysis_id TEXT,
            session_id TEXT,
            login_id TEXT,
            clarity INTEGER,
            objectivity INTEGER,
            usefulness INTEGER,
            appropriateness INTEGER,
            alignment INTEGER,
            comments TEXT
        )
    """)

    con.commit()
    con.close()

_init_db()
init_tenant_tables()

def _prune_table(table: str, ts_col: str, ttl_days: int) -> None:
    try:
        if ttl_days <= 0:
            return
        cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff,))
        con.commit()
        con.close()
    except Exception:
        pass

def _prune_csv(path: str, ttl_days: int) -> None:
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
    except Exception:
        pass

_init_csv(AUTH_CSV, ["timestamp_utc","event_type","login_id","session_id","request_id","credential_label","success","hashed_attempt_prefix"])
_init_csv(ANALYSES_CSV, ["timestamp_utc","analysis_id","session_id","login_id","model","elapsed_seconds","input_chars","input_preview","input_sha256"])
_init_csv(ERRORS_CSV, ["timestamp_utc","request_id","route","kind","http_status","detail","session_id","login_id"])
_init_csv(ACK_CSV, ["timestamp_utc","ack_key","session_id","login_id","acknowledged","privacy_url","terms_url"])
_init_csv(REFUSALS_CSV, ["created_utc","analysis_id","source","category","reason","input_len","input_sha256"])
_init_csv(FEEDBACK_CSV, ["timestamp_utc","analysis_id","session_id","login_id","clarity","objectivity","usefulness","appropriateness","alignment","comments"])

_prune_csv(AUTH_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ANALYSES_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ERRORS_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ACK_CSV, TTL_DAYS_DEFAULT)
_prune_csv(REFUSALS_CSV, TTL_DAYS_DEFAULT)
_prune_csv(FEEDBACK_CSV, TTL_DAYS_DEFAULT)

_prune_table("auth_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("analyses", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("errors", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("ack_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("refusal_events", "created_utc", TTL_DAYS_DEFAULT)
_prune_table("feedback_events", "timestamp_utc", TTL_DAYS_DEFAULT)

# =============================================================================
# LOGGING
# =============================================================================
def log_auth_event(event_type: str, success: bool, login_id: str = "", credential_label: str = "APP_PASSWORD", attempted_secret: str = "") -> None:
    ts = _now_utc_iso()
    sid = ensure_session_id()
    rid = st.session_state.get("request_id") or new_request_id()
    hashed_prefix = ""
    if attempted_secret and not success:
        hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8", errors="ignore")).hexdigest()[:12]

    row = [ts, event_type, (login_id or "")[:120], sid, rid, credential_label, 1 if success else 0, hashed_prefix]
    try:
        with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO auth_events (timestamp_utc,event_type,login_id,session_id,request_id,credential_label,success,hashed_attempt_prefix)
               VALUES (?,?,?,?,?,?,?,?)""",
            (ts, event_type, (login_id or "")[:120], sid, rid, credential_label, 1 if success else 0, hashed_prefix),
        )
    except Exception:
        pass

def save_feedback(
    analysis_id: str,
    clarity: int,
    objectivity: int,
    usefulness: int,
    appropriateness: int,
    alignment: int,
    comments: str = "",
) -> None:
    """Persist post-analysis feedback (CSV + SQLite)."""
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = (st.session_state.get("login_id") or "")[:120]
    aid = (analysis_id or "")[:40]
    cmt = (comments or "").strip()
    if len(cmt) > MAX_FEEDBACK_COMMENT_CHARS:
        cmt = cmt[:MAX_FEEDBACK_COMMENT_CHARS] + "…"

    # CSV
    try:
        with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                [ts, aid, sid, login_id, clarity, objectivity, usefulness, appropriateness, alignment, cmt]
            )
    except Exception:
        pass

    # SQLite
    try:
        _db_exec(
            """INSERT INTO feedback_events
               (timestamp_utc,analysis_id,session_id,login_id,clarity,objectivity,usefulness,appropriateness,alignment,comments)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (ts, aid, sid, login_id, int(clarity), int(objectivity), int(usefulness), int(appropriateness), int(alignment), cmt),
        )
    except Exception:
        pass

def _is_locked() -> bool:
    return time.time() < st.session_state.get("_locked_until", 0.0)

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
        return False
    dq.append(now)
    return True

def _note_failed_login(attempted_secret: str = "") -> None:
    now = time.time()
    dq = st.session_state.setdefault("_fail_times", deque())
    cutoff = now - LOCKOUT_WINDOW_SEC
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now)

    log_auth_event("login_failed", False, login_id=(st.session_state.get("login_id", "") or ""), attempted_secret=attempted_secret)

    if len(dq) >= LOCKOUT_THRESHOLD:
        st.session_state["_locked_until"] = now + LOCKOUT_DURATION_SEC
        log_auth_event("login_lockout", False, login_id=(st.session_state.get("login_id", "") or ""))

# =============================================================================
# ACKNOWLEDGMENT GATE
# =============================================================================
def _get_ack_key() -> str:
    login_id = (st.session_state.get("login_id") or "").strip()
    if login_id:
        return f"login:{login_id.lower()}"
    return f"sid:{ensure_session_id()}"

def _has_ack(ack_key: str) -> bool:
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("""SELECT 1 FROM ack_events WHERE acknowledged=1 AND ack_key=? LIMIT 1""", (ack_key,))
        ok = cur.fetchone() is not None
        con.close()
        return ok
    except Exception:
        return False

def require_acknowledgment() -> None:
    if st.session_state.get("ack_ok"):
        return
    ack_key = _get_ack_key()
    if _has_ack(ack_key):
        st.session_state["ack_ok"] = True
        return

    with st.form("ack_form", clear_on_submit=False):
        st.markdown("### Privacy & Terms Acknowledgment")
        st.write(
            "Before using Veritas, confirm you have read and agree to the "
            f"[Privacy Policy]({PRIVACY_URL or '#'}) and "
            f"[Terms of Use]({TERMS_URL or '#'})."
        )
        c1 = st.checkbox("I have read the Privacy Policy")
        c2 = st.checkbox("I agree to the Terms of Use")
        submit = st.form_submit_button("I acknowledge")

        if submit:
            if not (c1 and c2):
                st.error("Please check both boxes.")
                st.stop()
            ts = _now_utc_iso()
            sid = ensure_session_id()
            login_id = st.session_state.get("login_id", "")
            try:
                with open(ACK_CSV, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([ts, ack_key, sid, login_id, 1, PRIVACY_URL, TERMS_URL])
            except Exception:
                pass
            try:
                _db_exec(
                    """INSERT INTO ack_events (timestamp_utc,ack_key,session_id,login_id,acknowledged,privacy_url,terms_url)
                       VALUES (?,?,?,?,?,?,?)""",
                    (ts, ack_key, sid, login_id, 1, PRIVACY_URL, TERMS_URL),
                )
            except Exception:
                pass
            st.session_state["ack_ok"] = True
            st.success("Acknowledgment recorded.")
            _safe_rerun()

    st.stop()

# =============================================================================
# DOCUMENT EXTRACTION
# =============================================================================
def extract_document_text(uploaded_file) -> str:
    if uploaded_file is None:
        return ""

    filename = (getattr(uploaded_file, "name", "") or "").lower()
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
    if ext and ext not in DOC_ALLOWED_EXTENSIONS:
        return ""

    try:
        file_bytes = uploaded_file.getvalue()
    except Exception:
        try:
            file_bytes = uploaded_file.read()
        except Exception:
            return ""

    if filename.endswith((".txt", ".md", ".csv")):
        try:
            return file_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    if filename.endswith(".docx"):
        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            txt = "\n".join(p.text for p in doc.paragraphs if p.text)
            return txt.strip()
        except Exception:
            return ""

    if filename.endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(file_bytes))
            pages = [(p.extract_text() or "") for p in reader.pages]
            return "\n".join(pages).strip()
        except Exception:
            return ""

    return ""

# =============================================================================
# HARD SAFETY STOP (backup only; refusal_router is primary)
# =============================================================================
def local_safety_stop(user_text: str) -> Optional[str]:
    t = (user_text or "").strip().lower()
    if not t:
        return None
    if re.search(r"\b(i\s*(want|plan|intend|am\s*going)\s*to\s*(kill|harm|hurt)\s*(myself|me))\b", t):
        return (
            "If you are in immediate danger or thinking about harming yourself, call or text 988 in the U.S., "
            "or contact your local emergency number. Analysis has been stopped for safety."
        )
    if re.search(r"\b(i\s*(plan|intend|will|want)\s*to\s*(attack|shoot|bomb|kill|harm))\b", t):
        return "This text indicates potential real-world harm planning. Analysis has been stopped."
    return None

# =============================================================================
# SESSION STATE DEFAULTS
# =============================================================================
ensure_session_id()
st.session_state.setdefault("request_id", new_request_id())
st.session_state.setdefault("authed", False)
st.session_state.setdefault("is_admin", False)
st.session_state.setdefault("login_id", "")
st.session_state.setdefault("ack_ok", False)
st.session_state.setdefault("doc_uploader_key", 0)
st.session_state.setdefault("last_report", "")
st.session_state.setdefault("report_ready", False)
st.session_state.setdefault("veritas_analysis_id", "")
st.session_state.setdefault("feedback_last_submitted_analysis_id", "")

# =============================================================================
# AUTH UI
# =============================================================================
def show_login() -> None:
    st.markdown(
        "<h2 style='color:#FF7A00; font-weight:700;'>Veritas Institutional Trial Portal</h2>",
        unsafe_allow_html=True,
    )

    # ✅ DEFINE mode (this is what you accidentally removed)
    mode = st.radio(
        label="",
        options=["User", "Admin"],
        index=0,
        horizontal=True,
        label_visibility="collapsed",
        key="login_mode",
    )

    if mode == "User":
        with st.form("login_form_user"):
            login_id = st.text_input(
                "Institutional User ID",
                value=st.session_state.get("login_id", "")
            )
            pwd = st.text_input("Password", type="password")
            submit = st.form_submit_button("Enter")

        if submit:
            if not APP_PASSWORD:
                st.error("APP_PASSWORD is not configured on this instance.")
                st.stop()

            if _is_locked():
                remaining = int(st.session_state.get("_locked_until", 0.0) - time.time())
                mins, secs = max(0, remaining // 60), max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()

            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("Too many requests. Please wait and try again.")
                st.stop()

            login_id_clean = (login_id or "").strip()
            if not login_id_clean:
                st.error("User ID is required.")
                st.stop()

            if hmac.compare_digest(_norm(pwd), _norm(APP_PASSWORD)):
                st.session_state["authed"] = True
                st.session_state["is_admin"] = False
                st.session_state["login_id"] = login_id_clean
                st.session_state["_fail_times"] = deque()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=login_id_clean, credential_label="APP_PASSWORD")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=pwd)
                st.error("Incorrect password.")
                st.stop()

    else:
        if not ADMIN_PASSWORD:
            st.error("Admin access is not configured on this instance.")
            st.stop()

        with st.form("login_form_admin"):
            admin_email = st.text_input("Admin Email")
            admin_pwd = st.text_input("Admin Password", type="password")
            submit = st.form_submit_button("Admin Enter")

        if submit:
            if _is_locked():
                remaining = int(st.session_state.get("_locked_until", 0.0) - time.time())
                mins, secs = max(0, remaining // 60), max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()

            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("Too many requests. Please wait and try again.")
                st.stop()

            email = (admin_email or "").strip().lower()
            if ADMIN_EMAILS and email not in ADMIN_EMAILS:
                _note_failed_login(attempted_secret=admin_pwd)
                st.error("Invalid admin credentials.")
                st.stop()

            if hmac.compare_digest(_norm(admin_pwd), _norm(ADMIN_PASSWORD)):
                st.session_state["authed"] = True
                st.session_state["is_admin"] = True
                st.session_state["login_id"] = email
                st.session_state["_fail_times"] = deque()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("admin_login_success", True, login_id=email, credential_label="ADMIN_PASSWORD")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=admin_pwd)
                st.error("Invalid admin credentials.")
                st.stop()

if not st.session_state.get("authed", False):
    show_login()
    st.stop()

# Post-login acknowledgment for non-admins
if not st.session_state.get("is_admin", False):
    require_acknowledgment()

# =============================================================================
# SIDEBAR
# =============================================================================
with st.sidebar:
    st.markdown(f"## {APP_TITLE}")
    st.markdown(
        f"<div class='small-muted'>Signed in as: <b>{st.session_state.get('login_id') or 'User'}</b></div>",
        unsafe_allow_html=True,
    )

    if st.button("Logout"):
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label="APP_PASSWORD")
        sid = st.session_state.get("sid")
        st.session_state.clear()
        st.session_state["sid"] = sid
        _safe_rerun()

# =============================================================================
# MAIN UI (ADMIN-ONLY CONSOLE)
# =============================================================================
if not st.session_state.get("is_admin", False):
    st.error("This console is restricted to administrators.")
    st.stop()

tabs = st.tabs(["Analyze", "Admin"])
tab_analyze, tab_admin = tabs[0], tabs[1]

def reset_canvas() -> None:
    st.session_state["doc_uploader_key"] = st.session_state.get("doc_uploader_key", 0) + 1
    st.session_state["last_report"] = ""
    st.session_state["report_ready"] = False
    st.session_state["user_input_box"] = ""
    st.session_state["veritas_analysis_id"] = ""
    st.session_state["feedback_last_submitted_analysis_id"] = ""

# =============================================================================
# ANALYZE TAB
# =============================================================================
with tab_analyze:
    st.subheader("Veritas — Content Review & Advisory Platform")
    st.caption("Veritas provides structured analysis with objective findings and non-prescriptive advisory guidance.")

    if st.session_state.get("report_ready") and st.session_state.get("veritas_analysis_id"):
        st.markdown(f"**Veritas Analysis ID:** `{st.session_state['veritas_analysis_id']}`")

    submitted = False

    with st.form("analysis_form"):
        user_text = st.text_area(
            "Paste or type text to analyze",
            height=220,
            key="user_input_box",
        )

        doc = st.file_uploader(
            f"Upload document (Max {int(MAX_UPLOAD_MB)}MB) — PDF, DOCX, TXT, MD, CSV",
            type=list(DOC_ALLOWED_EXTENSIONS),
            accept_multiple_files=False,
        )

        c1, c2 = st.columns([2, 1])

        with c1:
            submitted = st.form_submit_button(
                "Engage Veritas",
                use_container_width=True,
            )

        with c2:
            st.form_submit_button(
                "Reset Canvas",
                use_container_width=True,
                on_click=reset_canvas,
            )

    if submitted:
        new_request_id()

        extracted_text = ""
        if doc is not None:
            extracted_text = extract_document_text(doc)[:MAX_EXTRACT_CHARS]

        final_input = (
            user_text + ("\n\n" + extracted_text if extracted_text else "")
        ).strip()

        if not final_input:
            st.warning("Please paste text or upload a document to analyze.")
            st.stop()

        st.session_state["veritas_analysis_id"] = f"VTX-{uuid.uuid4().hex[:12].upper()}"
        analysis_id = st.session_state["veritas_analysis_id"]

        refusal = check_refusal(final_input)
        if refusal.should_refuse:
            output = render_refusal(refusal.category, refusal.reason)
            st.session_state["last_report"] = output
            st.session_state["report_ready"] = True
            st.markdown(output)
            st.stop()

        safety_msg = local_safety_stop(final_input)
        if safety_msg:
            st.session_state["last_report"] = safety_msg
            st.session_state["report_ready"] = True
            st.markdown(safety_msg)
            st.stop()

        client = get_openai_client()
        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                {"role": "user", "content": final_input},
            ],
            temperature=TEMPERATURE,
        )

        report = (resp.choices[0].message.content or "").strip()
        st.session_state["last_report"] = report
        st.session_state["report_ready"] = True

    if st.session_state.get("report_ready") and st.session_state.get("last_report"):
        st.markdown(st.session_state["last_report"])

        # =============================================================================
        # POST-ANALYSIS FEEDBACK (Trial Mode)
        # =============================================================================
        if INSTITUTIONAL_TRIAL_MODE and st.session_state.get("veritas_analysis_id"):
            st.divider()
            st.subheader("Institutional Trial Feedback")

            already_submitted = (
                st.session_state.get("feedback_last_submitted_analysis_id", "") == st.session_state["veritas_analysis_id"]
            )

            if already_submitted:
                st.success("Feedback recorded for this analysis.")
            else:
                with st.form("feedback_form", clear_on_submit=True):
                    st.caption("Quick ratings help validate output quality during the trial period.")
                    clarity = st.slider("Clarity of Analysis", 1, 5, 3)
                    objectivity = st.slider("Perceived Objectivity", 1, 5, 3)
                    usefulness = st.slider("Usefulness of Findings", 1, 5, 3)
                    appropriateness = st.slider("Institutional Appropriateness", 1, 5, 3)
                    alignment = st.slider("Alignment with Your Assessment", 1, 5, 3)
                    comments = st.text_area("Additional Comments (Optional)", height=120)

                    feedback_submit = st.form_submit_button("Submit Feedback")

                if feedback_submit:
                    save_feedback(
                        analysis_id=st.session_state["veritas_analysis_id"],
                        clarity=clarity,
                        objectivity=objectivity,
                        usefulness=usefulness,
                        appropriateness=appropriateness,
                        alignment=alignment,
                        comments=comments,
                    )
                    st.session_state["feedback_last_submitted_analysis_id"] = st.session_state["veritas_analysis_id"]
                    st.success("Thank you. Your feedback has been recorded.")
                    _safe_rerun()

# =============================================================================
# ADMIN TAB
# =============================================================================
with tab_admin:
    st.header("Admin Dashboard")

    st.subheader("Diagnostics")
    st.write(f"APP_MODE: `{APP_MODE or '(unset)'}`")
    st.write(f"Model: `{MODEL_NAME}`")
    st.write(f"Temperature: `{TEMPERATURE}`")
    st.write(f"DB Path: `{DB_PATH}`")
    st.write(f"Trial Feedback Mode: `{'ON' if INSTITUTIONAL_TRIAL_MODE else 'OFF'}`")

    st.subheader("Refusal Telemetry")
    def fetch_recent_refusals(limit: int = 500) -> List[Tuple[Any, ...]]:
        try:
            con = sqlite3.connect(DB_PATH, timeout=30)
            cur = con.cursor()
            cur.execute(
                """SELECT created_utc, analysis_id, source, category, reason, input_len
                   FROM refusal_events
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
            con.close()
            return rows
        except Exception:
            try:
                con.close()
            except Exception:
                pass
            return []

    rows = fetch_recent_refusals(limit=500)
    if not rows:
        st.info("No refusal events logged yet.")
    else:
        df = pd.DataFrame(rows, columns=["created_utc", "analysis_id", "source", "category", "reason", "input_len"])
        st.dataframe(df, use_container_width=True)
        st.download_button(
            "Download Refusal Log (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="veritas_refusal_log.csv",
            mime="text/csv",
        )

    st.subheader("Tenant Management")

    with st.form("create_tenant_form"):
        tenant_id = st.text_input("Tenant ID")
        tier = st.selectbox("Tier", ["Starter", "Professional", "Enterprise"])
        annual_limit = st.number_input("Annual Analysis Limit", min_value=1, value=100)
        create = st.form_submit_button("Create Tenant & Issue Key")

        if create:
            if not tenant_id:
                st.error("Tenant ID is required.")
                st.stop()

            raw_key = admin_create_tenant(
                tenant_id=tenant_id.strip(),
                tier=tier,
                monthly_limit=int(annual_limit),  # underlying function may still use this param name
            )

            st.success("Tenant created. Copy the key now — it will not be shown again.")
            st.code(raw_key)

    st.divider()

    with st.form("suspend_tenant_form"):
        suspend_id = st.text_input("Tenant ID to Suspend")
        suspend = st.form_submit_button("Suspend Tenant")

        if suspend:
            if not suspend_id:
                st.error("Tenant ID is required.")
                st.stop()
            suspend_tenant(suspend_id.strip())
            st.success(f"Tenant '{suspend_id.strip()}' has been suspended.")

    st.divider()

    with st.form("rotate_key_form"):
        rotate_tenant_id = st.text_input("Tenant ID")
        old_key_id = st.text_input("Current Key ID")
        rotate = st.form_submit_button("Rotate Tenant Key")

        if rotate:
            if not rotate_tenant_id or not old_key_id:
                st.error("Tenant ID and Key ID are required.")
                st.stop()
            new_key = rotate_key(rotate_tenant_id.strip(), old_key_id.strip())
            st.success("Key rotated. Copy the new key now — it will not be shown again.")
            st.code(new_key)

    st.divider()
    st.subheader("Tenant Reporting")

    period = current_period_yyyy()
    st.caption(f"Usage period (UTC): {period}")

    rows = admin_usage_snapshot(period_yyyy=period, limit=500)
    if rows:
        df = pd.DataFrame(rows, columns=["tenant_id", "tier", "annual_limit", "status", "analysis_count"])
        st.dataframe(df, use_container_width=True)
        st.download_button(
            "Download Tenant Usage Snapshot (CSV)",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"tenant_usage_snapshot_{period}.csv",
            mime="text/csv",
        )
    else:
        st.info("No tenants found.")

    st.divider()

    st.markdown("### Tenant Lookup")
    lookup_id = st.text_input("Lookup Tenant ID", key="tenant_lookup_id")

    if st.button("Lookup Tenant", key="tenant_lookup_btn"):
        t = admin_get_tenant((lookup_id or "").strip())
        if not t:
            st.error("No tenant found with that Tenant ID.")
            st.stop()

        tenant_id_val = t.get("tenant_id")
        used = admin_get_usage(tenant_id_val, period)
        limit_val = int(t.get("annual_analysis_limit") or 0)

        st.success("Tenant found.")
        st.write({
            "tenant_id": tenant_id_val,
            "tier": t.get("tier"),
            "annual_limit": limit_val,
            "status": t.get("status"),
            "usage_this_year": used,
            "created_utc": t.get("created_utc"),
            "updated_utc": t.get("updated_utc"),
        })

        keys = admin_list_tenant_keys(tenant_id_val, limit=50)
        if keys:
            kdf = pd.DataFrame(keys, columns=["key_id", "status", "created_utc", "revoked_utc", "rotated_from_key_id"])
            st.markdown("#### Tenant Keys")
            st.dataframe(kdf, use_container_width=True)
            st.download_button(
                "Download Tenant Keys (CSV)",
                data=kdf.to_csv(index=False).encode("utf-8"),
                file_name=f"tenant_keys_{tenant_id_val}.csv",
                mime="text/csv",
            )
        else:
            st.info("No keys found for this tenant.")

    # OPTIONAL: Feedback export (quick access for trial reporting)
    st.divider()
    st.subheader("Trial Feedback (Export)")

    def fetch_recent_feedback(limit: int = 1000) -> List[Tuple[Any, ...]]:
        try:
            con = sqlite3.connect(DB_PATH, timeout=30)
            cur = con.cursor()
            cur.execute(
                """SELECT timestamp_utc, analysis_id, login_id, clarity, objectivity, usefulness, appropriateness, alignment, comments
                   FROM feedback_events
                   ORDER BY id DESC
                   LIMIT ?""",
                (limit,),
            )
            rows = cur.fetchall()
            con.close()
            return rows
        except Exception:
            try:
                con.close()
            except Exception:
                pass
            return []

    frows = fetch_recent_feedback(limit=1000)
    if not frows:
        st.info("No feedback submitted yet.")
    else:
        fdf = pd.DataFrame(
            frows,
            columns=["timestamp_utc","analysis_id","login_id","clarity","objectivity","usefulness","appropriateness","alignment","comments"]
        )
        st.dataframe(fdf, use_container_width=True)
        st.download_button(
            "Download Feedback Log (CSV)",
            data=fdf.to_csv(index=False).encode("utf-8"),
            file_name="veritas_feedback_log.csv",
            mime="text/csv",
        )

# =============================================================================
# FOOTER
# =============================================================================
st.markdown(
    "<div style='margin-top:1.25rem;opacity:.75;font-size:.9rem;'>Copyright 2026 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True,
)

















