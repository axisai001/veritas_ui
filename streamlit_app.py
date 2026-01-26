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
from zoneinfo import ZoneInfo
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
from openai import OpenAI

from tenant_store import current_period_yyyymm, get_usage, increment_usage

# Refusal Router (required companion file)
from refusal_router import check_refusal, render_refusal, RefusalResult

import refusal_router as rr
st.sidebar.write("refusal_router loaded from:", rr.__file__)

# =============================================================================
# CONFIG
# =============================================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
UPLOAD_DIR = STATIC_DIR / "uploads"

for p in (DATA_DIR, STATIC_DIR, UPLOAD_DIR):
    p.mkdir(parents=True, exist_ok=True)

APP_TITLE = (os.environ.get("APP_TITLE") or "Veritas").strip()

# OpenAI
MODEL_NAME = (os.getenv("OPENAI_MODEL", "").strip() or "gpt-4.1-mini")
TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.2"))

# Auth (set via Streamlit secrets or environment variables)
APP_PASSWORD = (os.environ.get("APP_PASSWORD") or "").strip()
ADMIN_PASSWORD = (os.environ.get("ADMIN_PASSWORD") or "").strip()

# Optional admin email allowlist (recommended for B2B admin access)
ADMIN_EMAILS = set()
_raw_admin_emails = (os.environ.get("ADMIN_EMAILS") or "").strip()
if _raw_admin_emails:
    ADMIN_EMAILS = {e.strip().lower() for e in _raw_admin_emails.split(",") if e.strip()}

# Privacy / Terms (optional but used for acknowledgment gate)
PRIVACY_URL = (os.environ.get("PRIVACY_URL") or "").strip()
TERMS_URL = (os.environ.get("TERMS_URL") or "").strip()

# Upload limits
MAX_UPLOAD_MB = float(os.environ.get("MAX_UPLOAD_MB", "10"))
MAX_EXTRACT_CHARS = int(os.environ.get("MAX_EXTRACT_CHARS", "50000"))
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}

# Logging (CSV + SQLite)
DB_PATH = str(DATA_DIR / "veritas.db")

# Ensure ALL modules (tenant_store, admin tools, etc.) use the SAME DB
os.environ.setdefault("DB_PATH", DB_PATH)

ANALYSES_CSV = str(DATA_DIR / "analyses.csv")
ERRORS_CSV = str(DATA_DIR / "errors.csv")
AUTH_CSV = str(DATA_DIR / "auth_events.csv")
ACK_CSV = str(DATA_DIR / "ack_events.csv")
REFUSALS_CSV = str(DATA_DIR / "refusal_telemetry.csv")

# Rate limiting + lockout
RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT = int(os.environ.get("RATE_LIMIT_CHAT", "6"))
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RATE_LIMIT_WINDOW_SEC", "60"))

LOCKOUT_THRESHOLD = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800"))

# TTL pruning
TTL_DAYS_DEFAULT = int(os.environ.get("LOG_TTL_DAYS", "365"))

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
      .veritas-id { font-size: 1.15rem; font-weight: 700; margin: .25rem 0 .5rem 0; }
      .small-muted { opacity: .78; font-size: .92rem; }
      [data-testid="stToolbar"] { visibility: hidden !important; height: 0 !important; }
      #MainMenu { visibility: hidden !important; }
      footer { visibility: hidden !important; }
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

def ensure_analysis_id() -> str:
    if not st.session_state.get("veritas_analysis_id"):
        st.session_state["veritas_analysis_id"] = f"VTX-{uuid.uuid4().hex[:12].upper()}"
    return st.session_state["veritas_analysis_id"]

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

        con.commit()
        con.close()

# Initialize core application tables
_init_db()

# Initialize B2B tenant tables (VER-B2B-001)
from tenant_store import init_tenant_tables
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

_init_db()

_init_csv(AUTH_CSV, ["timestamp_utc","event_type","login_id","session_id","request_id","credential_label","success","hashed_attempt_prefix"])
_init_csv(ANALYSES_CSV, ["timestamp_utc","analysis_id","session_id","login_id","model","elapsed_seconds","input_chars","input_preview","input_sha256"])
_init_csv(ERRORS_CSV, ["timestamp_utc","request_id","route","kind","http_status","detail","session_id","login_id"])
_init_csv(ACK_CSV, ["timestamp_utc","ack_key","session_id","login_id","acknowledged","privacy_url","terms_url"])
_init_csv(REFUSALS_CSV, ["created_utc","analysis_id","source","category","reason","input_len","input_sha256"])

_prune_csv(AUTH_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ANALYSES_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ERRORS_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ACK_CSV, TTL_DAYS_DEFAULT)
_prune_csv(REFUSALS_CSV, TTL_DAYS_DEFAULT)

_prune_table("auth_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("analyses", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("errors", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("ack_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("refusal_events", "created_utc", TTL_DAYS_DEFAULT)

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

def log_error_event(kind: str, route: str, http_status: int, detail: str) -> None:
    ts = _now_utc_iso()
    rid = st.session_state.get("request_id") or new_request_id()
    sid = ensure_session_id()
    login_id = st.session_state.get("login_id", "")
    safe_detail = (detail or "")[:500]

    try:
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, rid, route, kind, http_status, safe_detail, sid, login_id])
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO errors (timestamp_utc,request_id,route,kind,http_status,detail,session_id,login_id)
               VALUES (?,?,?,?,?,?,?,?)""",
            (ts, rid, route, kind, http_status, safe_detail, sid, login_id),
        )
    except Exception:
        pass

def log_analysis_run(analysis_id: str, input_text: str, elapsed_seconds: float, model_name: str) -> None:
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = st.session_state.get("login_id", "")

    row = [
        ts,
        analysis_id,
        sid,
        login_id,
        model_name,
        round(float(elapsed_seconds or 0.0), 3),
        len(input_text or ""),
        _safe_preview(input_text),
        _sha256(input_text),
    ]
    try:
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO analyses (timestamp_utc,analysis_id,session_id,login_id,model,elapsed_seconds,input_chars,input_preview,input_sha256)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (ts, analysis_id, sid, login_id, model_name, float(elapsed_seconds or 0.0), len(input_text or ""), _safe_preview(input_text), _sha256(input_text)),
        )
    except Exception:
        pass

def log_ack_event(ack_key: str, acknowledged: bool) -> None:
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = st.session_state.get("login_id", "")

    try:
        with open(ACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, ack_key, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL])
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO ack_events (timestamp_utc,ack_key,session_id,login_id,acknowledged,privacy_url,terms_url)
               VALUES (?,?,?,?,?,?,?)""",
            (ts, ack_key, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL),
        )
    except Exception:
        pass

def log_refusal_event(analysis_id: str, category: str, reason: str, source: str, input_text: str) -> None:
    created = _now_utc_iso()
    in_len = len((input_text or "").strip())
    in_hash = _sha256((input_text or "").strip())

    try:
        with open(REFUSALS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([created, analysis_id, source, category, (reason or "")[:240], in_len, in_hash])
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO refusal_events (created_utc,analysis_id,source,category,reason,input_len,input_sha256)
               VALUES (?,?,?,?,?,?,?)""",
            (created, analysis_id, source, category, (reason or "")[:240], in_len, in_hash),
        )
    except Exception:
        pass

def fetch_recent_refusals(limit: int = 500) -> List[Tuple[Any, ...]]:
    try:
        con = sqlite3.connect(DB_PATH, timeout=30)
        cur = con.cursor()

        # Ensure the table exists (prevents OperationalError on fresh/mismatched DB)
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

    except sqlite3.OperationalError:
        # Fail-safe: don't crash the whole app if DB is locked/unavailable
        try:
            con.close()
        except Exception:
            pass
        return []

# =============================================================================
# RATE LIMIT + LOCKOUT
# =============================================================================
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

def _is_locked() -> bool:
    return time.time() < st.session_state.get("_locked_until", 0.0)

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
        cur.execute(
            """SELECT 1 FROM ack_events WHERE acknowledged=1 AND ack_key=? LIMIT 1""",
            (ack_key,),
        )
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
            log_ack_event(ack_key, True)
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

    # TXT / MD / CSV
    if filename.endswith((".txt", ".md", ".csv")):
        try:
            return file_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            return ""

    # DOCX
    if filename.endswith(".docx"):
        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            txt = "\n".join(p.text for p in doc.paragraphs if p.text)
            return txt.strip()
        except Exception:
            return ""

    # PDF
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
    # explicit self-harm intent
    if re.search(r"\b(i\s*(want|plan|intend|am\s*going)\s*to\s*(kill|harm|hurt)\s*(myself|me))\b", t):
        return (
            "If you are in immediate danger or thinking about harming yourself, call or text 988 in the U.S., "
            "or contact your local emergency number. Analysis has been stopped for safety."
        )
    # credible violence planning
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
st.session_state.setdefault("last_report_id", "")
st.session_state.setdefault("report_ready", False)

# =============================================================================
# AUTH UI
# =============================================================================
def show_login() -> None:
    st.subheader("Launch Veritas")

    mode = st.radio(
        label="",
        options=["User", "Admin"],
        index=0,
        horizontal=True,
        label_visibility="collapsed",
    )

    if mode == "User":
        with st.form("login_form_user"):
            login_id = st.text_input("Tester ID or Business User ID", value=st.session_state.get("login_id", ""))
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
        # preserve session id for continuity, clear the rest
        sid = st.session_state.get("sid")
        st.session_state.clear()
        st.session_state["sid"] = sid
        _safe_rerun()

# =============================================================================
# MAIN UI
# =============================================================================
tabs = ["Analyze"]
if st.session_state.get("is_admin", False):
    tabs.append("Admin")

tab_objs = st.tabs(tabs)
tab_map = {name: tab_objs[i] for i, name in enumerate(tabs)}
tab_analyze = tab_map["Analyze"]
tab_admin = tab_map.get("Admin")

def reset_canvas() -> None:
    st.session_state["doc_uploader_key"] = st.session_state.get("doc_uploader_key", 0) + 1
    st.session_state["last_report"] = ""
    st.session_state["last_report_id"] = ""
    st.session_state["report_ready"] = False

    # IMPORTANT:
    # Do NOT generate a new analysis ID on reset.
    # Generate it ONLY when "Engage Veritas" is clicked and a real analysis is performed.
    st.session_state["veritas_analysis_id"] = ""

    st.session_state["user_input_box"] = ""

# =============================================================================
# ANALYZE TAB
# =============================================================================
with tab_analyze:
    st.subheader("Veritas — Content Analysis and Advisory System")
    st.caption("Veritas returns objective findings with non-prescriptive advisory guidance.")

    # Show the Analysis ID only AFTER a report exists
    if st.session_state.get("report_ready") and st.session_state.get("veritas_analysis_id"):
        st.markdown(f"**Veritas Analysis ID:** `{st.session_state['veritas_analysis_id']}`")

    # Ensure submitted is always defined (prevents NameError)
    submitted = False

    # -----------------------------
    # FORM (collect inputs only)
    # -----------------------------
    with st.form("analysis_form", clear_on_submit=False):
        user_text = st.text_area(
            "Paste or type text to analyze",
            height=220,
            key="user_input_box",
        )

        doc = st.file_uploader(
            f"Upload document (Max {int(MAX_UPLOAD_MB)}MB) — PDF, DOCX, TXT, MD, CSV",
            type=list(DOC_ALLOWED_EXTENSIONS),
            accept_multiple_files=False,
            key=f"doc_uploader_{st.session_state['doc_uploader_key']}",
        )

        c1, c2 = st.columns([1, 1], gap="small")
        submitted = c1.form_submit_button("Engage Veritas")
        c2.form_submit_button("Reset Canvas", on_click=reset_canvas)

    # -----------------------------
    # SUBMIT HANDLER (outside form)
    # -----------------------------
    if submitted:
        new_request_id()

        # -----------------------------
        # TENANT USAGE ENFORCEMENT (B2B)
        # -----------------------------
        tenant_id = st.session_state.get("tenant_id")
        monthly_limit = int(st.session_state.get("tenant_limit") or 0)

        if not tenant_id or monthly_limit <= 0:
            st.error("Tenant context missing. Please re-verify your tenant key.")
            st.session_state["tenant_verified"] = False
            st.stop()

        period = current_period_yyyymm()
        used = get_usage(tenant_id, period)

        if used >= monthly_limit:
            st.error(f"Monthly analysis limit reached ({used}/{monthly_limit}).")
            st.stop()


        if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
            st.error("Too many requests. Please wait and try again.")
            st.stop()

        extracted_text = ""
        source = "typed"

        if doc is not None:
            extracted_text = extract_document_text(doc)[:MAX_EXTRACT_CHARS]
            if extracted_text:
                source = "document"

        final_input = (user_text + ("\n\n" + extracted_text if extracted_text else "")).strip()

        if not final_input:
            st.warning("Please paste text or upload a document to analyze.")
            st.stop()

        # Generate Analysis ID ONLY now that analysis will proceed
        st.session_state["veritas_analysis_id"] = f"VTX-{uuid.uuid4().hex[:12].upper()}"
        analysis_id = st.session_state["veritas_analysis_id"]

        # Refusal pre-check (single source of truth)
        try:
            refusal: RefusalResult = check_refusal(final_input)
        except Exception as e:
            log_error_event("REFUSAL_ROUTER_ERROR", "/analyze", 500, repr(e))
            st.error("Refusal router error. See logs.")
            st.stop()

        if refusal.should_refuse:
            output = render_refusal(refusal.category, refusal.reason)

            log_refusal_event(
                analysis_id=analysis_id,
                category=str(getattr(refusal.category, "value", refusal.category)),
                reason=refusal.reason,
                source=source,
                input_text=final_input,
            )

            st.session_state["last_report"] = output
            st.session_state["last_report_id"] = analysis_id
            st.session_state["report_ready"] = True

            st.markdown(output)
            st.stop()  # HARD STOP — model never runs


        # Backup hard stop for explicit safety-critical patterns
        msg = local_safety_stop(final_input)
        if msg:
            st.error(msg)
            st.stop()

        client = OpenAI()
        prog = st.progress(0, text="Starting analysis...")
        t0 = time.time()

        try:
            prog.progress(35, text="Submitting to Veritas...")
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                    {"role": "user", "content": final_input},
                ],
                temperature=TEMPERATURE,
            )

            report = (resp.choices[0].message.content or "").strip() if resp and resp.choices else ""
            if not report:
                raise RuntimeError("Empty response from model.")

            # Enforce two-section format; re-ask once if needed.
            if ("Objective Findings" not in report) or ("Advisory Guidance" not in report):
                resp2 = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                        {"role": "user", "content": final_input},
                        {"role": "user", "content": "Reformat to the required two-section output exactly."},
                    ],
                    temperature=TEMPERATURE,
                )
                report2 = (resp2.choices[0].message.content or "").strip() if resp2 and resp2.choices else ""
                report = report2 or report

            st.session_state["last_report"] = report
            st.session_state["last_report_id"] = analysis_id
            st.session_state["report_ready"] = True

            log_analysis_run(
                analysis_id=analysis_id,
                input_text=final_input,
                elapsed_seconds=(time.time() - t0),
                model_name=MODEL_NAME,
            )
            
            # Step 5 — bill usage ONLY after successful analysis
            increment_usage(tenant_id, period)
            
            prog.progress(100, text="Analysis complete")

        except Exception as e:
            log_error_event("ANALYZE_ERROR", "/analyze", 500, repr(e))
            st.error("The analysis did not complete. Please try again.")
            st.exception(e)
        finally:
            prog.empty()

    # -----------------------------
    # DISPLAY LAST REPORT (always)
    # -----------------------------
    if st.session_state.get("report_ready") and st.session_state.get("last_report"):
        st.markdown(st.session_state["last_report"])

# =============================================================================
# ADMIN TAB
# =============================================================================
if tab_admin is not None:
    with tab_admin:
        st.header("Admin Dashboard")

        st.info("Admin tab loaded.")

        try:
            # B2B tenant store import (VER-B2B-001)
            from tenant_store import admin_create_tenant, suspend_tenant, rotate_key
        except Exception as e:
            st.error("Tenant management module failed to load.")
            st.code(repr(e))
            st.stop()

        st.subheader("Refusal Telemetry")
        rows = fetch_recent_refusals(limit=500)
        if not rows:
            st.info("No refusal events logged yet.")
        else:
            df = pd.DataFrame(
                rows,
                columns=["created_utc", "analysis_id", "source", "category", "reason", "input_len"]
            )
            st.dataframe(df, use_container_width=True)
            st.download_button(
                "Download Refusal Log (CSV)",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="veritas_refusal_log.csv",
                mime="text/csv",
            )

        st.subheader("Diagnostics")
        st.write(f"Model: `{MODEL_NAME}`")
        st.write(f"Temperature: `{TEMPERATURE}`")
        st.write(f"DB Path: `{DB_PATH}`")

                # ---------------------------------
        # B2B TENANT MANAGEMENT (VER-B2B-001)
        # ---------------------------------
        from tenant_store import admin_create_tenant, suspend_tenant, rotate_key

        st.subheader("Tenant Management")

        # --- Create Tenant ---
        with st.form("create_tenant_form"):
            tenant_id = st.text_input("Tenant ID")
            tier = st.selectbox("Tier", ["Starter", "Professional", "Enterprise"])
            monthly_limit = st.number_input(
                "Monthly Analysis Limit",
                min_value=1,
                value=100
            )
            create = st.form_submit_button("Create Tenant & Issue Key")

            if create:
                if not tenant_id:
                    st.error("Tenant ID is required.")
                    st.stop()

                raw_key = admin_create_tenant(
                    tenant_id=tenant_id.strip(),
                    tier=tier,
                    monthly_limit=int(monthly_limit),
                )

                st.success("Tenant created. Copy the key now — it will not be shown again.")
                st.code(raw_key)

        st.divider()

        # --- Suspend Tenant ---
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

        # --- Rotate Tenant Key ---
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

        # ---------------------------------
        # VERIFY TENANT (INTERNAL)
        # ---------------------------------
        st.subheader("Verify Tenant (Internal)")

        lookup_tenant_id = st.text_input("Enter Tenant ID to verify", key="verify_tenant_id")

        if st.button("Verify Tenant"):
            try:
                tid = (lookup_tenant_id or "").strip()
                if not tid:
                    st.error("Tenant ID is required.")
                    st.stop()

                con = sqlite3.connect(DB_PATH, timeout=30)
                cur = con.cursor()

                cur.execute(
                    """
                    SELECT tenant_id, tier, monthly_analysis_limit, status, created_utc
                    FROM tenants
                    WHERE tenant_id = ?
                    """,
                    (tid,),
                )
                tenant = cur.fetchone()

                cur.execute(
                    """
                    SELECT key_id, status, created_utc
                    FROM tenant_keys
                    WHERE tenant_id = ?
                    ORDER BY created_utc DESC
                    LIMIT 20
                    """,
                    (tid,),
                )
                keys = cur.fetchall()

                con.close()

                if not tenant:
                    st.error("No tenant found with that Tenant ID.")
                else:
                    st.success("Tenant exists.")
                    st.write({
                        "tenant_id": tenant[0],
                        "tier": tenant[1],
                        "monthly_analysis_limit": tenant[2],
                        "status": tenant[3],
                        "created_utc": tenant[4],
                    })

                    if not keys:
                        st.info("No keys found for this tenant yet.")
                    else:
                        st.write("Associated keys (key_id, status, created_utc):")
                        df_keys = pd.DataFrame(keys, columns=["key_id", "status", "created_utc"])
                        st.dataframe(df_keys, use_container_width=True)

            except Exception as e:
                st.error("Verification failed.")
                st.code(repr(e))

# =============================================================================
# FOOTER
# =============================================================================
st.markdown(
    "<div style='margin-top:1.25rem;opacity:.75;font-size:.9rem;'>Copyright 2026 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True,
)






























