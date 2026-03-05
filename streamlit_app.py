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
# - Analysis logging (CSV + SQLite) INCLUDING full input text + output text
# - PDF/DOCX/TXT/MD/CSV text extraction
# - Post-analysis feedback form (CSV + SQLite) tied to Analysis ID (stores full input text too)
# - Bug reporting tab (CSV + SQLite) with optional screenshot upload
# - ✅ Institutional accounts (DB-backed): per-institution ID + password (hashed), created/reset/disabled via Admin UI
#
# Dependencies:
#   streamlit, openai, pandas, python-docx, pypdf
# Optional (recommended for encryption at rest of feedback input copy):
#   cryptography

import os
import io
import re
import csv
import time
import hmac
import uuid
import hashlib
import secrets
import sqlite3
import unicodedata
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import deque
from typing import Any, List, Optional, Tuple

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
    st.caption("Set APP_MODE=internal_console (env or Streamlit Secrets) to enable this Streamlit UI.")
    st.stop()

# Refusal Router (required companion file)
from refusal_router import check_refusal, render_refusal  # noqa: E402

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

# --- Optional encrypted copy for feedback input (in addition to plaintext storage) ---
STORE_ENCRYPTED_INPUT_FOR_FEEDBACK = (_get_setting("STORE_ENCRYPTED_INPUT_FOR_FEEDBACK", "0")).strip() == "1"
INPUT_ENCRYPTION_KEY = (_get_setting("INPUT_ENCRYPTION_KEY", "")).strip()  # Fernet key recommended

# --- ENFORCED OpenAI key wiring (Env-first fallback + secrets) ---
def _get_openai_api_key() -> str:
    return (_get_setting("OPENAI_API_KEY", "") or "").strip()


def get_openai_client() -> OpenAI:
    api_key = _get_openai_api_key()
    if not api_key:
        st.error("OPENAI_API_KEY is not configured for this instance.")
        st.caption("Set OPENAI_API_KEY in Streamlit Secrets or environment variables.")
        st.stop()
    return OpenAI(api_key=api_key)


# Auth (set via Streamlit secrets or environment variables)
# NOTE: APP_PASSWORD is retained for backward compatibility, but institutional login is now DB-backed.
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
os.environ["DB_PATH"] = DB_PATH  # force single source of truth for other modules

ANALYSES_CSV = str(DATA_DIR / "analyses.csv")
ERRORS_CSV = str(DATA_DIR / "errors.csv")
AUTH_CSV = str(DATA_DIR / "auth_events.csv")
ACK_CSV = str(DATA_DIR / "ack_events.csv")
REFUSALS_CSV = str(DATA_DIR / "refusal_telemetry.csv")
FEEDBACK_CSV = str(DATA_DIR / "feedback_events.csv")

# --- Bug reporting (CSV + SQLite) ---
BUGS_CSV = str(DATA_DIR / "bug_reports.csv")
BUGS_UPLOAD_DIR = UPLOAD_DIR / "bugs"
BUGS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_BUG_TITLE_CHARS = int(_get_setting("MAX_BUG_TITLE_CHARS", "140"))
MAX_BUG_TEXT_CHARS = int(_get_setting("MAX_BUG_TEXT_CHARS", "4000"))
MAX_BUG_ATTACHMENT_MB = float(_get_setting("MAX_BUG_ATTACHMENT_MB", "5"))

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
from tenant_store import (  # noqa: E402
    init_tenant_tables,
    current_period_yyyy,
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
# STREAMLIT PAGE + THEME
# =============================================================================
st.set_page_config(page_title=APP_TITLE, layout="centered")

st.markdown(
    """
    <style>
    html, body, [data-testid="stAppViewContainer"] { background-color:#0B1F3B !important; color:#FFFFFF !important; }
    .stApp { background-color:#0B1F3B !important; color:#FFFFFF !important; }
    header[data-testid="stHeader"] { background-color:#0B1F3B !important; height:0px !important; }
    header[data-testid="stHeader"] > div { background-color:#0B1F3B !important; }
    [data-testid="stToolbar"] { visibility:hidden !important; height:0 !important; }
    #MainMenu { visibility:hidden !important; }
    footer { visibility:hidden !important; }

    section[data-testid="stSidebar"] { background-color:#08172B !important; }

    div.stButton > button,
    div[data-testid="stFormSubmitButton"] > button {
        background-color:#FF7A00 !important;
        color:#FFFFFF !important;
        font-weight:700 !important;
        border-radius:6px !important;
        border:none !important;
    }
    div.stButton > button:hover,
    div[data-testid="stFormSubmitButton"] > button:hover { background-color:#E06600 !important; }

    input, textarea {
        background-color:#132B4F !important;
        color:#FFFFFF !important;
        border-radius:6px !important;
        border:1px solid #1E3A66 !important;
    }

    button[kind="secondary"] { background-color:#132B4F !important; }

    button[role="tab"] { background-color:#132B4F !important; color:#FFFFFF !important; }

    .stDataFrame { background-color:#132B4F !important; }

    .login-title { color:#FF7A00 !important; font-weight:800 !important; margin-bottom:0.5rem !important; }
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


# --- Institutional password hashing (one-way) ---
def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """
    Returns 'salt$sha256' (one-way). Do not store plaintext passwords.
    """
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256((password + salt).encode("utf-8", errors="ignore")).hexdigest()
    return f"{salt}${digest}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = (stored_hash or "").split("$", 1)
    except Exception:
        return False
    check = hashlib.sha256((password + salt).encode("utf-8", errors="ignore")).hexdigest()
    return secrets.compare_digest(check, digest)


# =============================================================================
# OPTIONAL ENCRYPTION HELPERS (for feedback encrypted copy)
# =============================================================================
def _xor_crypt(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


def _encrypt_text(plain: str) -> str:
    """
    Encrypt plaintext for SQLite storage.
    Prefers cryptography.Fernet if installed.
    Falls back to XOR+base64 (weak). Still avoids plaintext at rest for encrypted copy.
    """
    plain_b = (plain or "").encode("utf-8", errors="ignore")
    if not plain_b:
        return ""

    if not INPUT_ENCRYPTION_KEY:
        raise RuntimeError("Missing INPUT_ENCRYPTION_KEY")

    # Prefer Fernet if available
    try:
        from cryptography.fernet import Fernet  # type: ignore

        f = Fernet(INPUT_ENCRYPTION_KEY.encode("utf-8"))
        return f.encrypt(plain_b).decode("utf-8")
    except Exception:
        import base64

        key_b = hashlib.sha256(INPUT_ENCRYPTION_KEY.encode("utf-8")).digest()
        return base64.b64encode(_xor_crypt(plain_b, key_b)).decode("utf-8")


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


def _db_fetchone(sql: str, params: Tuple[Any, ...] = ()) -> Optional[Tuple[Any, ...]]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    con.close()
    return row


def _db_fetchall(sql: str, params: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    con.close()
    return rows


def _db_add_column_if_missing(table: str, col: str, coltype: str) -> None:
    try:
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute(f"PRAGMA table_info({table})")
        cols = {r[1] for r in cur.fetchall()}
        if col not in cols:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")
            con.commit()
        con.close()
    except Exception:
        try:
            con.close()
        except Exception:
            pass


def _init_db() -> None:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        """
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
        """
    )

    # ✅ analyses now stores full input_text + output_text
    cur.execute(
        """
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
            input_sha256 TEXT,
            input_text TEXT,
            output_text TEXT
        )
        """
    )

    cur.execute(
        """
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
        """
    )

    cur.execute(
        """
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
        """
    )

    cur.execute(
        """
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
        """
    )

    # ✅ feedback now stores plaintext input_text (plus optional encrypted copy)
    cur.execute(
        """
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
            comments TEXT,
            input_sha256 TEXT,
            input_text TEXT,
            input_encrypted TEXT
        )
        """
    )

    # ✅ bug reports (CSV + SQLite)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS bug_reports (
            id TEXT PRIMARY KEY,
            timestamp_utc TEXT,
            analysis_id TEXT,
            session_id TEXT,
            login_id TEXT,
            is_admin INTEGER,
            title TEXT,
            category TEXT,
            severity TEXT,
            steps_to_reproduce TEXT,
            expected_behavior TEXT,
            actual_behavior TEXT,
            page_context TEXT,
            user_agent TEXT,
            attachment_path TEXT,
            status TEXT,
            internal_notes TEXT
        )
        """
    )

    # ✅ institutional accounts (DB-backed)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS institution_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            institution_name TEXT NOT NULL,
            institution_id TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_utc TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            trial_start TEXT,
            trial_end TEXT,
            notes TEXT
        )
        """
    )

    con.commit()
    con.close()


_init_db()

# Backward-compatible DB migrations (safe no-ops if columns already exist)
_db_add_column_if_missing("analyses", "input_text", "TEXT")
_db_add_column_if_missing("analyses", "output_text", "TEXT")

_db_add_column_if_missing("feedback_events", "input_sha256", "TEXT")
_db_add_column_if_missing("feedback_events", "input_text", "TEXT")
_db_add_column_if_missing("feedback_events", "input_encrypted", "TEXT")

_db_add_column_if_missing("bug_reports", "status", "TEXT")
_db_add_column_if_missing("bug_reports", "internal_notes", "TEXT")
_db_add_column_if_missing("bug_reports", "attachment_path", "TEXT")

# Institutional table migrations (in case you later expand schema)
_db_add_column_if_missing("institution_users", "trial_start", "TEXT")
_db_add_column_if_missing("institution_users", "trial_end", "TEXT")
_db_add_column_if_missing("institution_users", "notes", "TEXT")

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


_init_csv(
    AUTH_CSV,
    ["timestamp_utc", "event_type", "login_id", "session_id", "request_id", "credential_label", "success", "hashed_attempt_prefix"],
)
_init_csv(
    ANALYSES_CSV,
    [
        "timestamp_utc",
        "analysis_id",
        "session_id",
        "login_id",
        "model",
        "elapsed_seconds",
        "input_chars",
        "input_preview",
        "input_sha256",
        "input_text",
        "output_text",
    ],
)
_init_csv(ERRORS_CSV, ["timestamp_utc", "request_id", "route", "kind", "http_status", "detail", "session_id", "login_id"])
_init_csv(ACK_CSV, ["timestamp_utc", "ack_key", "session_id", "login_id", "acknowledged", "privacy_url", "terms_url"])
_init_csv(REFUSALS_CSV, ["created_utc", "analysis_id", "source", "category", "reason", "input_len", "input_sha256"])
_init_csv(
    FEEDBACK_CSV,
    [
        "timestamp_utc",
        "analysis_id",
        "session_id",
        "login_id",
        "clarity",
        "objectivity",
        "usefulness",
        "appropriateness",
        "alignment",
        "comments",
        "input_sha256",
        "input_text",
    ],
)
_init_csv(
    BUGS_CSV,
    [
        "timestamp_utc",
        "bug_id",
        "analysis_id",
        "session_id",
        "login_id",
        "is_admin",
        "title",
        "category",
        "severity",
        "steps_to_reproduce",
        "expected_behavior",
        "actual_behavior",
        "page_context",
        "user_agent",
        "attachment_path",
        "status",
    ],
)

_prune_csv(AUTH_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ANALYSES_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ERRORS_CSV, TTL_DAYS_DEFAULT)
_prune_csv(ACK_CSV, TTL_DAYS_DEFAULT)
_prune_csv(REFUSALS_CSV, TTL_DAYS_DEFAULT)
_prune_csv(FEEDBACK_CSV, TTL_DAYS_DEFAULT)
_prune_csv(BUGS_CSV, TTL_DAYS_DEFAULT)

_prune_table("auth_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("analyses", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("errors", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("ack_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("refusal_events", "created_utc", TTL_DAYS_DEFAULT)
_prune_table("feedback_events", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("bug_reports", "timestamp_utc", TTL_DAYS_DEFAULT)
_prune_table("institution_users", "created_utc", TTL_DAYS_DEFAULT)

# =============================================================================
# INSTITUTION ACCOUNT OPS
# =============================================================================
def admin_create_institution_user(
    institution_name: str,
    trial_start: str = "",
    trial_end: str = "",
    notes: str = "",
) -> Tuple[str, str]:
    """
    Creates a new institutional login.
    Returns (institution_id, plain_password) -- shown ONCE.
    """
    inst_id = f"inst_{secrets.token_hex(4).upper()}"
    plain_pwd = secrets.token_urlsafe(12)
    pwd_hash = _hash_password(plain_pwd)
    created = _now_utc_iso()

    _db_exec(
        """INSERT INTO institution_users
           (institution_name, institution_id, password_hash, created_utc, active, trial_start, trial_end, notes)
           VALUES (?,?,?,?,1,?,?,?)""",
        (
            (institution_name or "").strip()[:180],
            inst_id,
            pwd_hash,
            created,
            (trial_start or "").strip()[:40],
            (trial_end or "").strip()[:40],
            (notes or "").strip()[:500],
        ),
    )
    return inst_id, plain_pwd


def admin_reset_institution_password(institution_id: str) -> Optional[str]:
    new_pwd = secrets.token_urlsafe(12)
    new_hash = _hash_password(new_pwd)
    bid = (institution_id or "").strip()

    row = _db_fetchone("SELECT 1 FROM institution_users WHERE institution_id=? LIMIT 1", (bid,))
    if not row:
        return None

    _db_exec("UPDATE institution_users SET password_hash=? WHERE institution_id=?", (new_hash, bid))
    return new_pwd


def admin_set_institution_active(institution_id: str, active: bool) -> bool:
    bid = (institution_id or "").strip()
    row = _db_fetchone("SELECT 1 FROM institution_users WHERE institution_id=? LIMIT 1", (bid,))
    if not row:
        return False
    _db_exec("UPDATE institution_users SET active=? WHERE institution_id=?", (1 if active else 0, bid))
    return True


def get_institution_user_for_login(institution_id: str) -> Optional[Tuple[str, int, str, str]]:
    """
    Returns (password_hash, active, trial_start, trial_end) or None
    """
    bid = (institution_id or "").strip()
    row = _db_fetchone(
        """SELECT password_hash, active, trial_start, trial_end
           FROM institution_users
           WHERE institution_id=? LIMIT 1""",
        (bid,),
    )
    if not row:
        return None
    return (row[0] or "", int(row[1] or 0), (row[2] or "")[:40], (row[3] or "")[:40])


def _trial_expired(trial_end: str) -> bool:
    """
    trial_end is expected ISO8601 (recommended):
      2026-04-15T23:59:59+00:00
    We fail-open if unparsable to avoid accidental lockouts.
    """
    te = (trial_end or "").strip()
    if not te:
        return False
    try:
        end_dt = datetime.fromisoformat(te)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > end_dt
    except Exception:
        return False


# =============================================================================
# LOGGING
# =============================================================================
def log_auth_event(
    event_type: str,
    success: bool,
    login_id: str = "",
    credential_label: str = "APP_PASSWORD",
    attempted_secret: str = "",
) -> None:
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


def log_analysis_event(
    analysis_id: str,
    model: str,
    elapsed_seconds: float,
    analyzed_text: str,
    output_text: str,
) -> None:
    """
    ✅ Stores full analyzed input + full output in BOTH:
    - analyses.csv
    - analyses table (SQLite)
    """
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = (st.session_state.get("login_id") or "")[:120]

    text = (analyzed_text or "").strip()
    out = (output_text or "").strip()

    row = [
        ts,
        (analysis_id or "")[:40],
        sid,
        login_id,
        (model or "")[:80],
        float(elapsed_seconds or 0.0),
        len(text),
        _safe_preview(text, 220),
        _sha256(text) if text else "",
        text,
        out,
    ]

    try:
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
    except Exception:
        pass

    try:
        _db_exec(
            """INSERT INTO analyses
               (timestamp_utc,analysis_id,session_id,login_id,model,elapsed_seconds,input_chars,input_preview,input_sha256,input_text,output_text)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts,
                (analysis_id or "")[:40],
                sid,
                login_id,
                (model or "")[:80],
                float(elapsed_seconds or 0.0),
                len(text),
                _safe_preview(text, 220),
                _sha256(text) if text else "",
                text,
                out,
            ),
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
    analyzed_text: str = "",
) -> None:
    """
    ✅ Stores feedback + FULL input_text (plaintext) in:
    - feedback_events.csv
    - feedback_events table (SQLite)
    Also stores optional encrypted copy in SQLite if enabled.
    """
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = (st.session_state.get("login_id") or "")[:120]
    aid = (analysis_id or "")[:40]

    cmt = (comments or "").strip()
    if len(cmt) > MAX_FEEDBACK_COMMENT_CHARS:
        cmt = cmt[:MAX_FEEDBACK_COMMENT_CHARS] + "…"

    text = (analyzed_text or "").strip()
    text_sha = _sha256(text) if text else ""

    text_enc = ""
    if STORE_ENCRYPTED_INPUT_FOR_FEEDBACK and text:
        try:
            text_enc = _encrypt_text(text)
        except Exception:
            text_enc = ""

    # CSV (includes plaintext input_text)
    try:
        with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                [ts, aid, sid, login_id, clarity, objectivity, usefulness, appropriateness, alignment, cmt, text_sha, text]
            )
    except Exception:
        pass

    # SQLite (includes plaintext + optional encrypted copy)
    try:
        _db_exec(
            """INSERT INTO feedback_events
               (timestamp_utc,analysis_id,session_id,login_id,clarity,objectivity,usefulness,appropriateness,alignment,comments,input_sha256,input_text,input_encrypted)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                ts,
                aid,
                sid,
                login_id,
                int(clarity),
                int(objectivity),
                int(usefulness),
                int(appropriateness),
                int(alignment),
                cmt,
                text_sha,
                text,
                text_enc,
            ),
        )
    except Exception:
        pass


def _get_user_agent_best_effort() -> str:
    """
    Best-effort user agent capture.
    Streamlit doesn't guarantee access in all deployments, so fail-closed to "".
    """
    try:
        ctx = getattr(st, "context", None)
        if ctx and getattr(ctx, "headers", None):
            ua = (ctx.headers.get("User-Agent") or ctx.headers.get("user-agent") or "").strip()
            return ua[:400]
    except Exception:
        pass
    return ""


def _save_bug_attachment(file_obj) -> str:
    """
    Saves attachment to disk (STATIC_DIR/uploads/bugs).
    Returns saved path as string or "".
    """
    if file_obj is None:
        return ""

    try:
        raw = file_obj.getvalue()
    except Exception:
        try:
            raw = file_obj.read()
        except Exception:
            return ""

    if not raw:
        return ""

    max_bytes = int(MAX_BUG_ATTACHMENT_MB * 1024 * 1024)
    if len(raw) > max_bytes:
        raise ValueError(f"Attachment exceeds {MAX_BUG_ATTACHMENT_MB:.1f}MB.")

    orig_name = (getattr(file_obj, "name", "") or "attachment").strip()
    ext = ""
    if "." in orig_name:
        ext = "." + orig_name.rsplit(".", 1)[-1].lower()

    # allow common screenshot formats only
    if ext not in {".png", ".jpg", ".jpeg", ".webp"}:
        raise ValueError("Attachment must be PNG, JPG, JPEG, or WEBP.")

    fname = f"BUG-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4).upper()}{ext}"
    out_path = BUGS_UPLOAD_DIR / fname
    with open(out_path, "wb") as f:
        f.write(raw)

    return str(out_path)


def log_bug_report(
    title: str,
    category: str,
    severity: str,
    steps_to_reproduce: str,
    expected_behavior: str,
    actual_behavior: str,
    analysis_id: str = "",
    page_context: str = "Report a Bug",
    attachment_file=None,
) -> str:
    """
    Writes bug report to bug_reports.csv + SQLite.
    Does NOT store full analysis input text. Optionally links analysis_id.
    Returns bug_id.
    """
    ts = _now_utc_iso()
    sid = ensure_session_id()
    login_id = (st.session_state.get("login_id") or "")[:120]
    is_admin = 1 if st.session_state.get("is_admin", False) else 0

    t = (title or "").strip()
    if len(t) > MAX_BUG_TITLE_CHARS:
        t = t[:MAX_BUG_TITLE_CHARS] + "…"

    def _cap(x: str) -> str:
        x = (x or "").strip()
        if len(x) > MAX_BUG_TEXT_CHARS:
            return x[:MAX_BUG_TEXT_CHARS] + "…"
        return x

    steps = _cap(steps_to_reproduce)
    exp = _cap(expected_behavior)
    act = _cap(actual_behavior)

    aid = (analysis_id or "").strip()[:40]
    ua = _get_user_agent_best_effort()

    attachment_path = ""
    try:
        attachment_path = _save_bug_attachment(attachment_file) if attachment_file is not None else ""
    except Exception as e:
        # Fail-closed on attachment but still allow bug submission
        attachment_path = f"ATTACHMENT_ERROR: {str(e)[:180]}"

    bug_id = f"BUG-{uuid.uuid4().hex[:12].upper()}"
    status = "Open"

    # CSV
    try:
        with open(BUGS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(
                [
                    ts,
                    bug_id,
                    aid,
                    sid,
                    login_id,
                    is_admin,
                    t,
                    (category or "")[:40],
                    (severity or "")[:20],
                    steps,
                    exp,
                    act,
                    (page_context or "")[:80],
                    ua,
                    attachment_path,
                    status,
                ]
            )
    except Exception:
        pass

    # SQLite
    try:
        _db_exec(
            """INSERT INTO bug_reports
               (id,timestamp_utc,analysis_id,session_id,login_id,is_admin,title,category,severity,
                steps_to_reproduce,expected_behavior,actual_behavior,page_context,user_agent,attachment_path,status,internal_notes)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                bug_id,
                ts,
                aid,
                sid,
                login_id,
                is_admin,
                t,
                (category or "")[:40],
                (severity or "")[:20],
                steps,
                exp,
                act,
                (page_context or "")[:80],
                ua,
                attachment_path,
                status,
                "",
            ),
        )
    except Exception:
        pass

    return bug_id


def _update_bug_status_in_csv(bug_id: str, new_status: str) -> bool:
    """
    Updates status in bug_reports.csv for the given bug_id.
    Returns True if a row was updated, else False.
    """
    try:
        if not os.path.exists(BUGS_CSV):
            return False

        with open(BUGS_CSV, "r", newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))

        if not rows:
            return False

        header = rows[0]
        data = rows[1:]

        # Find indices safely (supports future reordering)
        try:
            idx_bug = header.index("bug_id")
            idx_status = header.index("status")
        except ValueError:
            # Fallback to known positions if header changed unexpectedly
            idx_bug = 1
            idx_status = len(header) - 1

        updated = False
        for r in data:
            if len(r) <= max(idx_bug, idx_status):
                continue
            if (r[idx_bug] or "").strip() == bug_id:
                r[idx_status] = (new_status or "").strip()
                updated = True
                break

        if not updated:
            return False

        with open(BUGS_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(data)

        return True
    except Exception:
        return False


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
st.session_state.setdefault("last_analyzed_input", "")

# =============================================================================
# AUTH UI
# =============================================================================
def show_login() -> None:
    st.markdown(
        "<h2 style='color:#FF7A00; font-weight:700;'>Veritas Institutional Trial Portal</h2>",
        unsafe_allow_html=True,
    )

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
            login_id = st.text_input("Institutional User ID", value=st.session_state.get("login_id", ""))
            pwd = st.text_input("Password", type="password")
            submit = st.form_submit_button("Enter")

        if submit:
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
                st.error("Institutional User ID is required.")
                st.stop()

            rec = get_institution_user_for_login(login_id_clean)
            if not rec:
                _note_failed_login(attempted_secret=pwd)
                st.error("Invalid credentials.")
                st.stop()

            stored_hash, active, trial_start, trial_end = rec
            if active != 1:
                st.error("This institutional account is disabled.")
                st.stop()

            if _trial_expired(trial_end):
                st.error("This trial account has expired.")
                st.stop()

            if _verify_password(_norm(pwd), stored_hash):
                st.session_state["authed"] = True
                st.session_state["is_admin"] = False
                st.session_state["login_id"] = login_id_clean
                st.session_state["_fail_times"] = deque()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=login_id_clean, credential_label="INSTITUTION_USERS_DB")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=pwd)
                st.error("Invalid credentials.")
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
        cred = "ADMIN_PASSWORD" if st.session_state.get("is_admin", False) else "INSTITUTION_USERS_DB"
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label=cred)
        sid = st.session_state.get("sid")
        st.session_state.clear()
        st.session_state["sid"] = sid
        _safe_rerun()

# =============================================================================
# MAIN UI
# =============================================================================
def reset_canvas() -> None:
    st.session_state["doc_uploader_key"] = st.session_state.get("doc_uploader_key", 0) + 1
    st.session_state["user_input_box"] = ""
    st.session_state["last_report"] = ""
    st.session_state["report_ready"] = False
    st.session_state["veritas_analysis_id"] = ""
    st.session_state["last_analyzed_input"] = ""


if st.session_state.get("is_admin", False):
    tabs = st.tabs(["Analyze", "Report a Bug", "Admin"])
    tab_analyze, tab_bug, tab_admin = tabs[0], tabs[1], tabs[2]
else:
    tabs = st.tabs(["Analyze", "Report a Bug"])
    tab_analyze, tab_bug = tabs[0], tabs[1]
    tab_admin = None

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
            key=f"doc_uploader_{st.session_state.get('doc_uploader_key', 0)}",
        )

        c1, c2 = st.columns([2, 1])
        with c1:
            submitted = st.form_submit_button("Engage Veritas", use_container_width=True)
        with c2:
            st.form_submit_button("Start New Analysis", use_container_width=True, on_click=reset_canvas)

    if submitted:
        new_request_id()

        extracted_text = ""
        if doc is not None:
            extracted_text = extract_document_text(doc)[:MAX_EXTRACT_CHARS]

        final_input = (user_text + ("\n\n" + extracted_text if extracted_text else "")).strip()

        if not final_input:
            st.warning("Please paste text or upload a document to analyze.")
            st.stop()

        # Store analyzed input (for feedback + diagnostics)
        st.session_state["last_analyzed_input"] = final_input

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

        t0 = time.time()
        resp = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
                {"role": "user", "content": final_input},
            ],
            temperature=TEMPERATURE,
        )
        elapsed = time.time() - t0

        report = (resp.choices[0].message.content or "").strip()
        st.session_state["last_report"] = report
        st.session_state["report_ready"] = True

        # ✅ Persist EVERYTHING + full input + output
        log_analysis_event(
            analysis_id=analysis_id,
            model=MODEL_NAME,
            elapsed_seconds=elapsed,
            analyzed_text=final_input,
            output_text=report,
        )

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
                        analyzed_text=st.session_state.get("last_analyzed_input", ""),
                    )
                    st.session_state["feedback_last_submitted_analysis_id"] = st.session_state["veritas_analysis_id"]
                    st.success("Thank you. Your feedback has been recorded.")
                    _safe_rerun()

# =============================================================================
# REPORT A BUG TAB
# =============================================================================
with tab_bug:
    st.subheader("Report a Bug")
    st.caption("Use this form to report issues. Do not paste sensitive data.")

    prefill_aid = (st.session_state.get("veritas_analysis_id") or "").strip()

    with st.form("bug_form", clear_on_submit=True):
        analysis_id = st.text_input(
            "Veritas Analysis ID (optional)",
            value=prefill_aid,
            help="If this bug relates to a specific analysis, keep this filled in.",
        )

        title = st.text_input("Bug Title", max_chars=MAX_BUG_TITLE_CHARS)

        c1, c2 = st.columns(2)
        with c1:
            category = st.selectbox(
                "Category",
                ["UI", "Upload/Parsing", "Analysis", "Performance", "Login/Access", "Other"],
                index=0,
            )
        with c2:
            severity = st.selectbox(
                "Severity",
                ["Low", "Medium", "High", "Critical"],
                index=1,
            )

        steps = st.text_area("Steps to Reproduce", height=140, placeholder="1) ...\n2) ...\n3) ...")
        expected = st.text_area("Expected Behavior", height=90)
        actual = st.text_area("Actual Behavior", height=90)

        attachment = st.file_uploader(
            f"Optional Screenshot (PNG/JPG/WEBP, up to {MAX_BUG_ATTACHMENT_MB:.0f}MB)",
            type=["png", "jpg", "jpeg", "webp"],
            accept_multiple_files=False,
        )

        submitted_bug = st.form_submit_button("Submit Bug Report", use_container_width=True)

    if submitted_bug:
        if not (title or "").strip():
            st.error("Bug Title is required.")
            st.stop()

        bug_id = log_bug_report(
            title=title,
            category=category,
            severity=severity,
            steps_to_reproduce=steps,
            expected_behavior=expected,
            actual_behavior=actual,
            analysis_id=analysis_id,
            page_context="Report a Bug",
            attachment_file=attachment,
        )

        st.success(f"Bug submitted. Tracking ID: `{bug_id}`")

# =============================================================================
# ADMIN TAB
# =============================================================================
if tab_admin is not None:
    with tab_admin:
        st.header("Admin Dashboard")

        st.subheader("Diagnostics")
        st.write(f"APP_MODE: `{APP_MODE or '(unset)'}`")
        st.write(f"Model: `{MODEL_NAME}`")
        st.write(f"Temperature: `{TEMPERATURE}`")
        st.write(f"DB Path: `{DB_PATH}`")
        st.write(f"Trial Feedback Mode: `{'ON' if INSTITUTIONAL_TRIAL_MODE else 'OFF'}`")
        st.write(f"Encrypted feedback input copy: `{'ON' if STORE_ENCRYPTED_INPUT_FOR_FEEDBACK else 'OFF'}`")

        # ---------------------------------------------------------------------
        # INSTITUTION ACCOUNTS (CREATE / RESET / ENABLE-DISABLE / EXPORT)
        # ---------------------------------------------------------------------
        st.divider()
        st.subheader("Institution Accounts (Login IDs & Passwords)")

        with st.form("inst_create_form", clear_on_submit=True):
            inst_name = st.text_input("Institution Name")
            c1, c2 = st.columns(2)
            with c1:
                trial_start = st.text_input("Trial Start (optional, ISO e.g., 2026-04-01T00:00:00+00:00)")
            with c2:
                trial_end = st.text_input("Trial End (optional, ISO e.g., 2026-04-15T23:59:59+00:00)")
            notes = st.text_area("Notes (optional)", height=90)
            create_inst = st.form_submit_button("Generate Institution Credentials", use_container_width=True)

        if create_inst:
            if not (inst_name or "").strip():
                st.error("Institution Name is required.")
                st.stop()

            inst_id, inst_pwd = admin_create_institution_user(
                institution_name=inst_name,
                trial_start=trial_start,
                trial_end=trial_end,
                notes=notes,
            )
            st.success("Institution account created. Copy credentials now (password shown only once).")
            st.code(f"Institution ID: {inst_id}\nPassword: {inst_pwd}")

        st.markdown("#### Reset / Disable / Enable")

        with st.form("inst_manage_form", clear_on_submit=True):
            manage_id = st.text_input("Institution ID (e.g., inst_ABC12345)")
            action = st.selectbox("Action", ["Reset Password", "Disable Account", "Enable Account"])
            manage_submit = st.form_submit_button("Apply", use_container_width=True)

        if manage_submit:
            mid = (manage_id or "").strip()
            if not mid:
                st.error("Institution ID is required.")
                st.stop()

            if action == "Reset Password":
                new_pwd = admin_reset_institution_password(mid)
                if not new_pwd:
                    st.error("Institution ID not found.")
                    st.stop()
                st.success("Password reset. Copy new password now (shown only once).")
                st.code(f"Institution ID: {mid}\nNew Password: {new_pwd}")

            elif action == "Disable Account":
                ok = admin_set_institution_active(mid, False)
                if not ok:
                    st.error("Institution ID not found.")
                    st.stop()
                st.success("Account disabled.")

            else:
                ok = admin_set_institution_active(mid, True)
                if not ok:
                    st.error("Institution ID not found.")
                    st.stop()
                st.success("Account enabled.")

        st.markdown("#### Institution Accounts (Export)")
        rows = _db_fetchall(
            """SELECT institution_name, institution_id, active, created_utc, trial_start, trial_end, notes
               FROM institution_users
               ORDER BY created_utc DESC
               LIMIT 2000"""
        )
        if not rows:
            st.info("No institution accounts created yet.")
        else:
            idf = pd.DataFrame(
                rows,
                columns=["institution_name", "institution_id", "active", "created_utc", "trial_start", "trial_end", "notes"],
            )
            st.dataframe(idf, use_container_width=True)
            st.download_button(
                "Download Institution Accounts (CSV)",
                data=idf.to_csv(index=False).encode("utf-8"),
                file_name="veritas_institution_accounts.csv",
                mime="text/csv",
            )

        # ---------------------------------------------------------------------
        # BUG REPORTS (INBOX / EXPORT / STATUS UPDATES)
        # ---------------------------------------------------------------------
        st.divider()
        st.subheader("Bug Reports (Inbox / Export)")

        def fetch_recent_bugs(limit: int = 1000) -> List[Tuple[Any, ...]]:
            try:
                con = sqlite3.connect(DB_PATH, timeout=30)
                cur = con.cursor()
                cur.execute(
                    """SELECT timestamp_utc, id, analysis_id, login_id, is_admin,
                              title, category, severity, status,
                              steps_to_reproduce, expected_behavior, actual_behavior,
                              page_context, user_agent, attachment_path, internal_notes
                       FROM bug_reports
                       ORDER BY timestamp_utc DESC
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

        brows = fetch_recent_bugs(limit=1000)
        if not brows:
            st.info("No bug reports logged yet.")
        else:
            bdf = pd.DataFrame(
                brows,
                columns=[
                    "timestamp_utc",
                    "bug_id",
                    "analysis_id",
                    "login_id",
                    "is_admin",
                    "title",
                    "category",
                    "severity",
                    "status",
                    "steps_to_reproduce",
                    "expected_behavior",
                    "actual_behavior",
                    "page_context",
                    "user_agent",
                    "attachment_path",
                    "internal_notes",
                ],
            )

            f1, f2, f3 = st.columns(3)
            with f1:
                sev_vals = sorted([v for v in bdf["severity"].dropna().unique().tolist() if str(v).strip()])
                sev_filter = st.selectbox("Severity", ["(All)"] + sev_vals, index=0)
            with f2:
                status_vals = sorted([v for v in bdf["status"].dropna().unique().tolist() if str(v).strip()])
                status_filter = st.selectbox("Status", ["(All)"] + status_vals, index=0)
            with f3:
                cat_vals = sorted([v for v in bdf["category"].dropna().unique().tolist() if str(v).strip()])
                cat_filter = st.selectbox("Category", ["(All)"] + cat_vals, index=0)

            view = bdf
            if sev_filter != "(All)":
                view = view[view["severity"] == sev_filter]
            if status_filter != "(All)":
                view = view[view["status"] == status_filter]
            if cat_filter != "(All)":
                view = view[view["category"] == cat_filter]

            st.dataframe(view, use_container_width=True)

            st.download_button(
                "Download Bug Reports (CSV)",
                data=view.to_csv(index=False).encode("utf-8"),
                file_name="veritas_bug_reports.csv",
                mime="text/csv",
            )

            st.markdown("#### Update Bug Status / Internal Notes")
            with st.form("bug_update_form", clear_on_submit=True):
                bug_id_in = st.text_input("Bug ID (e.g., BUG-ABC123...)")
                new_status = st.selectbox("New Status", ["Open", "In Review", "Blocked", "Resolved", "Won't Fix"])
                new_notes = st.text_area("Internal Notes (optional)", height=120)
                upd = st.form_submit_button("Update Bug", use_container_width=True)

            if upd:
                bid = (bug_id_in or "").strip()
                if not bid:
                    st.error("Bug ID is required.")
                    st.stop()

                # 1) Update SQLite
                try:
                    _db_exec(
                        "UPDATE bug_reports SET status=?, internal_notes=? WHERE id=?",
                        (new_status, (new_notes or "").strip(), bid),
                    )
                except Exception:
                    st.error("Failed to update bug. Verify Bug ID exists and DB is writable.")
                    st.stop()

                # 2) Update CSV tracker status (so it matches)
                csv_ok = _update_bug_status_in_csv(bid, new_status)
                if not csv_ok:
                    st.warning("Updated SQLite, but could not update bug_reports.csv (row not found or file missing).")

                st.success("Bug updated.")
                _safe_rerun()

        # ---------------------------------------------------------------------
        # ANALYSES (EXPORT) — moved under Bug Reports
        # ---------------------------------------------------------------------
        st.divider()
        st.subheader("Analyses (Export)")

        def fetch_recent_analyses(limit: int = 500) -> List[Tuple[Any, ...]]:
            try:
                con = sqlite3.connect(DB_PATH, timeout=30)
                cur = con.cursor()
                cur.execute(
                    """SELECT timestamp_utc, analysis_id, login_id, model, elapsed_seconds,
                              input_chars, input_preview, input_sha256, input_text, output_text
                       FROM analyses
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

        arows = fetch_recent_analyses(limit=500)
        if not arows:
            st.info("No analyses logged yet.")
        else:
            adf = pd.DataFrame(
                arows,
                columns=[
                    "timestamp_utc",
                    "analysis_id",
                    "login_id",
                    "model",
                    "elapsed_seconds",
                    "input_chars",
                    "input_preview",
                    "input_sha256",
                    "input_text",
                    "output_text",
                ],
            )
            st.dataframe(adf, use_container_width=True)
            st.download_button(
                "Download Analyses Log (CSV)",
                data=adf.to_csv(index=False).encode("utf-8"),
                file_name="veritas_analyses_log.csv",
                mime="text/csv",
            )

        # ---------------------------------------------------------------------
        # TRIAL FEEDBACK (EXPORT) — moved under Bug Reports
        # ---------------------------------------------------------------------
        st.divider()
        st.subheader("Trial Feedback (Export)")

        def fetch_recent_feedback(limit: int = 1000) -> List[Tuple[Any, ...]]:
            try:
                con = sqlite3.connect(DB_PATH, timeout=30)
                cur = con.cursor()
                cur.execute(
                    """SELECT timestamp_utc, analysis_id, login_id, clarity, objectivity, usefulness,
                              appropriateness, alignment, comments, input_sha256, input_text,
                              CASE WHEN input_encrypted IS NOT NULL AND input_encrypted != '' THEN 1 ELSE 0 END AS has_encrypted_copy
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
                columns=[
                    "timestamp_utc",
                    "analysis_id",
                    "login_id",
                    "clarity",
                    "objectivity",
                    "usefulness",
                    "appropriateness",
                    "alignment",
                    "comments",
                    "input_sha256",
                    "input_text",
                    "has_encrypted_copy",
                ],
            )
            st.dataframe(fdf, use_container_width=True)
            st.download_button(
                "Download Feedback Log (CSV)",
                data=fdf.to_csv(index=False).encode("utf-8"),
                file_name="veritas_feedback_log.csv",
                mime="text/csv",
            )

        # ---------------------------------------------------------------------
        # TENANT MANAGEMENT (unchanged)
        # ---------------------------------------------------------------------
        st.divider()
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
            st.write(
                {
                    "tenant_id": tenant_id_val,
                    "tier": t.get("tier"),
                    "annual_limit": limit_val,
                    "status": t.get("status"),
                    "usage_this_year": used,
                    "created_utc": t.get("created_utc"),
                    "updated_utc": t.get("updated_utc"),
                }
            )

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

# =============================================================================
# FOOTER
# =============================================================================
st.markdown(
    "<div style='margin-top:1.25rem;opacity:.75;font-size:.9rem;'>Copyright © 2026 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True,
)



