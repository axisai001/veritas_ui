# streamlit_app.py — Veritas (Streamlit)
# Tabs: Analyze, Feedback, Support, Help, (Admin only if authenticated as admin)
# Strict 10-section bias report, CSV+SQLite logging, SendGrid email.
# Post-login Privacy/Terms acknowledgment (persisted), Admin maintenance tools,
# and robust background image support (local static file OR external URL).
#
# Update (overrides-first email config):
# - Per-tab overrides (FEEDBACK_* / SUPPORT_*) are treated as first-class.
# - If ALL required override fields for a channel are present AND valid, globals are ignored.
# - If any override fields are missing, we gracefully fall back to global SENDGRID_* for just those fields.
# - Status banner reflects actual effective config per tab.
#
# New (auth flow):
# - Pre-login screen lets user choose "User" or "Admin" sign-in.
# - Admin tab only appears when authenticated as admin.
# - No admin login UI after login for regular users.

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
from typing import Optional, List, Dict
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
    settings = load_settings()  # requires OPENAI_API_KEY available to it
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

def _parse_pilot_start_to_utc(s: str):
    if not s: return None
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

# SendGrid globals (fallbacks)
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "") or st.secrets.get("SENDGRID_API_KEY", "")
SENDGRID_TO       = os.environ.get("SENDGRID_TO", "") or st.secrets.get("SENDGRID_TO", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM", "") or st.secrets.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT  = os.environ.get("SENDGRID_SUBJECT", "") or st.secrets.get("SENDGRID_SUBJECT", "New Veritas Feedback")

# ======= Email config helpers (overrides-first) =======
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _get_secret_multi(candidates: List[str]) -> str:
    # env first
    for nm in candidates:
        v = os.environ.get(nm)
        if v and str(v).strip():
            return str(v).strip()
    # st.secrets flat
    try:
        for nm in candidates:
            v = st.secrets.get(nm, "")
            if v and str(v).strip():
                return str(v).strip()
        # st.secrets nested (dot notation)
        for nm in candidates:
            if "." in nm:
                parts = nm.split(".")
                cur = st.secrets
                ok = True
                for p in parts:
                    if isinstance(cur, dict) and p in cur:
                        cur = cur[p]
                    else:
                        ok = False
                        break
                if ok and cur and str(cur).strip():
                    return str(cur).strip()
    except Exception:
        pass
    return ""

def _channel_overrides(channel: str) -> Dict[str, str]:
    ch = channel.strip().lower()
    return {
        "api_key": _get_secret_multi([f"{ch.upper()}_SENDGRID_API_KEY", f"{ch}.sendgrid.api_key"]),
        "from":    _get_secret_multi([f"{ch.upper()}_SENDGRID_FROM",    f"{ch}.sendgrid.from"]),
        "to":      _get_secret_multi([f"{ch.upper()}_SENDGRID_TO",      f"{ch}.sendgrid.to"]),
        "subject": _get_secret_multi([f"{ch.upper()}_SENDGRID_SUBJECT", f"{ch}.sendgrid.subject"]),
    }

def _overrides_are_complete_and_valid(ov: Dict[str, str], default_subject: str) -> bool:
    # api_key non-trivial, from/to valid emails; subject can fall back
    key_ok = bool(ov["api_key"] and len(ov["api_key"]) > 20)
    from_ok = bool(ov["from"] and EMAIL_RE.match(ov["from"]))
    to_ok   = bool(ov["to"]   and EMAIL_RE.match(ov["to"]))
    # subject not strictly required (we can supply default)
    return key_ok and from_ok and to_ok

def _effective_mail_cfg(channel: str) -> Dict[str, str]:
    """
    If channel overrides are present AND valid (key/from/to), return ONLY overrides (subject fallback allowed).
    Otherwise, construct a mixed config that uses any provided overrides and falls back to globals per field.
    """
    ch = channel.strip().lower()
    default_subject = "New Veritas Support Ticket" if ch == "support" else (SENDGRID_SUBJECT or "New Veritas Feedback")
    ov = _channel_overrides(ch)

    if _overrides_are_complete_and_valid(ov, default_subject):
        return {
            "api_key": ov["api_key"],
            "from":    ov["from"],
            "to":      ov["to"],
            "subject": ov["subject"] or default_subject,
            "source":  "overrides-only"
        }

    # Partial overrides or none → fall back per field to globals
    return {
        "api_key": ov["api_key"] or SENDGRID_API_KEY,
        "from":    ov["from"]    or SENDGRID_FROM,
        "to":      ov["to"]      or SENDGRID_TO,
        "subject": (ov["subject"] or ( "New Veritas Support Ticket" if ch == "support" else (SENDGRID_SUBJECT or "New Veritas Feedback") )),
        "source":  "mixed-or-global"
    }

def _email_is_configured(channel: str) -> bool:
    cfg = _effective_mail_cfg(channel)
    key_ok = bool(cfg["api_key"] and len(cfg["api_key"]) > 20)
    from_ok = bool(cfg["from"] and EMAIL_RE.match(cfg["from"]))
    to_ok   = bool(cfg["to"]   and EMAIL_RE.match(cfg["to"]))
    return key_ok and from_ok and to_ok

def _mask_email(addr: str) -> str:
    try:
        left, right = addr.split("@", 1)
        left_m = (left[0] + "*"*(max(0,len(left)-2)) + left[-1]) if len(left) > 2 else left[0] + "*"
        dom, *rest = right.split(".")
        dom_m = (dom[0] + "*"*(max(0,len(dom)-2)) + dom[-1]) if len(dom) > 2 else dom[0] + "*"
        tail = ".".join(rest) if rest else ""
        return f"{left_m}@{dom_m}{('.' + tail) if tail else ''}"
    except Exception:
        return "********"

def _email_status(channel: str):
    cfg = _effective_mail_cfg(channel)
    if _email_is_configured(channel):
        st.success(
            f"Email is enabled for {channel} ({cfg['source']}). "
            f"FROM={_mask_email(cfg['from'])} → TO={_mask_email(cfg['to'])}"
        )
    else:
        missing = []
        if not (cfg["api_key"] and len(cfg["api_key"]) > 20): missing.append("API_KEY")
        if not (cfg["from"] and EMAIL_RE.match(cfg["from"])): missing.append("FROM")
        if not (cfg["to"]   and EMAIL_RE.match(cfg["to"])):   missing.append("TO")
        st.warning(
            f"Email delivery is NOT configured for {channel} ({cfg['source']}). "
            + ("Missing/invalid: " + ", ".join(missing) if missing else "Unknown error") + "."
        )

# Password gate
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# Lockout config
LOCKOUT_THRESHOLD      = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC     = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC   = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800"))

# Storage / branding
BASE_DIR      = os.path.dirname(__file__)
STATIC_DIR    = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(STATIC_DIR, "uploads")
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

ALLOWED_EXTENSIONS     = {"png", "jpg", "jpeg", "webp"}
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}
BG_ALLOWED_EXTENSIONS  = {"svg", "png", "jpg", "jpeg", "webp"}

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
_init_csv(SUPPORT_CSV,  ["timestamp_utc","timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"] if False else ["timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"])
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

# ===== Identity + Veritas Prompts (EXACT as provided) =====
IDENTITY_PROMPT = "I'm Veritas — a bias detection tool."

DEFAULT_SYSTEM_PROMPT = """
# streamlit_app.py — Veritas (Streamlit)
# Tabs: Analyze, Feedback, Support, Help, (Admin only if authenticated as admin)
# Strict 10-section bias report, CSV+SQLite logging, SendGrid email.
# Post-login Privacy/Terms acknowledgment (persisted), Admin maintenance tools,
# and robust background image support (local static file OR external URL).
#
# Update (overrides-first email config):
# - Per-tab overrides (FEEDBACK_* / SUPPORT_*) are treated as first-class.
# - If ALL required override fields for a channel are present AND valid, globals are ignored.
# - If any override fields are missing, we gracefully fall back to global SENDGRID_* for just those fields.
# - Status banner reflects actual effective config per tab.
#
# New (auth flow):
# - Pre-login screen lets user choose "User" or "Admin" sign-in.
# - Admin tab only appears when authenticated as admin.
# - No admin login UI after login for regular users.

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
from typing import Optional, List, Dict
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
    settings = load_settings()  # requires OPENAI_API_KEY available to it
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

def _parse_pilot_start_to_utc(s: str):
    if not s: return None
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

# SendGrid globals (fallbacks)
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "") or st.secrets.get("SENDGRID_API_KEY", "")
SENDGRID_TO       = os.environ.get("SENDGRID_TO", "") or st.secrets.get("SENDGRID_TO", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM", "") or st.secrets.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT  = os.environ.get("SENDGRID_SUBJECT", "") or st.secrets.get("SENDGRID_SUBJECT", "New Veritas Feedback")

# ======= Email config helpers (overrides-first) =======
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _get_secret_multi(candidates: List[str]) -> str:
    # env first
    for nm in candidates:
        v = os.environ.get(nm)
        if v and str(v).strip():
            return str(v).strip()
    # st.secrets flat
    try:
        for nm in candidates:
            v = st.secrets.get(nm, "")
            if v and str(v).strip():
                return str(v).strip()
        # st.secrets nested (dot notation)
        for nm in candidates:
            if "." in nm:
                parts = nm.split(".")
                cur = st.secrets
                ok = True
                for p in parts:
                    if isinstance(cur, dict) and p in cur:
                        cur = cur[p]
                    else:
                        ok = False
                        break
                if ok and cur and str(cur).strip():
                    return str(cur).strip()
    except Exception:
        pass
    return ""

def _channel_overrides(channel: str) -> Dict[str, str]:
    ch = channel.strip().lower()
    return {
        "api_key": _get_secret_multi([f"{ch.upper()}_SENDGRID_API_KEY", f"{ch}.sendgrid.api_key"]),
        "from":    _get_secret_multi([f"{ch.upper()}_SENDGRID_FROM",    f"{ch}.sendgrid.from"]),
        "to":      _get_secret_multi([f"{ch.upper()}_SENDGRID_TO",      f"{ch}.sendgrid.to"]),
        "subject": _get_secret_multi([f"{ch.upper()}_SENDGRID_SUBJECT", f"{ch}.sendgrid.subject"]),
    }

def _overrides_are_complete_and_valid(ov: Dict[str, str], default_subject: str) -> bool:
    # api_key non-trivial, from/to valid emails; subject can fall back
    key_ok = bool(ov["api_key"] and len(ov["api_key"]) > 20)
    from_ok = bool(ov["from"] and EMAIL_RE.match(ov["from"]))
    to_ok   = bool(ov["to"]   and EMAIL_RE.match(ov["to"]))
    # subject not strictly required (we can supply default)
    return key_ok and from_ok and to_ok

def _effective_mail_cfg(channel: str) -> Dict[str, str]:
    """
# If channel overrides are present AND valid (key/from/to), return ONLY overrides (subject fallback allowed).
Otherwise, construct a mixed config that uses any provided overrides and falls back to globals per field.
    """
    ch = channel.strip().lower()
    default_subject = "New Veritas Support Ticket" if ch == "support" else (SENDGRID_SUBJECT or "New Veritas Feedback")
    ov = _channel_overrides(ch)

    if _overrides_are_complete_and_valid(ov, default_subject):
        return {
            "api_key": ov["api_key"],
            "from":    ov["from"],
            "to":      ov["to"],
            "subject": ov["subject"] or default_subject,
            "source":  "overrides-only"
        }

    # Partial overrides or none → fall back per field to globals
    return {
        "api_key": ov["api_key"] or SENDGRID_API_KEY,
        "from":    ov["from"]    or SENDGRID_FROM,
        "to":      ov["to"]      or SENDGRID_TO,
        "subject": (ov["subject"] or ( "New Veritas Support Ticket" if ch == "support" else (SENDGRID_SUBJECT or "New Veritas Feedback") )),
        "source":  "mixed-or-global"
    }

def _email_is_configured(channel: str) -> bool:
    cfg = _effective_mail_cfg(channel)
    key_ok = bool(cfg["api_key"] and len(cfg["api_key"]) > 20)
    from_ok = bool(cfg["from"] and EMAIL_RE.match(cfg["from"]))
    to_ok   = bool(cfg["to"]   and EMAIL_RE.match(cfg["to"]))
    return key_ok and from_ok and to_ok

def _mask_email(addr: str) -> str:
    try:
        left, right = addr.split("@", 1)
        left_m = (left[0] + "*"*(max(0,len(left)-2)) + left[-1]) if len(left) > 2 else left[0] + "*"
        dom, *rest = right.split(".")
        dom_m = (dom[0] + "*"*(max(0,len(dom)-2)) + dom[-1]) if len(dom) > 2 else dom[0] + "*"
        tail = ".".join(rest) if rest else ""
        return f"{left_m}@{dom_m}{('.' + tail) if tail else ''}"
    except Exception:
        return "********"

def _email_status(channel: str):
    cfg = _effective_mail_cfg(channel)
    if _email_is_configured(channel):
        st.success(
            f"Email is enabled for {channel} ({cfg['source']}). "
            f"FROM={_mask_email(cfg['from'])} → TO={_mask_email(cfg['to'])}"
        )
    else:
        missing = []
        if not (cfg["api_key"] and len(cfg["api_key"]) > 20): missing.append("API_KEY")
        if not (cfg["from"] and EMAIL_RE.match(cfg["from"])): missing.append("FROM")
        if not (cfg["to"]   and EMAIL_RE.match(cfg["to"])):   missing.append("TO")
        st.warning(
            f"Email delivery is NOT configured for {channel} ({cfg['source']}). "
            + ("Missing/invalid: " + ", ".join(missing) if missing else "Unknown error") + "."
        )

# Password gate
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# Lockout config
LOCKOUT_THRESHOLD      = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC     = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC   = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800"))

# Storage / branding
BASE_DIR      = os.path.dirname(__file__)
STATIC_DIR    = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(STATIC_DIR, "uploads")
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

ALLOWED_EXTENSIONS     = {"png", "jpg", "jpeg", "webp"}
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}
BG_ALLOWED_EXTENSIONS  = {"svg", "png", "jpg", "jpeg", "webp"}

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
_init_csv(SUPPORT_CSV,  ["timestamp_utc","timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"] if False else ["timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"])
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

# ===== Identity + Veritas Prompts (EXACT as provided) =====
IDENTITY_PROMPT = "I'm Veritas — a bias detection tool."

DEFAULT_SYSTEM_PROMPT = """
You are a language and bias detection expert trained to analyze academic documents for both subtle and overt bias. Your role is to review the provided academic content — including written language and any accompanying charts, graphs, or images — to identify elements that may be exclusionary, biased, or create barriers for individuals from underrepresented or marginalized groups.
In addition, you must provide contextual definitions and framework awareness to improve user literacy and reduce false positives.
Your task is strictly limited to bias detection and related analysis. Do not generate unrelated content, perform tasks outside this scope, or deviate from the role of a bias detection system. Always remain focused on identifying, explaining, and suggesting revisions for potential bias in the text or visuals provided. 
  ...
""".strip()

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
        "Then **output ONLY** using this exact template (10 numbered sections, same headings, same order). "
        "Do not add any intro/outro or backticks. "
        "If no bias is present, set ‘1. Bias Detected: No’ and ‘2. Bias Score: 🟢 No Bias | Score: 0.00’. "
        "For sections 3, 4, and 9 in that case, write ‘(none)’. "
        "Include section 10 even when no bias is present.\n\n"
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

def _safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")

# ---- Global rate limiter ----
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
        try:
            ts = datetime.now(timezone.utc).isoformat()
            _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                     (ts, _gen_error_id(), st.session_state.get("request_id",""), key, "RATE_LIMIT", 429,
                      f"limit={limit}/{window_sec}s", _get_sid(), st.session_state.get("login_id",""), "streamlit", "streamlit"))
        except Exception:
            pass
    # The call should still be blocked when exceeding limit
        return False
    dq.append(now)
    return True

# ---- CSV/DB logging helpers ----
def log_error_event(kind: str, route: str, http_status: int, detail: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        eid = _gen_error_id()
        rid = st.session_state.get("request_id") or _gen_request_id()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        safe_detail = (detail or "")[:500]
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua])
        _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                 (ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua))
        return eid
    except Exception:
        return None

def log_analysis(public_id: str, internal_id: str, assistant_text: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        conv_obj = {"assistant_reply": assistant_text}
        conv_json = json.dumps(conv_obj, ensure_ascii=False)
        conv_chars = len(conv_json)
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json])
        _db_exec("""INSERT INTO analyses (timestamp_utc,public_report_id,internal_report_id,session_id,login_id,remote_addr,user_agent,conversation_chars,conversation_json)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                 (ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json))
    except Exception:
        pass

def log_auth_event(event_type: str, success: bool, login_id: str = "", credential_label: str = "APP_PASSWORD", attempted_secret: Optional[str] = None):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        tid = _gen_tracking_id()
        addr = "streamlit"; ua = "streamlit"
        hashed_prefix = ""
        if attempted_secret and not success:
            hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8")).hexdigest()[:12]
        row = [ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, success, hashed_prefix, addr, ua]
        with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        _db_exec("""INSERT INTO auth_events (timestamp_utc,event_type,login_id,session_id,tracking_id,credential_label,success,hashed_attempt_prefix,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                 (ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, 1 if success else 0, hashed_prefix, addr, ua))
        st.session_state["last_tracking_id"] = tid
        return tid
    except Exception:
        return None

def log_ack_event(acknowledged: bool):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        row = [ts, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL, addr, ua]
        with open(ACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        _db_exec("""INSERT INTO ack_events (timestamp_utc,session_id,login_id,acknowledged,privacy_url,terms_url,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?)""",
                 (ts, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL, addr, ua))
    except Exception:
        pass

# ---- Pruning helpers ----
def _prune_csv_by_ttl(path: str, ttl_days: int):
    try:
        if ttl_days <= 0 or not os.path.exists(path):
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)
        with open(path, "r", encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        if not rows: return
        header, data = rows[0], rows[1:]
        kept = []
        for row in data:
            try:
                ts = datetime.fromisoformat(row[0])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                kept.append(row); continue
            if ts >= cutoff:
                kept.append(row)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(header); w.writerows(kept)
    except Exception:
        pass

def _prune_db_by_ttl(table: str, ts_col: str, ttl_days: int):
    try:
        if ttl_days <= 0: return
        cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff,))
        con.commit(); con.close()
    except Exception:
        pass

def _wipe_db_table(table: str):
    try:
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute(f"DELETE FROM {table}")
        con.commit(); con.close()
    except Exception:
        pass

# Boot-time pruning
_prune_csv_by_ttl(AUTH_CSV, AUTH_LOG_TTL_DAYS)
_prune_csv_by_ttl(ANALYSES_CSV, ANALYSES_LOG_TTL_DAYS)
_prune_csv_by_ttl(FEEDBACK_CSV, FEEDBACK_LOG_TTL_DAYS)
_prune_csv_by_ttl(ERRORS_CSV, ERRORS_LOG_TTL_DAYS)
_prune_csv_by_ttl(SUPPORT_CSV, SUPPORT_LOG_TTL_DAYS)
_prune_csv_by_ttl(ACK_CSV, ACK_TTL_DAYS)

# ====== Global CSS ======
PRIMARY = "#FF8C32"
ACCENT = "#E97C25"
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] {{ font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
.block-container {{ padding-top: 2.75rem !important; padding-bottom: 64px !important; }}

/* Buttons */
div.stButton > button, .stDownloadButton button, .stForm [type="submit"],
[data-testid="stFileUploader"] section div div span button,
button[kind="primary"], button[kind="secondary"],
[data-testid="baseButton-secondary"], [data-testid="baseButton-primary"] {{
  background-color: {PRIMARY} !important; color: #111418 !important;
  border: 1px solid {PRIMARY} !important; border-radius: .75rem !important;
  box-shadow: none !important; padding: 0.60rem 1rem !important;
  font-size: 0.95rem !important; font-weight: 500 !important;
}}
.stForm button[type="submit"],
.stForm [data-testid="baseButton-primary"],
.stForm [data-testid="baseButton-secondary"] {{
  white-space: nowrap !important; word-break: normal !important; overflow: visible !important;
  width: auto !important; min-width: 180px !important; height: auto !important;
  display: inline-flex !important; align-items: center !important; justify-content: center !important;
}}
.v-card {{ background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px; padding: 18px; }}
#analyze-card h3 {{ margin: 0 0 .5rem !important; }}
#analyze-card [data-testid="stTextArea"] label,
#analyze-card [data-testid="stFileUploader"] label {{ margin-top: 0 !important; }}
.v-actions {{ display: inline-flex; gap: 1.0rem; align-items: center;
  padding: .45rem .75rem; border-radius: 10px; background: rgba(0,0,0,0.65); }}
.v-actions a {{ color: #fff !important; text-decoration: none; font-weight: 600; }}
.v-actions a:hover {{ text-decoration: underline; }}
.v-actions .copy-note {{ color:#fff; opacity:.8; font-size:.85rem; }}
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
            mime = {"svg":"image/svg+xml","png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","webp":"image/webp"}.get(ext, "application/octet-stream")
            b64 = base64.b64encode(p.read_bytes()).decode("ascii")
            st.markdown(f"""
            <style>
            .stApp {{
                background: url("data:{mime};base64,{b64}") no-repeat center center fixed;
                background-size: cover;
            }}
            </style>
            """, unsafe_allow_html=True)
        elif BG_URL:
            safe_url = BG_URL.replace('"','%22')
            st.markdown(f"""
            <style>
            .stApp {{
                background: url("{safe_url}") no-repeat center center fixed;
                background-size: cover;
            }}
            </style>
            """, unsafe_allow_html=True)
    except Exception:
        pass

_inject_bg()

# =========== Header ===========
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
    st.session_state["request_id"] = _gen_request_id()
st.session_state.setdefault("authed", False)
st.session_state.setdefault("history", [])
st.session_state.setdefault("last_reply", "")
st.session_state.setdefault("user_input_box", "")
st.session_state.setdefault("_clear_text_box", False)
st.session_state.setdefault("_fail_times", deque())
st.session_state.setdefault("_locked_until", 0.0)
st.session_state.setdefault("is_admin", False)
st.session_state.setdefault("ack_ok", False)
# NEW: counter to force-reset the file_uploader on “New Analysis”
st.session_state.setdefault("doc_uploader_key", 0)
# NEW: store which login view is selected on pre-login screen
st.session_state.setdefault("auth_view", "user")  # 'user' or 'admin'

# Pilot countdown gate
if not pilot_started():
    st.info("Pilot hasn’t started yet.")
    if PILOT_START_UTC:
        now = datetime.now(timezone.utc)
        remaining = PILOT_START_UTC - now
        secs = int(max(0, remaining.total_seconds()))
        dd = secs // 86400; hh = (secs % 86400) // 3600; mm = (secs % 3600) // 60; ss = secs % 60
        local_str = PILOT_START_UTC.astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
        st.write(f"Opens on **{local_str}** · Countdown: **{dd}d {hh:02}:{mm:02}:{ss:02}**")
        st.stop()

def _is_locked() -> bool:
    return time.time() < st.session_state["_locked_until"]

def _note_failed_login(attempted_secret: str = ""):
    now = time.time()
    dq = st.session_state["_fail_times"]
    cutoff = now - LOCKOUT_WINDOW_SEC
    while dq and dq[0] < cutoff: dq.popleft()
    dq.append(now)
    log_auth_event("login_failed", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD", attempted_secret=attempted_secret)
    if len(dq) >= LOCKOUT_THRESHOLD:
        st.session_state["_locked_until"] = now + LOCKOUT_DURATION_SEC
        log_auth_event("login_lockout", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD")

# ====== Pre-login screen (User vs Admin) ======
def show_login():
    st.subheader("Sign In")

    # Choose which login you want to perform.
    auth_choice = st.radio(
        "",
        options=["User", "Admin"],
        index=(0 if st.session_state.get("auth_view", "user") == "user" else 1),
        horizontal=True,
        label_visibility="collapsed"  # <— hides the empty label cleanly
    )
    st.session_state["auth_view"] = "admin" if auth_choice == "Admin" else "user"

    if st.session_state["auth_view"] == "user":
        # ---- Normal User Login ----
        with st.form("login_form_user"):
            login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id", ""))
            pwd = st.text_input("Password", type="password")
           # unpack all 4 columns, even if you don’t use the last two explicitly
            c1, c2, _gap, _spacer = st.columns([2, 2, 1, 5])
            with c1:
                submit = st.form_submit_button("Enter")
            with c2:
                cancel = st.form_submit_button("Cancel")
        if cancel:
            st.stop()

        if submit:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60); secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("network error"); st.stop()
            if pwd == APP_PASSWORD:
                st.session_state["authed"] = True
                st.session_state["is_admin"] = False  # regular user
                st.session_state["login_id"] = (login_id or "").strip()
                st.session_state["_fail_times"].clear()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=st.session_state["login_id"], credential_label="APP_PASSWORD")
                st.success("Logged in.")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=pwd)
                st.error("Incorrect password")

    else:
        # ---- Admin Login (separate) ----
        if not ADMIN_PASSWORD:
            st.warning("Admin access is not configured on this instance.")
            st.stop()

        with st.form("login_form_admin"):
            admin_email = st.text_input("Admin Email", value=os.environ.get("ADMIN_PREFILL_EMAIL", ""))
            admin_pwd = st.text_input("Admin Password", type="password")
            a1, a2, _gap, _spacer = st.columns([2, 2, 1, 5])
            with a1:
                submit_admin = st.form_submit_button("Login")
            with a2:
                cancel_admin = st.form_submit_button("Cancel")
        if cancel_admin:
            st.session_state["auth_view"] = "user"
            _safe_rerun()

        if submit_admin:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60); secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("network error"); st.stop()

            # Validate admin credentials (optional email allow-list)
            if (not ADMIN_EMAIL_ALLOWED or (admin_email.strip().lower() == ADMIN_EMAIL_ALLOWED.lower())) and (admin_pwd == ADMIN_PASSWORD):
                st.session_state["authed"] = True
                st.session_state["is_admin"] = True
                st.session_state["login_id"] = admin_email.strip()
                st.session_state["_fail_times"].clear()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=st.session_state["login_id"], credential_label="ADMIN_PASSWORD")
                st.success("Admin access granted.")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=admin_pwd)
                st.error("Invalid admin credentials.")

# Require login if password is set; else auto-enter as user
if not st.session_state["authed"] and APP_PASSWORD:
    show_login(); st.stop()
elif not APP_PASSWORD:
    _sid = _get_sid()
    if "login_id" not in st.session_state:
        st.session_state["login_id"] = ""
    log_auth_event("login_success", True, login_id="", credential_label="NO_PASSWORD")
    st.session_state["authed"] = True
    # remains non-admin unless separately logged in via admin view (not shown when APP_PASSWORD is empty)

# ====== Sidebar ======
with st.sidebar:
    st.markdown(f"<h2 style='margin:.25rem 0 .75rem 0;'>{APP_TITLE}</h2>", unsafe_allow_html=True)
    if st.button("Logout"):
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label="APP_PASSWORD")
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box",
                  "_fail_times","_locked_until","show_support","is_admin","ack_ok","auth_view"):
            st.session_state.pop(k, None)
        _safe_rerun()

# ====== Acknowledgment Gate (post-login) ======
def _has_valid_ack(login_id: str, sid: str) -> bool:
    try:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=ACK_TTL_DAYS)
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute("""SELECT timestamp_utc FROM ack_events
                       WHERE acknowledged=1 AND (login_id=? OR session_id=?)
                       ORDER BY id DESC LIMIT 1""", (login_id or "", sid))
        row = cur.fetchone(); con.close()
        if not row: return False
        ts = datetime.fromisoformat(row[0])
        if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
        return ts >= cutoff_dt
    except Exception:
        return False

def require_acknowledgment():
    if st.session_state.get("ack_ok", False): return
    sid = _get_sid()
    login_id = st.session_state.get("login_id","")
    if _has_valid_ack(login_id, sid):
        st.session_state["ack_ok"] = True
        return

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
        if submitted:
            if not (c1 and c2):
                st.error("Please check both boxes to continue."); st.stop()
            log_ack_event(True)
            st.session_state["ack_ok"] = True
            st.success("Thanks! You may continue."); _safe_rerun()

    st.stop()

# Require acknowledgment after login — skip for admin sessions
if not st.session_state.get("is_admin", False):
    require_acknowledgment()

# ================= Tabs =================
tab_names = ["🔍 Analyze", "💬 Feedback", "🛟 Support", "❓ Help"]
# Only reveal Admin tab if authenticated as admin
if st.session_state.get("is_admin", False):
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
            key=f"doc_uploader_{st.session_state['doc_uploader_key']}"  # NEW: dynamic key so we can reset on New Analysis
        )

        bcol1, bcol2, _spacer = st.columns([2,2,6])
        with bcol1:
            submitted = st.form_submit_button("Analyze")
        with bcol2:
            new_analysis = st.form_submit_button("New Analysis")

    # NEW: safer reset handler for New Analysis
    if 'new_analysis' in locals() and new_analysis:
        # Do not write directly to the text-area's key here. Use the clear flag, which is honored above.
        st.session_state["_clear_text_box"] = True
        st.session_state["last_reply"] = ""
        st.session_state["history"] = []
        # Force the file_uploader to remount with a fresh key (clears the selected file)
        st.session_state["doc_uploader_key"] += 1
        _safe_rerun()

    if 'submitted' in locals() and submitted:
        if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
            st.error("network error"); st.stop()

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
                with st.spinner("Extracting document…"):
                    def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
                        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                        if ext == "pdf":
                            if PdfReader is None: return ""
                            reader = PdfReader(io.BytesIO(file_bytes))
                            parts = []
                            for page in reader.pages:
                                try: parts.append(page.extract_text() or "")
                                except Exception: continue
                            return "\n\n".join(parts)[:MAX_EXTRACT_CHARS]
                        elif ext == "docx":
                            if docx is None: return ""
                            buf = io.BytesIO(file_bytes)
                            doc_obj = docx.Document(buf)
                            text = "\n".join(p.text for p in doc_obj.paragraphs)
                            return text[:MAX_EXTRACT_CHARS]
                        elif ext in ("txt","md","csv"):
                            def _safe_decode(b: bytes) -> str:
                                for enc in ("utf-8","utf-16","latin-1"):
                                    try: return b.decode(enc)
                                    except Exception: continue
                                return b.decode("utf-8", errors="ignore")
                            return _safe_decode(file_bytes)[:MAX_EXTRACT_CHARS]
                        return ""
                    extracted = (extract_text_from_file(doc.getvalue(), doc.name) or "").strip()
            except Exception as e:
                log_error_event(kind="EXTRACT", route="/extract", http_status=500, detail=repr(e))
                st.error("network error"); st.stop()

        final_input = (user_text + ("\n\n" + extracted if extracted else "")).strip()
        if not final_input:
            st.error("Please enter some text or upload a document."); st.stop()

        # --- OpenAI call ---
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
            log_error_event(kind="OPENAI", route="/chat", http_status=502, detail=repr(e))
            st.error("Could not contact the language model. Check API key/model."); st.stop()

        public_report_id = _gen_public_report_id()
        internal_report_id = _gen_internal_report_id()
        decorated_reply = f"📄 Report ID: {public_report_id}\n\n{model_reply}".strip()

        st.session_state["history"].append({"role":"assistant","content":decorated_reply})
        st.session_state["last_reply"] = decorated_reply
        try: log_analysis(public_report_id, internal_report_id, decorated_reply)
        except Exception: pass

        st.session_state["_clear_text_box"] = True
        try: prog.progress(100, text="Done ✓")
        except Exception: prog.progress(100)
        _safe_rerun()

    # Show latest report (if any)
    if st.session_state.get("last_reply"):
        st.write("### Bias Report")
        st.markdown(st.session_state["last_reply"])

        def _build_pdf_inline(content: str) -> bytes:
            if SimpleDocTemplate is None:
                return content.encode("utf-8")
            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf, pagesize=letter,
                leftMargin=0.8*inch, rightMargin=0.8*inch,
                topMargin=0.9*inch, bottomMargin=0.9*inch
            )
            styles = getSampleStyleSheet()
            base = styles["Normal"]; base.leading = 14; base.fontName = "Helvetica"
            body = ParagraphStyle("Body", parent=base, fontSize=10)
            h = ParagraphStyle("H", parent=base, fontSize=12, spaceAfter=8, leading=14)
            story = []
            title = APP_TITLE + " — Bias Analysis Report"
            ts = datetime.now().astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
            story.append(Paragraph(f"<b>{title}</b>", h))
            story.append(Paragraph(f"<i>Generated {ts}</i>", base))
            story.append(Spacer(1, 10))
            for p in [p.strip() for p in content.split("\n\n") if p.strip()]:
                safe = p.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(safe, body)); story.append(Spacer(1, 6))
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
    try {{
      await navigator.clipboard.writeText(text_{uid});
      note_{uid}.style.display = "inline";
      setTimeout(() => note_{uid}.style.display = "none", 1200);
    }} catch (e) {{
      const ta = document.createElement("textarea");
      ta.value = text_{uid}; ta.style.position="fixed"; ta.style.opacity="0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      try {{ document.execCommand("copy"); }} catch (_e) {{}}
      ta.remove(); note_{uid}.style.display = "inline";
      setTimeout(() => note_{uid}.style.display = "none", 1200);
    }}
  }});
</script>
""", height=64)

    st.markdown('</div>', unsafe_allow_html=True)

# -------------------- Feedback Tab --------------------
with tabs[1]:
    st.write("### Feedback")
    _email_status("feedback")

    with st.form("feedback_form"):
        rating = st.slider("Your rating", min_value=1, max_value=5, value=5)
        email = st.text_input("Email (required)")
        comments = st.text_area("Comments (what worked / what didn’t)", height=120, max_chars=2000)
        submit_fb = st.form_submit_button("Submit feedback")
    if submit_fb:
        EMAIL_RE_LOCAL = EMAIL_RE
        if not email or not EMAIL_RE_LOCAL.match(email):
            st.error("Please enter a valid email."); st.stop()
        lines = []
        for m in st.session_state["history"]:
            if m["role"] == "assistant":
                lines.append("Assistant: " + m["content"])
        transcript = "\n\n".join(lines)[:100000]
        conv_chars = len(transcript)
        ts_now = datetime.now(timezone.utc).isoformat()
        # CSV
        try:
            with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts_now, rating, email[:200], (comments or "").replace("\r", " ").strip(), conv_chars, transcript, "streamlit", "streamlit"])
        except Exception as e:
            log_error_event(kind="FEEDBACK", route="/feedback", http_status=500, detail=repr(e))
            st.error("network error"); st.stop()
        # DB
        try:
            _db_exec("""INSERT INTO feedback (timestamp_utc,rating,email,comments,conversation_chars,conversation,remote_addr,ua)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (ts_now, rating, email[:200], (comments or "").replace("\r", " ").strip(), conv_chars, transcript, "streamlit", "streamlit"))
        except Exception:
            pass
        # Email
        fb_cfg = _effective_mail_cfg("feedback")
        if not _email_is_configured("feedback"):
            st.warning("Feedback saved locally; email delivery is not configured for Feedback.")
        else:
            try:
                conv_preview = transcript[:2000]
                plain = (
                    f"New Veritas feedback\nTime (UTC): {ts_now}\nRating: {rating}/5\n"
                    f"From user email: {email}\nComments:\n{comments}\n\n"
                    f"--- Report (first 2,000 chars) ---\n{conv_preview}\n\n"
                    f"IP: streamlit\nUser-Agent: streamlit\n"
                )
                html_body = (
                    f"<h3>New Veritas feedback</h3>"
                    f"<p><strong>Time (UTC):</strong> {ts_now}</p>"
                    f"<p><strong>Rating:</strong> {rating}/5</p>"
                    f"<p><strong>From user email:</strong> {email}</p>"
                    f"<p><strong>Comments:</strong><br>{(comments or '').replace(chr(10), '<br>')}</p>"
                    f"<hr><p><strong>Report (first 2,000 chars):</strong><br>"
                    f"<pre style='white-space:pre-wrap'>{conv_preview}</pre></p>"
                    f"<hr><p><strong>IP:</strong> streamlit<br><strong>User-Agent:</strong> streamlit</p>"
                )
                payload = {
                    "personalizations": [{"to": [{"email": fb_cfg["to"]}]}],
                    "from": {"email": fb_cfg["from"], "name": "Veritas"},
                    "subject": fb_cfg["subject"] or "New Veritas Feedback",
                    "content": [{"type": "text/plain", "value": plain}, {"type": "text/html", "value": html_body}],
                }
                with httpx.Client(timeout=12) as client:
                    r = client.post(
                        "https://api.sendgrid.com/v3/mail/send",
                        headers={"Authorization": f"Bearer {fb_cfg['api_key']}", "Content-Type": "application/json"},
                        json=payload,
                    )
                if r.status_code not in (200, 202):
                    st.error("Feedback saved but email failed to send.")
                else:
                    st.success("Thanks — feedback saved and emailed ✓")
            except Exception:
                st.error("Feedback saved but email failed to send.")

# -------------------- Support Tab --------------------
with tabs[2]:
    st.write("### Support")
    _email_status("support")

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
    if cancel_support:
        _safe_rerun()
    if submit_support:
        if not full_name.strip():
            st.error("Please enter your full name.")
        elif not email_sup.strip():
            st.error("Please enter your email.")
        elif not issue_text.strip():
            st.error("Please describe the issue.")
        else:
            ticket_id = _gen_ticket_id()
            ts = datetime.now(timezone.utc).isoformat()
            sid = st.session_state.get("sid") or _get_sid()
            login_id = st.session_state.get("login_id", "")
            ua = "streamlit"
            try:
                with open(SUPPORT_CSV, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([ts, ticket_id, full_name.strip(), email_sup.strip(),
                                            bias_report_id.strip(), issue_text.strip(), sid, login_id, ua])
            except Exception as e:
                log_error_event(kind="SUPPORT_WRITE", route="/support", http_status=500, detail=repr(e))
                st.error("We couldn't save your ticket. Please try again.")
            else:
                try:
                    _db_exec("""INSERT INTO support_tickets (timestamp_utc,ticket_id,full_name,email,bias_report_id,issue,session_id,login_id,user_agent)
                                VALUES (?,?,?,?,?,?,?,?,?)""",
                             (ts, ticket_id, full_name.strip(), email_sup.strip(), bias_report_id.strip(), issue_text.strip(), sid, login_id, ua))
                except Exception:
                    pass

                sup_cfg = _effective_mail_cfg("support")
                if _email_is_configured("support"):
                    try:
                        subject = sup_cfg["subject"] or f"[Veritas Support] Ticket {ticket_id}"
                        plain = (
                            f"New Support Ticket\n"
                            f"Ticket ID: {ticket_id}\n"
                            f"Time (UTC): {ts}\n"
                            f"From: {full_name} <{email_sup}>\n"
                            f"Bias Report ID: {bias_report_id}\n\n"
                            f"Issue:\n{issue_text}\n\n"
                            f"Session: {sid}\nLogin: {login_id}\n"
                        )
                        html_body = (
                            f"<h3>New Veritas Support Ticket</h3>"
                            f"<p><strong>Ticket ID:</strong> {ticket_id}</p>"
                            f"<p><strong>Time (UTC):</strong> {ts}</p>"
                            f"<p><strong>From:</strong> {full_name} &lt;{email_sup}&gt;</p>"
                            f"<p><strong>Bias Report ID:</strong> {bias_report_id or '(none)'}"
                            f"<p><strong>Issue:</strong><br><pre style='white-space:pre-wrap'>{issue_text}</pre></p>"
                            f"<hr><p><strong>Session:</strong> {sid}<br><strong>Login:</strong> {login_id}</p>"
                        )
                        payload = {
                            "personalizations": [{"to": [{"email": sup_cfg["to"]}]}],
                            "from": {"email": sup_cfg["from"], "name": "Veritas"},
                            "subject": subject,
                            "content": [{"type": "text/plain", "value": plain}, {"type": "text/html", "value": html_body}],
                        }
                        with httpx.Client(timeout=12) as client:
                            r = client.post(
                                "https://api.sendgrid.com/v3/mail/send",
                                headers={"Authorization": f"Bearer {sup_cfg['api_key']}", "Content-Type": "application/json"},
                                json=payload
                            )
                        if r.status_code not in (200, 202):
                            st.warning("Ticket saved; email notification failed.")
                    except Exception:
                        st.warning("Ticket saved; email notification failed.")
                else:
                    st.warning("Ticket saved locally; email delivery is not configured for Support.")

                st.success(f"Thanks! Your support ticket has been submitted. **Ticket ID: {ticket_id}**")
                _safe_rerun()

# -------------------- Help Tab --------------------
with tabs[3]:
    st.write("### Help")
    st.markdown(
        """
- Paste text or upload a document, then click **Analyze**.
- After the report appears, use the action links (**Copy** / **Download**).
- Use the **Feedback** tab to rate your experience and share comments.
- Use the **Support** tab to submit any issues; include the Report ID if applicable.
- Each login, you must acknowledge **Privacy Policy & Terms of Use**.
        """
    )

# -------------------- Admin Tab (only for authenticated admins) --------------------
if st.session_state.get("is_admin", False):
    with tabs[-1]:
        st.write("### Admin")

        if st.button("Exit Admin"):
            st.session_state["is_admin"] = False
            _safe_rerun()

        sub1, sub2, sub3, sub4 = st.tabs(["🕘 History", "📂 Data Explorer", "🧹 Maintenance", "🎨 Branding"])

        # ---- History
        with sub1:
            st.write("#### Previous Reports")
            q = st.text_input("Search by Report ID or text (local DB)", placeholder="e.g., VER-2025… or a phrase…")
            try:
                con = sqlite3.connect(DB_PATH)
                df = pd.read_sql_query("SELECT timestamp_utc, public_report_id, internal_report_id, conversation_json FROM analyses ORDER BY id DESC LIMIT 1000", con)
                con.close()
            except Exception:
                df = pd.DataFrame(columns=["timestamp_utc","public_report_id","internal_report_id","conversation_json"])
            if not df.empty:
                def extract_preview(js: str) -> str:
                    try:
                        return json.loads(js).get("assistant_reply","")[:220]
                    except Exception:
                        return ""
                df["preview"] = df["conversation_json"].apply(extract_preview)
                if q.strip():
                    ql = q.lower()
                    df = df[df.apply(lambda r: (ql in str(r["public_report_id"]).lower()) or (ql in str(r["preview"]).lower()), axis=1)]
                st.dataframe(df[["timestamp_utc","public_report_id","internal_report_id","preview"]], use_container_width=True, hide_index=True)
                sel = st.text_input("Load a report back into the viewer by Report ID (optional)")
                if st.button("Load Report"):
                    row = df[df["public_report_id"] == sel]
                    if len(row) == 1:
                        try:
                            txt = json.loads(row.iloc[0]["conversation_json"]).get("assistant_reply","")
                            st.session_state["last_reply"] = txt
                            st.success("Loaded into Analyze tab.")
                        except Exception:
                            st.error("Could not load that report.")
                    else:
                        st.warning("Report ID not found in the current list.")
            else:
                st.info("No reports yet.")

        # ---- Data Explorer
        with sub2:
            st.write("#### Data Explorer")
            st.caption("Browse app data stored on this instance. Use the download buttons for backups.")

            def _read_csv_safe(path: str) -> pd.DataFrame:
                try:
                    return pd.read_csv(path)
                except Exception:
                    return pd.DataFrame()

            c1, c2 = st.columns(2)
            with c1:
                st.write("##### Auth Events")
                st.dataframe(_read_csv_safe(AUTH_CSV), use_container_width=True)
                try:
                    st.download_button("Download auth_events.csv", data=open(AUTH_CSV, "rb").read(), file_name="auth_events.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Errors")
                st.dataframe(_read_csv_safe(ERRORS_CSV), use_container_width=True)
                try:
                    st.download_button("Download errors.csv", data=open(ERRORS_CSV, "rb").read(), file_name="errors.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Acknowledgments")
                st.dataframe(_read_csv_safe(ACK_CSV), use_container_width=True)
                try:
                    st.download_button("Download ack_events.csv", data=open(ACK_CSV, "rb").read(), file_name="ack_events.csv", mime="text/csv")
                except Exception:
                    pass
            with c2:
                st.write("##### Analyses")
                st.dataframe(_read_csv_safe(ANALYSES_CSV), use_container_width=True)
                try:
                    st.download_button("Download analyses.csv", data=open(ANALYSES_CSV, "rb").read(), file_name="analyses.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Feedback")
                st.dataframe(_read_csv_safe(FEEDBACK_CSV), use_container_width=True)
                try:
                    st.download_button("Download feedback.csv", data=open(FEEDBACK_CSV, "rb").read(), file_name="feedback.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Support Tickets")
                st.dataframe(_read_csv_safe(SUPPORT_CSV), use_container_width=True)
                try:
                    st.download_button("Download support_tickets.csv", data=open(SUPPORT_CSV, "rb").read(), file_name="support_tickets.csv", mime="text/csv")
                except Exception:
                    pass

        # ---- Maintenance
        with sub3:
            st.write("#### Prune & Wipe Data")
            st.caption("Prune removes rows older than the TTL. Wipe deletes ALL rows in a dataset. Use with care.")

            st.write("**Prune by TTL (days)**")
            cpa, cpb, cpc = st.columns(3)
            with cpa:
                ttl_auth = st.number_input("Auth Events TTL",   min_value=0, value=max(0, AUTH_LOG_TTL_DAYS),     step=1)
                ttl_err  = st.number_input("Errors TTL",        min_value=0, value=max(0, ERRORS_LOG_TTL_DAYS),  step=1)
                ttl_ack  = st.number_input("Ack Events TTL",    min_value=0, value=max(0, ACK_TTL_DAYS),         step=1)
            with cpb:
                ttl_ana  = st.number_input("Analyses TTL",      min_value=0, value=max(0, ANALYSES_LOG_TTL_DAYS),step=1)
                ttl_fb   = st.number_input("Feedback TTL",      min_value=0, value=max(0, FEEDBACK_LOG_TTL_DAYS),step=1)
                ttl_sup  = st.number_input("Support TTL",       min_value=0, value=max(0, SUPPORT_LOG_TTL_DAYS), step=1)
            with cpc:
                st.markdown("&nbsp;")
                if st.button("Run Prune Now (CSV + DB)"):
                    _prune_csv_by_ttl(AUTH_CSV, ttl_auth);    _prune_db_by_ttl("auth_events", "timestamp_utc", ttl_auth)
                    _prune_csv_by_ttl(ERRORS_CSV, ttl_err);   _prune_db_by_ttl("errors", "timestamp_utc", ttl_err)
                    _prune_csv_by_ttl(ACK_CSV, ttl_ack);      _prune_db_by_ttl("ack_events", "timestamp_utc", ttl_ack)
                    _prune_csv_by_ttl(ANALYSES_CSV, ttl_ana); _prune_db_by_ttl("analyses", "timestamp_utc", ttl_ana)
                    _prune_csv_by_ttl(FEEDBACK_CSV, ttl_fb);  _prune_db_by_ttl("feedback", "timestamp_utc", ttl_fb)
                    _prune_csv_by_ttl(SUPPORT_CSV, ttl_sup);  _prune_db_by_ttl("support_tickets", "timestamp_utc", ttl_sup)
                    st.success("Prune complete.")

            st.write("---")
            st.write("**Wipe Dataset (dangerous)**")
            target = st.selectbox("Choose dataset to wipe", [
                "auth_events", "errors", "ack_events", "analyses", "feedback", "support_tickets"
            ])
            confirm = st.text_input("Type PURGE to confirm")
            if st.button("Wipe Selected Dataset"):
                if confirm.strip().upper() == "PURGE":
                    _wipe_db_table(target)
                    csv_map = {
                        "auth_events": AUTH_CSV, "errors": ERRORS_CSV, "ack_events": ACK_CSV,
                        "analyses": ANALYSES_CSV, "feedback": FEEDBACK_CSV, "support_tickets": SUPPORT_CSV
                    }
                    path = csv_map.get(target)
                    if path and os.path.exists(path):
                        hdr = []
                        try:
                            with open(path, "r", encoding="utf-8", newline="") as f:
                                rdr = csv.reader(f); hdr = next(rdr, [])
                        except Exception:
                            pass
                        with open(path, "w", encoding="utf-8", newline="") as f:
                            if hdr:
                                csv.writer(f).writerow(hdr)
                    st.success(f"Wiped: {target}")
                else:
                    st.error("Confirmation failed. Type PURGE to proceed.")

        # ---- Branding
        with sub4:
            st.write("#### Branding: Background Image")
            current_bg = _find_local_bg_file()
            if current_bg:
                st.success(f"Current local background: `{current_bg.name}` in `/static`.")
            elif BG_URL:
                st.info(f"Using BG_URL: {BG_URL}")
            else:
                st.warning("No background set. Add one below or configure BG_URL in secrets.")

            up = st.file_uploader("Upload a background (SVG/PNG/JPG/WEBP)", type=list(BG_ALLOWED_EXTENSIONS))
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Save Background"):
                    if up is None:
                        st.error("Choose a file first.")
                    else:
                        ext = up.name.rsplit(".", 1)[-1].lower() if "." in up.name else ""
                        if ext not in BG_ALLOWED_EXTENSIONS:
                            st.error("Unsupported file type.")
                        else:
                            for p in Path(STATIC_DIR).glob("bg.*"):
                                try: p.unlink()
                                except Exception: pass
                            out = Path(STATIC_DIR) / f"bg.{ext}"
                            out.write_bytes(up.getvalue())
                            st.success(f"Saved background to `static/{out.name}`.")
                            _safe_rerun()
            with c2:
                if st.button("Remove Background"):
                    removed = False
                    for p in Path(STATIC_DIR).glob("bg.*"):
                        try:
                            p.unlink(); removed = True
                        except Exception:
                            pass
                    if removed:
                        st.success("Background removed.")
                        _safe_rerun()
                    else:
                        st.info("No local background to remove.")
            st.caption("Tip: To use an external image, set a `BG_URL` secret (e.g., a GitHub RAW link).")

# ====== Footer ======
st.markdown(
    "<div id='vFooter'>Copyright 2025 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True
)









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
        "Then **output ONLY** using this exact template (10 numbered sections, same headings, same order). "
        "Do not add any intro/outro or backticks. "
        "If no bias is present, set ‘1. Bias Detected: No’ and ‘2. Bias Score: 🟢 No Bias | Score: 0.00’. "
        "For sections 3, 4, and 9 in that case, write ‘(none)’. "
        "Include section 10 even when no bias is present.\n\n"
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

def _safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")

# ---- Global rate limiter ----
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
        try:
            ts = datetime.now(timezone.utc).isoformat()
            _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                     (ts, _gen_error_id(), st.session_state.get("request_id",""), key, "RATE_LIMIT", 429,
                      f"limit={limit}/{window_sec}s", _get_sid(), st.session_state.get("login_id",""), "streamlit", "streamlit"))
        except Exception:
            pass
    # The call should still be blocked when exceeding limit
        return False
    dq.append(now)
    return True

# ---- CSV/DB logging helpers ----
def log_error_event(kind: str, route: str, http_status: int, detail: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        eid = _gen_error_id()
        rid = st.session_state.get("request_id") or _gen_request_id()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        safe_detail = (detail or "")[:500]
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua])
        _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                 (ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua))
        return eid
    except Exception:
        return None

def log_analysis(public_id: str, internal_id: str, assistant_text: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        conv_obj = {"assistant_reply": assistant_text}
        conv_json = json.dumps(conv_obj, ensure_ascii=False)
        conv_chars = len(conv_json)
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json])
        _db_exec("""INSERT INTO analyses (timestamp_utc,public_report_id,internal_report_id,session_id,login_id,remote_addr,user_agent,conversation_chars,conversation_json)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                 (ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json))
    except Exception:
        pass

def log_auth_event(event_type: str, success: bool, login_id: str = "", credential_label: str = "APP_PASSWORD", attempted_secret: Optional[str] = None):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        tid = _gen_tracking_id()
        addr = "streamlit"; ua = "streamlit"
        hashed_prefix = ""
        if attempted_secret and not success:
            hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8")).hexdigest()[:12]
        row = [ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, success, hashed_prefix, addr, ua]
        with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        _db_exec("""INSERT INTO auth_events (timestamp_utc,event_type,login_id,session_id,tracking_id,credential_label,success,hashed_attempt_prefix,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?)""",
                 (ts, event_type, (login_id or "").strip()[:120], sid, tid, credential_label, 1 if success else 0, hashed_prefix, addr, ua))
        st.session_state["last_tracking_id"] = tid
        return tid
    except Exception:
        return None

def log_ack_event(acknowledged: bool):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_sid()
        login_id = st.session_state.get("login_id", "")
        addr = "streamlit"; ua = "streamlit"
        row = [ts, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL, addr, ua]
        with open(ACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        _db_exec("""INSERT INTO ack_events (timestamp_utc,session_id,login_id,acknowledged,privacy_url,terms_url,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?)""",
                 (ts, sid, login_id, 1 if acknowledged else 0, PRIVACY_URL, TERMS_URL, addr, ua))
    except Exception:
        pass

# ---- Pruning helpers ----
def _prune_csv_by_ttl(path: str, ttl_days: int):
    try:
        if ttl_days <= 0 or not os.path.exists(path):
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)
        with open(path, "r", encoding="utf-8", newline="") as f:
            rows = list(csv.reader(f))
        if not rows: return
        header, data = rows[0], rows[1:]
        kept = []
        for row in data:
            try:
                ts = datetime.fromisoformat(row[0])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                kept.append(row); continue
            if ts >= cutoff:
                kept.append(row)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(header); w.writerows(kept)
    except Exception:
        pass

def _prune_db_by_ttl(table: str, ts_col: str, ttl_days: int):
    try:
        if ttl_days <= 0: return
        cutoff = (datetime.now(timezone.utc) - timedelta(days=ttl_days)).isoformat()
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute(f"DELETE FROM {table} WHERE {ts_col} < ?", (cutoff,))
        con.commit(); con.close()
    except Exception:
        pass

def _wipe_db_table(table: str):
    try:
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute(f"DELETE FROM {table}")
        con.commit(); con.close()
    except Exception:
        pass

# Boot-time pruning
_prune_csv_by_ttl(AUTH_CSV, AUTH_LOG_TTL_DAYS)
_prune_csv_by_ttl(ANALYSES_CSV, ANALYSES_LOG_TTL_DAYS)
_prune_csv_by_ttl(FEEDBACK_CSV, FEEDBACK_LOG_TTL_DAYS)
_prune_csv_by_ttl(ERRORS_CSV, ERRORS_LOG_TTL_DAYS)
_prune_csv_by_ttl(SUPPORT_CSV, SUPPORT_LOG_TTL_DAYS)
_prune_csv_by_ttl(ACK_CSV, ACK_TTL_DAYS)

# ====== Global CSS ======
PRIMARY = "#FF8C32"
ACCENT = "#E97C25"
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] {{ font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
.block-container {{ padding-top: 2.75rem !important; padding-bottom: 64px !important; }}

/* Buttons */
div.stButton > button, .stDownloadButton button, .stForm [type="submit"],
[data-testid="stFileUploader"] section div div span button,
button[kind="primary"], button[kind="secondary"],
[data-testid="baseButton-secondary"], [data-testid="baseButton-primary"] {{
  background-color: {PRIMARY} !important; color: #111418 !important;
  border: 1px solid {PRIMARY} !important; border-radius: .75rem !important;
  box-shadow: none !important; padding: 0.60rem 1rem !important;
  font-size: 0.95rem !important; font-weight: 500 !important;
}}
.stForm button[type="submit"],
.stForm [data-testid="baseButton-primary"],
.stForm [data-testid="baseButton-secondary"] {{
  white-space: nowrap !important; word-break: normal !important; overflow: visible !important;
  width: auto !important; min-width: 180px !important; height: auto !important;
  display: inline-flex !important; align-items: center !important; justify-content: center !important;
}}
.v-card {{ background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08);
  border-radius: 16px; padding: 18px; }}
#analyze-card h3 {{ margin: 0 0 .5rem !important; }}
#analyze-card [data-testid="stTextArea"] label,
#analyze-card [data-testid="stFileUploader"] label {{ margin-top: 0 !important; }}
.v-actions {{ display: inline-flex; gap: 1.0rem; align-items: center;
  padding: .45rem .75rem; border-radius: 10px; background: rgba(0,0,0,0.65); }}
.v-actions a {{ color: #fff !important; text-decoration: none; font-weight: 600; }}
.v-actions a:hover {{ text-decoration: underline; }}
.v-actions .copy-note {{ color:#fff; opacity:.8; font-size:.85rem; }}
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
            mime = {"svg":"image/svg+xml","png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","webp":"image/webp"}.get(ext, "application/octet-stream")
            b64 = base64.b64encode(p.read_bytes()).decode("ascii")
            st.markdown(f"""
            <style>
            .stApp {{
                background: url("data:{mime};base64,{b64}") no-repeat center center fixed;
                background-size: cover;
            }}
            </style>
            """, unsafe_allow_html=True)
        elif BG_URL:
            safe_url = BG_URL.replace('"','%22')
            st.markdown(f"""
            <style>
            .stApp {{
                background: url("{safe_url}") no-repeat center center fixed;
                background-size: cover;
            }}
            </style>
            """, unsafe_allow_html=True)
    except Exception:
        pass

_inject_bg()

# =========== Header ===========
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
    st.session_state["request_id"] = _gen_request_id()
st.session_state.setdefault("authed", False)
st.session_state.setdefault("history", [])
st.session_state.setdefault("last_reply", "")
st.session_state.setdefault("user_input_box", "")
st.session_state.setdefault("_clear_text_box", False)
st.session_state.setdefault("_fail_times", deque())
st.session_state.setdefault("_locked_until", 0.0)
st.session_state.setdefault("is_admin", False)
st.session_state.setdefault("ack_ok", False)
# NEW: counter to force-reset the file_uploader on “New Analysis”
st.session_state.setdefault("doc_uploader_key", 0)
# NEW: store which login view is selected on pre-login screen
st.session_state.setdefault("auth_view", "user")  # 'user' or 'admin'

# Pilot countdown gate
if not pilot_started():
    st.info("Pilot hasn’t started yet.")
    if PILOT_START_UTC:
        now = datetime.now(timezone.utc)
        remaining = PILOT_START_UTC - now
        secs = int(max(0, remaining.total_seconds()))
        dd = secs // 86400; hh = (secs % 86400) // 3600; mm = (secs % 3600) // 60; ss = secs % 60
        local_str = PILOT_START_UTC.astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
        st.write(f"Opens on **{local_str}** · Countdown: **{dd}d {hh:02}:{mm:02}:{ss:02}**")
        st.stop()

def _is_locked() -> bool:
    return time.time() < st.session_state["_locked_until"]

def _note_failed_login(attempted_secret: str = ""):
    now = time.time()
    dq = st.session_state["_fail_times"]
    cutoff = now - LOCKOUT_WINDOW_SEC
    while dq and dq[0] < cutoff: dq.popleft()
    dq.append(now)
    log_auth_event("login_failed", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD", attempted_secret=attempted_secret)
    if len(dq) >= LOCKOUT_THRESHOLD:
        st.session_state["_locked_until"] = now + LOCKOUT_DURATION_SEC
        log_auth_event("login_lockout", False, login_id=(st.session_state.get("login_id","") or ""), credential_label="APP_PASSWORD")

# ====== Pre-login screen (User vs Admin) ======
def show_login():
    st.subheader("Sign In")

    # Choose which login you want to perform.
    auth_choice = st.radio(
        "",
        options=["User", "Admin"],
        index=(0 if st.session_state.get("auth_view", "user") == "user" else 1),
        horizontal=True,
        label_visibility="collapsed"  # <— hides the empty label cleanly
    )
    st.session_state["auth_view"] = "admin" if auth_choice == "Admin" else "user"

    if st.session_state["auth_view"] == "user":
        # ---- Normal User Login ----
        with st.form("login_form_user"):
            login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id", ""))
            pwd = st.text_input("Password", type="password")
           # unpack all 4 columns, even if you don’t use the last two explicitly
            c1, c2, _gap, _spacer = st.columns([2, 2, 1, 5])
            with c1:
                submit = st.form_submit_button("Enter")
            with c2:
                cancel = st.form_submit_button("Cancel")
        if cancel:
            st.stop()

        if submit:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60); secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("network error"); st.stop()
            if pwd == APP_PASSWORD:
                st.session_state["authed"] = True
                st.session_state["is_admin"] = False  # regular user
                st.session_state["login_id"] = (login_id or "").strip()
                st.session_state["_fail_times"].clear()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=st.session_state["login_id"], credential_label="APP_PASSWORD")
                st.success("Logged in.")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=pwd)
                st.error("Incorrect password")

    else:
        # ---- Admin Login (separate) ----
        if not ADMIN_PASSWORD:
            st.warning("Admin access is not configured on this instance.")
            st.stop()

        with st.form("login_form_admin"):
            admin_email = st.text_input("Admin Email", value=os.environ.get("ADMIN_PREFILL_EMAIL", ""))
            admin_pwd = st.text_input("Admin Password", type="password")
            a1, a2, _gap, _spacer = st.columns([2, 2, 1, 5])
            with a1:
                submit_admin = st.form_submit_button("Login")
            with a2:
                cancel_admin = st.form_submit_button("Cancel")
        if cancel_admin:
            st.session_state["auth_view"] = "user"
            _safe_rerun()

        if submit_admin:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60); secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("network error"); st.stop()

            # Validate admin credentials (optional email allow-list)
            if (not ADMIN_EMAIL_ALLOWED or (admin_email.strip().lower() == ADMIN_EMAIL_ALLOWED.lower())) and (admin_pwd == ADMIN_PASSWORD):
                st.session_state["authed"] = True
                st.session_state["is_admin"] = True
                st.session_state["login_id"] = admin_email.strip()
                st.session_state["_fail_times"].clear()
                st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, login_id=st.session_state["login_id"], credential_label="ADMIN_PASSWORD")
                st.success("Admin access granted.")
                _safe_rerun()
            else:
                _note_failed_login(attempted_secret=admin_pwd)
                st.error("Invalid admin credentials.")

# Require login if password is set; else auto-enter as user
if not st.session_state["authed"] and APP_PASSWORD:
    show_login(); st.stop()
elif not APP_PASSWORD:
    _sid = _get_sid()
    if "login_id" not in st.session_state:
        st.session_state["login_id"] = ""
    log_auth_event("login_success", True, login_id="", credential_label="NO_PASSWORD")
    st.session_state["authed"] = True
    # remains non-admin unless separately logged in via admin view (not shown when APP_PASSWORD is empty)

# ====== Sidebar ======
with st.sidebar:
    st.markdown(f"<h2 style='margin:.25rem 0 .75rem 0;'>{APP_TITLE}</h2>", unsafe_allow_html=True)
    if st.button("Logout"):
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label="APP_PASSWORD")
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box",
                  "_fail_times","_locked_until","show_support","is_admin","ack_ok","auth_view"):
            st.session_state.pop(k, None)
        _safe_rerun()

# ====== Acknowledgment Gate (post-login) ======
def _has_valid_ack(login_id: str, sid: str) -> bool:
    try:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=ACK_TTL_DAYS)
        con = sqlite3.connect(DB_PATH); cur = con.cursor()
        cur.execute("""SELECT timestamp_utc FROM ack_events
                       WHERE acknowledged=1 AND (login_id=? OR session_id=?)
                       ORDER BY id DESC LIMIT 1""", (login_id or "", sid))
        row = cur.fetchone(); con.close()
        if not row: return False
        ts = datetime.fromisoformat(row[0])
        if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
        return ts >= cutoff_dt
    except Exception:
        return False

def require_acknowledgment():
    if st.session_state.get("ack_ok", False): return
    sid = _get_sid()
    login_id = st.session_state.get("login_id","")
    if _has_valid_ack(login_id, sid):
        st.session_state["ack_ok"] = True
        return

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
        if submitted:
            if not (c1 and c2):
                st.error("Please check both boxes to continue."); st.stop()
            log_ack_event(True)
            st.session_state["ack_ok"] = True
            st.success("Thanks! You may continue."); _safe_rerun()

    st.stop()

# Require acknowledgment after login — skip for admin sessions
if not st.session_state.get("is_admin", False):
    require_acknowledgment()

# ================= Tabs =================
tab_names = ["🔍 Analyze", "💬 Feedback", "🛟 Support", "❓ Help"]
# Only reveal Admin tab if authenticated as admin
if st.session_state.get("is_admin", False):
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
            key=f"doc_uploader_{st.session_state['doc_uploader_key']}"  # NEW: dynamic key so we can reset on New Analysis
        )

        bcol1, bcol2, _spacer = st.columns([2,2,6])
        with bcol1:
            submitted = st.form_submit_button("Analyze")
        with bcol2:
            new_analysis = st.form_submit_button("New Analysis")

    # NEW: safer reset handler for New Analysis
    if 'new_analysis' in locals() and new_analysis:
        # Do not write directly to the text-area's key here. Use the clear flag, which is honored above.
        st.session_state["_clear_text_box"] = True
        st.session_state["last_reply"] = ""
        st.session_state["history"] = []
        # Force the file_uploader to remount with a fresh key (clears the selected file)
        st.session_state["doc_uploader_key"] += 1
        _safe_rerun()

    if 'submitted' in locals() and submitted:
        if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
            st.error("network error"); st.stop()

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
                with st.spinner("Extracting document…"):
                    def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
                        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                        if ext == "pdf":
                            if PdfReader is None: return ""
                            reader = PdfReader(io.BytesIO(file_bytes))
                            parts = []
                            for page in reader.pages:
                                try: parts.append(page.extract_text() or "")
                                except Exception: continue
                            return "\n\n".join(parts)[:MAX_EXTRACT_CHARS]
                        elif ext == "docx":
                            if docx is None: return ""
                            buf = io.BytesIO(file_bytes)
                            doc_obj = docx.Document(buf)
                            text = "\n".join(p.text for p in doc_obj.paragraphs)
                            return text[:MAX_EXTRACT_CHARS]
                        elif ext in ("txt","md","csv"):
                            def _safe_decode(b: bytes) -> str:
                                for enc in ("utf-8","utf-16","latin-1"):
                                    try: return b.decode(enc)
                                    except Exception: continue
                                return b.decode("utf-8", errors="ignore")
                            return _safe_decode(file_bytes)[:MAX_EXTRACT_CHARS]
                        return ""
                    extracted = (extract_text_from_file(doc.getvalue(), doc.name) or "").strip()
            except Exception as e:
                log_error_event(kind="EXTRACT", route="/extract", http_status=500, detail=repr(e))
                st.error("network error"); st.stop()

        final_input = (user_text + ("\n\n" + extracted if extracted else "")).strip()
        if not final_input:
            st.error("Please enter some text or upload a document."); st.stop()

        # --- OpenAI call ---
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
            log_error_event(kind="OPENAI", route="/chat", http_status=502, detail=repr(e))
            st.error("Could not contact the language model. Check API key/model."); st.stop()

        public_report_id = _gen_public_report_id()
        internal_report_id = _gen_internal_report_id()
        decorated_reply = f"📄 Report ID: {public_report_id}\n\n{model_reply}".strip()

        st.session_state["history"].append({"role":"assistant","content":decorated_reply})
        st.session_state["last_reply"] = decorated_reply
        try: log_analysis(public_report_id, internal_report_id, decorated_reply)
        except Exception: pass

        st.session_state["_clear_text_box"] = True
        try: prog.progress(100, text="Done ✓")
        except Exception: prog.progress(100)
        _safe_rerun()

    # Show latest report (if any)
    if st.session_state.get("last_reply"):
        st.write("### Bias Report")
        st.markdown(st.session_state["last_reply"])

        def _build_pdf_inline(content: str) -> bytes:
            if SimpleDocTemplate is None:
                return content.encode("utf-8")
            buf = io.BytesIO()
            doc = SimpleDocTemplate(
                buf, pagesize=letter,
                leftMargin=0.8*inch, rightMargin=0.8*inch,
                topMargin=0.9*inch, bottomMargin=0.9*inch
            )
            styles = getSampleStyleSheet()
            base = styles["Normal"]; base.leading = 14; base.fontName = "Helvetica"
            body = ParagraphStyle("Body", parent=base, fontSize=10)
            h = ParagraphStyle("H", parent=base, fontSize=12, spaceAfter=8, leading=14)
            story = []
            title = APP_TITLE + " — Bias Analysis Report"
            ts = datetime.now().astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
            story.append(Paragraph(f"<b>{title}</b>", h))
            story.append(Paragraph(f"<i>Generated {ts}</i>", base))
            story.append(Spacer(1, 10))
            for p in [p.strip() for p in content.split("\n\n") if p.strip()]:
                safe = p.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                story.append(Paragraph(safe, body)); story.append(Spacer(1, 6))
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
    try {{
      await navigator.clipboard.writeText(text_{uid});
      note_{uid}.style.display = "inline";
      setTimeout(() => note_{uid}.style.display = "none", 1200);
    }} catch (e) {{
      const ta = document.createElement("textarea");
      ta.value = text_{uid}; ta.style.position="fixed"; ta.style.opacity="0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      try {{ document.execCommand("copy"); }} catch (_e) {{}}
      ta.remove(); note_{uid}.style.display = "inline";
      setTimeout(() => note_{uid}.style.display = "none", 1200);
    }}
  }});
</script>
""", height=64)

    st.markdown('</div>', unsafe_allow_html=True)

# -------------------- Feedback Tab --------------------
with tabs[1]:
    st.write("### Feedback")
    _email_status("feedback")

    with st.form("feedback_form"):
        rating = st.slider("Your rating", min_value=1, max_value=5, value=5)
        email = st.text_input("Email (required)")
        comments = st.text_area("Comments (what worked / what didn’t)", height=120, max_chars=2000)
        submit_fb = st.form_submit_button("Submit feedback")
    if submit_fb:
        EMAIL_RE_LOCAL = EMAIL_RE
        if not email or not EMAIL_RE_LOCAL.match(email):
            st.error("Please enter a valid email."); st.stop()
        lines = []
        for m in st.session_state["history"]:
            if m["role"] == "assistant":
                lines.append("Assistant: " + m["content"])
        transcript = "\n\n".join(lines)[:100000]
        conv_chars = len(transcript)
        ts_now = datetime.now(timezone.utc).isoformat()
        # CSV
        try:
            with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts_now, rating, email[:200], (comments or "").replace("\r", " ").strip(), conv_chars, transcript, "streamlit", "streamlit"])
        except Exception as e:
            log_error_event(kind="FEEDBACK", route="/feedback", http_status=500, detail=repr(e))
            st.error("network error"); st.stop()
        # DB
        try:
            _db_exec("""INSERT INTO feedback (timestamp_utc,rating,email,comments,conversation_chars,conversation,remote_addr,ua)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (ts_now, rating, email[:200], (comments or "").replace("\r", " ").strip(), conv_chars, transcript, "streamlit", "streamlit"))
        except Exception:
            pass
        # Email
        fb_cfg = _effective_mail_cfg("feedback")
        if not _email_is_configured("feedback"):
            st.warning("Feedback saved locally; email delivery is not configured for Feedback.")
        else:
            try:
                conv_preview = transcript[:2000]
                plain = (
                    f"New Veritas feedback\nTime (UTC): {ts_now}\nRating: {rating}/5\n"
                    f"From user email: {email}\nComments:\n{comments}\n\n"
                    f"--- Report (first 2,000 chars) ---\n{conv_preview}\n\n"
                    f"IP: streamlit\nUser-Agent: streamlit\n"
                )
                html_body = (
                    f"<h3>New Veritas feedback</h3>"
                    f"<p><strong>Time (UTC):</strong> {ts_now}</p>"
                    f"<p><strong>Rating:</strong> {rating}/5</p>"
                    f"<p><strong>From user email:</strong> {email}</p>"
                    f"<p><strong>Comments:</strong><br>{(comments or '').replace(chr(10), '<br>')}</p>"
                    f"<hr><p><strong>Report (first 2,000 chars):</strong><br>"
                    f"<pre style='white-space:pre-wrap'>{conv_preview}</pre></p>"
                    f"<hr><p><strong>IP:</strong> streamlit<br><strong>User-Agent:</strong> streamlit</p>"
                )
                payload = {
                    "personalizations": [{"to": [{"email": fb_cfg["to"]}]}],
                    "from": {"email": fb_cfg["from"], "name": "Veritas"},
                    "subject": fb_cfg["subject"] or "New Veritas Feedback",
                    "content": [{"type": "text/plain", "value": plain}, {"type": "text/html", "value": html_body}],
                }
                with httpx.Client(timeout=12) as client:
                    r = client.post(
                        "https://api.sendgrid.com/v3/mail/send",
                        headers={"Authorization": f"Bearer {fb_cfg['api_key']}", "Content-Type": "application/json"},
                        json=payload,
                    )
                if r.status_code not in (200, 202):
                    st.error("Feedback saved but email failed to send.")
                else:
                    st.success("Thanks — feedback saved and emailed ✓")
            except Exception:
                st.error("Feedback saved but email failed to send.")

# -------------------- Support Tab --------------------
with tabs[2]:
    st.write("### Support")
    _email_status("support")

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
    if cancel_support:
        _safe_rerun()
    if submit_support:
        if not full_name.strip():
            st.error("Please enter your full name.")
        elif not email_sup.strip():
            st.error("Please enter your email.")
        elif not issue_text.strip():
            st.error("Please describe the issue.")
        else:
            ticket_id = _gen_ticket_id()
            ts = datetime.now(timezone.utc).isoformat()
            sid = st.session_state.get("sid") or _get_sid()
            login_id = st.session_state.get("login_id", "")
            ua = "streamlit"
            try:
                with open(SUPPORT_CSV, "a", newline="", encoding="utf-8") as f:
                    csv.writer(f).writerow([ts, ticket_id, full_name.strip(), email_sup.strip(),
                                            bias_report_id.strip(), issue_text.strip(), sid, login_id, ua])
            except Exception as e:
                log_error_event(kind="SUPPORT_WRITE", route="/support", http_status=500, detail=repr(e))
                st.error("We couldn't save your ticket. Please try again.")
            else:
                try:
                    _db_exec("""INSERT INTO support_tickets (timestamp_utc,ticket_id,full_name,email,bias_report_id,issue,session_id,login_id,user_agent)
                                VALUES (?,?,?,?,?,?,?,?,?)""",
                             (ts, ticket_id, full_name.strip(), email_sup.strip(), bias_report_id.strip(), issue_text.strip(), sid, login_id, ua))
                except Exception:
                    pass

                sup_cfg = _effective_mail_cfg("support")
                if _email_is_configured("support"):
                    try:
                        subject = sup_cfg["subject"] or f"[Veritas Support] Ticket {ticket_id}"
                        plain = (
                            f"New Support Ticket\n"
                            f"Ticket ID: {ticket_id}\n"
                            f"Time (UTC): {ts}\n"
                            f"From: {full_name} <{email_sup}>\n"
                            f"Bias Report ID: {bias_report_id}\n\n"
                            f"Issue:\n{issue_text}\n\n"
                            f"Session: {sid}\nLogin: {login_id}\n"
                        )
                        html_body = (
                            f"<h3>New Veritas Support Ticket</h3>"
                            f"<p><strong>Ticket ID:</strong> {ticket_id}</p>"
                            f"<p><strong>Time (UTC):</strong> {ts}</p>"
                            f"<p><strong>From:</strong> {full_name} &lt;{email_sup}&gt;</p>"
                            f"<p><strong>Bias Report ID:</strong> {bias_report_id or '(none)'}"
                            f"<p><strong>Issue:</strong><br><pre style='white-space:pre-wrap'>{issue_text}</pre></p>"
                            f"<hr><p><strong>Session:</strong> {sid}<br><strong>Login:</strong> {login_id}</p>"
                        )
                        payload = {
                            "personalizations": [{"to": [{"email": sup_cfg["to"]}]}],
                            "from": {"email": sup_cfg["from"], "name": "Veritas"},
                            "subject": subject,
                            "content": [{"type": "text/plain", "value": plain}, {"type": "text/html", "value": html_body}],
                        }
                        with httpx.Client(timeout=12) as client:
                            r = client.post(
                                "https://api.sendgrid.com/v3/mail/send",
                                headers={"Authorization": f"Bearer {sup_cfg['api_key']}", "Content-Type": "application/json"},
                                json=payload
                            )
                        if r.status_code not in (200, 202):
                            st.warning("Ticket saved; email notification failed.")
                    except Exception:
                        st.warning("Ticket saved; email notification failed.")
                else:
                    st.warning("Ticket saved locally; email delivery is not configured for Support.")

                st.success(f"Thanks! Your support ticket has been submitted. **Ticket ID: {ticket_id}**")
                _safe_rerun()

# -------------------- Help Tab --------------------
with tabs[3]:
    st.write("### Help")
    st.markdown(
        """
- Paste text or upload a document, then click **Analyze**.
- After the report appears, use the action links (**Copy** / **Download**).
- Use the **Feedback** tab to rate your experience and share comments.
- Use the **Support** tab to submit any issues; include the Report ID if applicable.
- Each login, you must acknowledge **Privacy Policy & Terms of Use**.
        """
    )

# -------------------- Admin Tab (only for authenticated admins) --------------------
if st.session_state.get("is_admin", False):
    with tabs[-1]:
        st.write("### Admin")

        if st.button("Exit Admin"):
            st.session_state["is_admin"] = False
            _safe_rerun()

        sub1, sub2, sub3, sub4 = st.tabs(["🕘 History", "📂 Data Explorer", "🧹 Maintenance", "🎨 Branding"])

        # ---- History
        with sub1:
            st.write("#### Previous Reports")
            q = st.text_input("Search by Report ID or text (local DB)", placeholder="e.g., VER-2025… or a phrase…")
            try:
                con = sqlite3.connect(DB_PATH)
                df = pd.read_sql_query("SELECT timestamp_utc, public_report_id, internal_report_id, conversation_json FROM analyses ORDER BY id DESC LIMIT 1000", con)
                con.close()
            except Exception:
                df = pd.DataFrame(columns=["timestamp_utc","public_report_id","internal_report_id","conversation_json"])
            if not df.empty:
                def extract_preview(js: str) -> str:
                    try:
                        return json.loads(js).get("assistant_reply","")[:220]
                    except Exception:
                        return ""
                df["preview"] = df["conversation_json"].apply(extract_preview)
                if q.strip():
                    ql = q.lower()
                    df = df[df.apply(lambda r: (ql in str(r["public_report_id"]).lower()) or (ql in str(r["preview"]).lower()), axis=1)]
                st.dataframe(df[["timestamp_utc","public_report_id","internal_report_id","preview"]], use_container_width=True, hide_index=True)
                sel = st.text_input("Load a report back into the viewer by Report ID (optional)")
                if st.button("Load Report"):
                    row = df[df["public_report_id"] == sel]
                    if len(row) == 1:
                        try:
                            txt = json.loads(row.iloc[0]["conversation_json"]).get("assistant_reply","")
                            st.session_state["last_reply"] = txt
                            st.success("Loaded into Analyze tab.")
                        except Exception:
                            st.error("Could not load that report.")
                    else:
                        st.warning("Report ID not found in the current list.")
            else:
                st.info("No reports yet.")

        # ---- Data Explorer
        with sub2:
            st.write("#### Data Explorer")
            st.caption("Browse app data stored on this instance. Use the download buttons for backups.")

            def _read_csv_safe(path: str) -> pd.DataFrame:
                try:
                    return pd.read_csv(path)
                except Exception:
                    return pd.DataFrame()

            c1, c2 = st.columns(2)
            with c1:
                st.write("##### Auth Events")
                st.dataframe(_read_csv_safe(AUTH_CSV), use_container_width=True)
                try:
                    st.download_button("Download auth_events.csv", data=open(AUTH_CSV, "rb").read(), file_name="auth_events.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Errors")
                st.dataframe(_read_csv_safe(ERRORS_CSV), use_container_width=True)
                try:
                    st.download_button("Download errors.csv", data=open(ERRORS_CSV, "rb").read(), file_name="errors.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Acknowledgments")
                st.dataframe(_read_csv_safe(ACK_CSV), use_container_width=True)
                try:
                    st.download_button("Download ack_events.csv", data=open(ACK_CSV, "rb").read(), file_name="ack_events.csv", mime="text/csv")
                except Exception:
                    pass
            with c2:
                st.write("##### Analyses")
                st.dataframe(_read_csv_safe(ANALYSES_CSV), use_container_width=True)
                try:
                    st.download_button("Download analyses.csv", data=open(ANALYSES_CSV, "rb").read(), file_name="analyses.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Feedback")
                st.dataframe(_read_csv_safe(FEEDBACK_CSV), use_container_width=True)
                try:
                    st.download_button("Download feedback.csv", data=open(FEEDBACK_CSV, "rb").read(), file_name="feedback.csv", mime="text/csv")
                except Exception:
                    pass

                st.write("##### Support Tickets")
                st.dataframe(_read_csv_safe(SUPPORT_CSV), use_container_width=True)
                try:
                    st.download_button("Download support_tickets.csv", data=open(SUPPORT_CSV, "rb").read(), file_name="support_tickets.csv", mime="text/csv")
                except Exception:
                    pass

        # ---- Maintenance
        with sub3:
            st.write("#### Prune & Wipe Data")
            st.caption("Prune removes rows older than the TTL. Wipe deletes ALL rows in a dataset. Use with care.")

            st.write("**Prune by TTL (days)**")
            cpa, cpb, cpc = st.columns(3)
            with cpa:
                ttl_auth = st.number_input("Auth Events TTL",   min_value=0, value=max(0, AUTH_LOG_TTL_DAYS),     step=1)
                ttl_err  = st.number_input("Errors TTL",        min_value=0, value=max(0, ERRORS_LOG_TTL_DAYS),  step=1)
                ttl_ack  = st.number_input("Ack Events TTL",    min_value=0, value=max(0, ACK_TTL_DAYS),         step=1)
            with cpb:
                ttl_ana  = st.number_input("Analyses TTL",      min_value=0, value=max(0, ANALYSES_LOG_TTL_DAYS),step=1)
                ttl_fb   = st.number_input("Feedback TTL",      min_value=0, value=max(0, FEEDBACK_LOG_TTL_DAYS),step=1)
                ttl_sup  = st.number_input("Support TTL",       min_value=0, value=max(0, SUPPORT_LOG_TTL_DAYS), step=1)
            with cpc:
                st.markdown("&nbsp;")
                if st.button("Run Prune Now (CSV + DB)"):
                    _prune_csv_by_ttl(AUTH_CSV, ttl_auth);    _prune_db_by_ttl("auth_events", "timestamp_utc", ttl_auth)
                    _prune_csv_by_ttl(ERRORS_CSV, ttl_err);   _prune_db_by_ttl("errors", "timestamp_utc", ttl_err)
                    _prune_csv_by_ttl(ACK_CSV, ttl_ack);      _prune_db_by_ttl("ack_events", "timestamp_utc", ttl_ack)
                    _prune_csv_by_ttl(ANALYSES_CSV, ttl_ana); _prune_db_by_ttl("analyses", "timestamp_utc", ttl_ana)
                    _prune_csv_by_ttl(FEEDBACK_CSV, ttl_fb);  _prune_db_by_ttl("feedback", "timestamp_utc", ttl_fb)
                    _prune_csv_by_ttl(SUPPORT_CSV, ttl_sup);  _prune_db_by_ttl("support_tickets", "timestamp_utc", ttl_sup)
                    st.success("Prune complete.")

            st.write("---")
            st.write("**Wipe Dataset (dangerous)**")
            target = st.selectbox("Choose dataset to wipe", [
                "auth_events", "errors", "ack_events", "analyses", "feedback", "support_tickets"
            ])
            confirm = st.text_input("Type PURGE to confirm")
            if st.button("Wipe Selected Dataset"):
                if confirm.strip().upper() == "PURGE":
                    _wipe_db_table(target)
                    csv_map = {
                        "auth_events": AUTH_CSV, "errors": ERRORS_CSV, "ack_events": ACK_CSV,
                        "analyses": ANALYSES_CSV, "feedback": FEEDBACK_CSV, "support_tickets": SUPPORT_CSV
                    }
                    path = csv_map.get(target)
                    if path and os.path.exists(path):
                        hdr = []
                        try:
                            with open(path, "r", encoding="utf-8", newline="") as f:
                                rdr = csv.reader(f); hdr = next(rdr, [])
                        except Exception:
                            pass
                        with open(path, "w", encoding="utf-8", newline="") as f:
                            if hdr:
                                csv.writer(f).writerow(hdr)
                    st.success(f"Wiped: {target}")
                else:
                    st.error("Confirmation failed. Type PURGE to proceed.")

        # ---- Branding
        with sub4:
            st.write("#### Branding: Background Image")
            current_bg = _find_local_bg_file()
            if current_bg:
                st.success(f"Current local background: `{current_bg.name}` in `/static`.")
            elif BG_URL:
                st.info(f"Using BG_URL: {BG_URL}")
            else:
                st.warning("No background set. Add one below or configure BG_URL in secrets.")

            up = st.file_uploader("Upload a background (SVG/PNG/JPG/WEBP)", type=list(BG_ALLOWED_EXTENSIONS))
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Save Background"):
                    if up is None:
                        st.error("Choose a file first.")
                    else:
                        ext = up.name.rsplit(".", 1)[-1].lower() if "." in up.name else ""
                        if ext not in BG_ALLOWED_EXTENSIONS:
                            st.error("Unsupported file type.")
                        else:
                            for p in Path(STATIC_DIR).glob("bg.*"):
                                try: p.unlink()
                                except Exception: pass
                            out = Path(STATIC_DIR) / f"bg.{ext}"
                            out.write_bytes(up.getvalue())
                            st.success(f"Saved background to `static/{out.name}`.")
                            _safe_rerun()
            with c2:
                if st.button("Remove Background"):
                    removed = False
                    for p in Path(STATIC_DIR).glob("bg.*"):
                        try:
                            p.unlink(); removed = True
                        except Exception:
                            pass
                    if removed:
                        st.success("Background removed.")
                        _safe_rerun()
                    else:
                        st.info("No local background to remove.")
            st.caption("Tip: To use an external image, set a `BG_URL` secret (e.g., a GitHub RAW link).")

# ====== Footer ======
st.markdown(
    "<div id='vFooter'>Copyright 2025 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True
)











