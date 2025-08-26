# streamlit_app.py  (updated)
import os
import io
import csv
import re
import time
import json
import hashlib
import secrets
from typing import Optional
from datetime import timedelta, datetime, timezone
from zoneinfo import ZoneInfo
from collections import deque

import streamlit as st
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
# NOTE: replace old `from config import Config, validate_config` usage
from config import load_settings

settings = load_settings()  # pulls OPENAI_API_KEY, OPENAI_MODEL, etc.

# ================= App constants from secrets/env (with safe defaults) =================
APP_TITLE = os.environ.get("APP_TITLE", "Veritas — Pilot Test")

MODEL = settings.openai_model
# temperature can be string in secrets; coerce to float with default
try:
    TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
except Exception:
    TEMPERATURE = 0.2

ADMIN_KEY = os.environ.get("BRAND_ADMIN_PASSWORD", "")

PILOT_TZ_NAME = os.environ.get("VERITAS_TZ", "America/Denver")
PILOT_TZ = ZoneInfo(PILOT_TZ_NAME)
PILOT_START_AT = os.environ.get("PILOT_START_AT", "")  # e.g., "2025-09-15 08:00" or ISO

# Rates / windows
RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT = int(os.environ.get("RATE_LIMIT_CHAT", "6"))
RATE_LIMIT_EXTRACT = int(os.environ.get("RATE_LIMIT_EXTRACT", "6"))
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RATE_LIMIT_WINDOW_SEC", "60"))

# Uploads
try:
    MAX_UPLOAD_MB = float(os.environ.get("MAX_UPLOAD_MB", "10"))
except Exception:
    MAX_UPLOAD_MB = 10.0

# TTLs (days)
AUTH_LOG_TTL_DAYS = int(os.environ.get("AUTH_LOG_TTL_DAYS", str(settings.auth_log_ttl_days)))
ANALYSES_LOG_TTL_DAYS = int(os.environ.get("ANALYSES_LOG_TTL_DAYS", "365"))
FEEDBACK_LOG_TTL_DAYS = int(os.environ.get("FEEDBACK_LOG_TTL_DAYS", "365"))
ERRORS_LOG_TTL_DAYS = int(os.environ.get("ERRORS_LOG_TTL_DAYS", "365"))

# SendGrid (optional)
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_TO = os.environ.get("SENDGRID_TO", "")
SENDGRID_FROM = os.environ.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT = os.environ.get("SENDGRID_SUBJECT", "New Veritas feedback")

# Password gate (optional)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

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

# Storage / branding
BASE_DIR = os.path.dirname(__file__)
STATIC_DIR = os.path.join(BASE_DIR, "static")
UPLOAD_FOLDER = os.path.join(STATIC_DIR, "uploads")  # logos only
DATA_DIR = os.path.join(BASE_DIR, "data")
FEEDBACK_CSV = os.path.join(DATA_DIR, "feedback.csv")
ERRORS_CSV = os.path.join(DATA_DIR, "errors.csv")
AUTH_CSV = os.path.join(DATA_DIR, "auth_events.csv")
ANALYSES_CSV = os.path.join(DATA_DIR, "analyses.csv")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}           # logo types
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}  # upload types
MAX_EXTRACT_CHARS = int(os.environ.get("MAX_EXTRACT_CHARS", "50000"))

# Initialize CSV headers if missing
if not os.path.exists(AUTH_CSV):
    with open(AUTH_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc",
            "event_type",            # login_success | login_failed | logout
            "login_id",              # optional user-supplied ID
            "session_id",
            "tracking_id",           # unique per event
            "credential_label",      # e.g., APP_PASSWORD or NO_PASSWORD
            "success",               # true/false
            "hashed_attempt_prefix", # first 12 chars sha256(attempt), only on failed
            "remote_addr",
            "user_agent"
        ])

if not os.path.exists(ANALYSES_CSV):
    with open(ANALYSES_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc",
            "public_report_id",      # user-visible (VER-...)
            "internal_report_id",    # AXIS internal (AX-...)
            "session_id",
            "login_id",
            "remote_addr",
            "user_agent",
            "conversation_chars",
            "conversation_json"
        ])

if not os.path.exists(FEEDBACK_CSV):
    with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc", "rating", "email", "comments",
            "conversation_chars", "conversation",
            "remote_addr", "ua"
        ])

if not os.path.exists(ERRORS_CSV):
    with open(ERRORS_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc",
            "error_id",
            "request_id",
            "route",
            "kind",
            "http_status",
            "detail",
            "session_id",
            "login_id",
            "remote_addr",
            "user_agent",
        ])

# Default tagline
CURRENT_TAGLINE = (os.environ.get("VERITAS_TAGLINE", "") or "").strip()

# Auto-detect existing logo
CURRENT_LOGO_FILENAME = None
if os.path.isdir(UPLOAD_FOLDER):
    for f in os.listdir(UPLOAD_FOLDER):
        name = f.lower()
        if name.startswith("logo.") and name.rsplit(".", 1)[-1] in ALLOWED_EXTENSIONS:
            CURRENT_LOGO_FILENAME = f
            break

# Startup marker
STARTED_AT_ISO = datetime.now(timezone.utc).isoformat()

# ================= Identity + Veritas Prompts =================
IDENTITY_PROMPT = """
You are Veritas — a bias detection tool. When the user asks your name or who you are,
introduce yourself plainly as: "I'm Veritas — a bias detection tool."
For greetings, capability questions, or other meta questions, respond briefly (1–2 sentences)
and do NOT produce the full bias-report template. Only produce the strict bias report when
the user provides text to analyze or clearly asks for an analysis.
Do not say "I am an AI language model" or similar.
""".strip()

DEFAULT_SYSTEM_PROMPT = """
You are a language and bias detection expert trained to analyze academic documents for both
subtle and overt bias. Review the following academic content — including written language and
any accompanying charts, graphs, or images — to identify elements that may be exclusionary,
biased, or create barriers for individuals from underrepresented or marginalized groups.
In addition, provide contextual definitions and framework awareness to improve user literacy
and reduce false positives.

Bias Categories (with academic context)
- Gendered language: Words or phrases that assume or privilege a specific gender identity (e.g., “chairman,” “he”).
- Academic elitism: Preference for specific institutions, journals, or credentials that may undervalue alternative but equally valid qualifications.
- Institutional framing (contextual): Identify when language frames institutions in biased ways. Do NOT generalize entire institutions; focus on specific contexts, departments, or phrasing that indicates exclusionary framing.
- Cultural or racial assumptions: Language or imagery that reinforces stereotypes or assumes shared cultural experiences. Only flag when context indicates stereotyping or exclusion — do not flag neutral academic descriptors.
- Age or career-stage bias: Terms that favor a particular age group or career stage without academic necessity (e.g., “young scholars”).
- Ableist or neurotypical assumptions: Language implying that only certain physical, mental, or cognitive abilities are valid for participation.
- Gatekeeping/exclusivity: Phrases that unnecessarily restrict eligibility or create prestige barriers.
- Family role, time availability, or economic assumptions: Language presuming certain domestic situations, financial status, or schedule flexibility.
- Visual bias: Charts/graphs or imagery that lack representation, use inaccessible colors, or reinforce stereotypes.

Bias Detection Rules
1. Context Check for Legal/Program/Framework Names: Do not flag factual names of laws, programs, religious texts, or courses unless context shows discriminatory or exclusionary framing.
2. Framework Awareness: If flagged bias appears in a legal, religious, or defined-framework text, explicitly note: “This operates within [Framework X]. Interpret accordingly.”
3. Multi-Pass Detection: After initial bias identification, re-check text for secondary or overlapping bias types. If multiple categories apply, bias score must reflect combined severity.
4. False Positive Reduction: Avoid flagging mild cultural references or neutral institutional references unless paired with exclusionary framing.
5. Terminology Neutralization: Always explain terms like bias, lens, perspective in context to avoid appearing accusatory. Frame as descriptive, not judgmental.
6. Objective vs. Subjective Distinction: Distinguish between objective truth claims and subjective statements.
7. Contextual Definition Layer: For each flagged term, provide contextual vs. general meaning.
8. Accurate Attribution Safeguard.
9. Legal/Compliance Neutrality Rule.

Strict thresholds and output format as specified previously.
""".strip()

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

def allowed_file(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_doc(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in DOC_ALLOWED_EXTENSIONS

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
        return "\n\n".join(parts)
    elif ext == "docx":
        if docx is None:
            return ""
        buf = io.BytesIO(file_bytes)
        doc_obj = docx.Document(buf)
        return "\n".join(p.text for p in doc_obj.paragraphs)
    elif ext in ("txt", "md", "csv"):
        return _safe_decode(file_bytes)
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
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua])
        # dev console
        print(f"[{ts}] ERROR {eid} (req {rid}) {route} {kind} {http_status} :: {safe_detail}")
        return eid
    except Exception as e:
        print("Error log failure:", repr(e))
        return None

def netw
