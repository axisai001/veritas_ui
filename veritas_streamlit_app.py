# main.py (self-contained)
import os
import csv
import re
import io
import time
import json
import hashlib
import secrets
from typing import Optional
from datetime import timedelta, datetime, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from collections import deque
import threading
from http import HTTPStatus

from flask import Flask, request, jsonify, Response, session, redirect, url_for, send_file, g
from werkzeug.utils import secure_filename
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

# ================= Inline Config (env-driven) =================
def _env_bool(name: str, default: str = "true") -> bool:
    return os.environ.get(name, default).strip().lower() == "true"

def _env_int(name: str, default: str) -> int:
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return int(default)

class Config:
    # App basics
    APP_TITLE = os.environ.get("APP_TITLE", "Veritas - Pilot Test")
    VERITAS_TZ = os.environ.get("VERITAS_TZ", "America/Denver")
    PILOT_START_AT = os.environ.get("PILOT_START_AT", "").strip()  # e.g. "2025-09-15 08:00"

    # Branding/admin
    BRAND_ADMIN_PASSWORD = os.environ.get("BRAND_ADMIN_PASSWORD")
    VERITAS_TAGLINE = os.environ.get("VERITAS_TAGLINE", "Designed for Empowerment, Not Influence").strip()

    # OpenAI
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    try:
        OPENAI_TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
    except Exception:
        OPENAI_TEMPERATURE = 0.2

    # Auth
    APP_PASSWORD = os.environ.get("APP_PASSWORD")  # if set, login is required

    # Security
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", "true")
    SESSION_COOKIE_HTTPONLY = _env_bool("SESSION_COOKIE_HTTPONLY", "true")
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    ENFORCE_HTTPS = _env_bool("ENFORCE_HTTPS", "false")  # set true behind TLS proxy

    # Uploads
    MAX_UPLOAD_MB = _env_int("MAX_UPLOAD_MB", "8")

    # Rate limiting
    RATE_LIMIT_WINDOW_SEC = _env_int("RATE_LIMIT_WINDOW_SEC", "60")
    RATE_LIMIT_LOGIN = _env_int("RATE_LIMIT_LOGIN", "10")      # 10/min/IP
    RATE_LIMIT_CHAT = _env_int("RATE_LIMIT_CHAT", "10")        # 10/min/IP
    RATE_LIMIT_EXTRACT = _env_int("RATE_LIMIT_EXTRACT", "10")  # 10/min/IP

    # SendGrid (optional)
    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    SENDGRID_TO = os.environ.get("SENDGRID_TO", "feedback@axislabs.ai")
    SENDGRID_FROM = os.environ.get("SENDGRID_FROM", "noreply@axislabs.ai")
    SENDGRID_SUBJECT = os.environ.get("SENDGRID_SUBJECT", "Veritas Pilot Feedback")

    # Log retention (days)
    AUTH_LOG_TTL_DAYS = _env_int("AUTH_LOG_TTL_DAYS", "365")
    ANALYSES_LOG_TTL_DAYS = _env_int("ANALYSES_LOG_TTL_DAYS", "365")
    FEEDBACK_LOG_TTL_DAYS = _env_int("FEEDBACK_LOG_TTL_DAYS", "365")
    ERRORS_LOG_TTL_DAYS = _env_int("ERRORS_LOG_TTL_DAYS", "365")

CFG = Config()

def validate_config():
    if CFG.SESSION_COOKIE_SAMESITE not in {"Lax", "Strict", "None"}:
        raise ValueError("SESSION_COOKIE_SAMESITE must be one of: Lax, Strict, None")
    # We allow OPENAI_API_KEY to be missing at boot; /chat will return a network error if so.

validate_config()

# ================= App constants from config =================
APP_TITLE = CFG.APP_TITLE
MODEL = CFG.OPENAI_MODEL
TEMPERATURE = CFG.OPENAI_TEMPERATURE

# Admin key for branding controls (hidden unlock)
ADMIN_KEY = CFG.BRAND_ADMIN_PASSWORD

# Pilot start (login countdown)
PILOT_TZ_NAME = CFG.VERITAS_TZ
PILOT_TZ = ZoneInfo(PILOT_TZ_NAME)
PILOT_START_AT = CFG.PILOT_START_AT  # e.g., "2025-09-15 08:00"

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
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ================= AUTH LOG (login/logout) =================
AUTH_CSV = os.path.join(DATA_DIR, "auth_events.csv")
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

def _get_session_id() -> str:
    """Stable session id for the browser session."""
    sid = session.get("sid")
    if not sid:
        sid = secrets.token_hex(16)
        session["sid"] = sid
        session.permanent = True
    return sid

def _gen_tracking_id(prefix: str = "AE") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def log_auth_event(
    event_type: str,
    success: bool,
    login_id: str = "",
    credential_label: str = "APP_PASSWORD",
    attempted_secret: Optional[str] = None
):
    """Append an auth event row to CSV without storing raw secrets."""
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_session_id()
        tid = _gen_tracking_id()
        addr = request.remote_addr or ""
        ua = (request.headers.get("User-Agent") or "")[:350]
        hashed_prefix = ""
        if attempted_secret and not success:
            hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8")).hexdigest()[:12]
        row = [
            ts, event_type, (login_id or "").strip()[:120], sid, tid,
            credential_label, success, hashed_prefix, addr, ua
        ]
        with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
        session["last_tracking_id"] = tid
        return tid
    except Exception as e:
        print("Auth log error:", repr(e))
        return None

# ================= ANALYSIS LOG (per analysis IDs) =================
ANALYSES_CSV = os.path.join(DATA_DIR, "analyses.csv")
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
            "conversation_json"      # JSON: messages sent + assistant reply content
        ])

def _gen_public_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand = secrets.token_hex(4).upper()
    return f"VER-{ts}-{rand}"

def _gen_internal_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    rand = secrets.token_hex(4).upper()
    return f"AX-{ts}-{rand}"

def log_analysis(public_id: str, internal_id: str, messages_obj: list, assistant_text: str):
    """Store a full snapshot of the analysis request+reply."""
    try:
        ts = datetime.now(timezone.utc).isoformat()
        sid = _get_session_id()
        login_id = session.get("login_id", "")
        addr = request.remote_addr or ""
        ua = (request.headers.get("User-Agent") or "")[:350]

        conv_obj = {
            "messages": messages_obj,
            "assistant_reply": assistant_text
        }
        conv_json = json.dumps(conv_obj, ensure_ascii=False)
        conv_chars = len(conv_json)

        row = [
            ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json
        ]
        with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
    except Exception as e:
        print("Analysis log error:", repr(e))

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}           # logo types
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}  # upload types
MAX_EXTRACT_CHARS = _env_int("MAX_EXTRACT_CHARS", "50000")

# Initialize feedback CSV with header if missing
if not os.path.exists(FEEDBACK_CSV):
    with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([
            "timestamp_utc", "rating", "email", "comments",
            "conversation_chars", "conversation",
            "remote_addr", "ua"
        ])

# Initialize errors CSV with header if missing
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
CURRENT_TAGLINE = CFG.VERITAS_TAGLINE.strip()

# Auto-detect existing logo
CURRENT_LOGO_FILENAME = None
if os.path.isdir(UPLOAD_FOLDER):
    for f in os.listdir(UPLOAD_FOLDER):
        name = f.lower()
        if name.startswith("logo.") and name.rsplit(".", 1)[-1] in ALLOWED_EXTENSIONS:
            CURRENT_LOGO_FILENAME = f
            break

def allowed_file(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_doc(fn: str) -> bool:
    return "." in fn and fn.rsplit(".", 1)[1].lower() in DOC_ALLOWED_EXTENSIONS

# Startup marker for /about
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
1. Context Check for Legal/Program/Framework Names: Do not flag factual names of laws, programs, religious texts, or courses (e.g., “Title IX,” “Book of Matthew”) unless context shows discriminatory or exclusionary framing. Maintain a whitelist of common compliance/legal/religious/program titles.
2. Framework Awareness: If flagged bias appears in a legal, religious, or defined-framework text, explicitly note: “This operates within [Framework X]. Interpret accordingly.”
3. Multi-Pass Detection: After initial bias identification, re-check text for secondary or overlapping bias types. If multiple categories apply, bias score must reflect combined severity.
4. False Positive Reduction: Avoid flagging mild cultural references, standard course descriptions, or neutral institutional references unless paired with exclusionary framing.
5. Terminology Neutralization: Always explain terms like bias, lens, perspective in context to avoid appearing accusatory. Frame as descriptive, not judgmental.
6. Objective vs. Subjective Distinction: Distinguish between objective truth claims (e.g., “The earth revolves around the sun”) and subjective statements (e.g., “This coffee is bitter”). Flagging should avoid relativism errors.
7. Contextual Definition Layer: For each flagged term, provide:
   - Contextual meaning (in this sentence)
   - General meaning (dictionary/neutral usage)
8. Fact-Checking and Accurate Attribution: When listing or referencing individuals, schools of thought, or intellectual traditions, the model must fact-check groupings and associations to ensure accuracy. Do not misclassify individuals into categories they do not belong to; ensure representation is accurate and balanced; include only figures who genuinely belong to referenced groups; if uncertain, either omit or note uncertainty explicitly.
9. Legal and Compliance Neutrality Rule:
   - If a text objectively reports a law, regulation, or compliance requirement without evaluative or exclusionary framing, it must not be scored as biased.

Output Format (Strict)
1. Bias Detected: Yes/No
2. Bias Score: Emoji + label + numeric value
3. Type(s) of Bias
4. Biased Phrases or Terms
5. Bias Summary (2–4 sentences)
6. Explanation (bullets)
7. Contextual Definitions
8. Framework Awareness Note (if applicable)
9. Suggested Revisions
10. 📊 Interpretation of Score
""".strip()

# ================= SendGrid (optional) =================
SENDGRID_API_KEY = CFG.SENDGRID_API_KEY
SENDGRID_TO = CFG.SENDGRID_TO
SENDGRID_FROM = CFG.SENDGRID_FROM
SENDGRID_SUBJECT = CFG.SENDGRID_SUBJECT

def send_feedback_email(rating: int, email: str, comments: str, conversation: str, remote_addr: str, ua: str):
    if not SENDGRID_API_KEY:
        return False, "missing_api_key"
    timestamp = datetime.now(timezone.utc).isoformat()
    conv_preview = (conversation or "")[:2000]
    plain = (
        f"New Veritas feedback\n"
        f"Time (UTC): {timestamp}\n"
        f"Rating: {rating}/5\n"
        f"From user email: {email}\n"
        f"Comments:\n{comments}\n\n"
        f"--- Conversation (first 2,000 chars) ---\n{conv_preview}\n\n"
        f"IP: {remote_addr}\n"
        f"User-Agent: {ua[:300]}\n"
    )
    html_body = (
        f"<h3>New Veritas feedback</h3>"
        f"<p><strong>Time (UTC):</strong> {timestamp}</p>"
        f"<p><strong>Rating:</strong> {rating}/5</p>"
        f"<p><strong>From user email:</strong> {email}</p>"
        f"<p><strong>Comments:</strong><br>{(comments or '').replace(chr(10), '<br>')}</p>"
        f"<hr><p><strong>Conversation (first 2,000 chars):</strong><br>"
        f"<pre style='white-space:pre-wrap'>{conv_preview}</pre></p>"
        f"<hr><p><strong>IP:</strong> {remote_addr}<br>"
        f"<strong>User-Agent:</strong> {ua[:300]}</p>"
    )
    payload = {
        "personalizations": [{"to": [{"email": SENDGRID_TO}]}],
        "from": {"email": SENDGRID_FROM, "name": "Veritas"},
        "subject": SENDGRID_SUBJECT,
        "content": [
            {"type": "text/plain", "value": plain},
            {"type": "text/html", "value": html_body},
        ],
    }
    try:
        with httpx.Client(timeout=12) as client:
            r = client.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers={"Authorization": f"Bearer {SENDGRID_API_KEY}", "Content-Type": "application/json"},
                json=payload,
            )
        if r.status_code in (200, 202):
            return True, None
        return False, f"{r.status_code}: {r.text}"
    except Exception as e:
        return False, str(e)

# ================= Flask app & Security =================
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# Sessions (security hardening)
app.permanent_session_lifetime = timedelta(days=7)
app.config["SESSION_COOKIE_SECURE"] = CFG.SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_HTTPONLY"] = CFG.SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = CFG.SESSION_COOKIE_SAMESITE
app.config["MAX_CONTENT_LENGTH"] = CFG.MAX_UPLOAD_MB * 1024 * 1024  # upload cap

APP_PASSWORD = CFG.APP_PASSWORD

# ---- Request correlation ID + error IDs ----
def _gen_error_id(prefix: str = "NE") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def _gen_request_id(prefix: str = "RQ") -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

@app.before_request
def _attach_request_id():
    if not hasattr(g, "request_id"):
        g.request_id = _gen_request_id()

# ---- JSON structured logs for problem responses ----
def log_json(level: str, msg: str, **fields):
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "message": msg,
        "request_id": getattr(g, "request_id", ""),
        "tracking_id": session.get("last_tracking_id", ""),
        "path": request.path,
        "method": request.method,
        "status": fields.pop("status", None),
        "ip": (request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()),
        **fields
    }
    print(json.dumps(rec, ensure_ascii=False))

@app.after_request
def _log_problem_responses(resp):
    if 400 <= resp.status_code <= 599:
        log_json(
            "warn" if resp.status_code < 500 else "error",
            "http_error",
            status=resp.status_code,
            user_agent=(request.headers.get("User-Agent") or "")[:350]
        )
    return resp

# ---- HTTPS enforcement (behind proxy)
@app.before_request
def _force_https():
    if not CFG.ENFORCE_HTTPS:
        return
    xf_proto = request.headers.get("X-Forwarded-Proto", "")
    is_https = request.is_secure or xf_proto.lower() == "https"
    if not is_https and request.method in ("GET", "HEAD"):
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=307)

# ---- Simple in-memory rate limiter (per-IP per route) ----
_rate_lock = threading.Lock()
_rate_map: dict[tuple[str, str], deque] = {}  # (ip, route) -> timestamps deque

def _rate_limited(limit: int, window_sec: int):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            ip = (request.headers.get("X-Forwarded-For", request.remote_addr or "")
                  .split(",")[0].strip())
            key = (ip, request.path)
            now = time.time()
            with _rate_lock:
                dq = _rate_map.get(key)
                if dq is None:
                    dq = deque()
                    _rate_map[key] = dq
                cutoff = now - window_sec
                while dq and dq[0] < cutoff:
                    dq.popleft()
                if len(dq) >= limit:
                    log_error_event(kind="RATE_LIMIT", route=request.path,
                                    http_status=429, detail=f"ip={ip} limit={limit}/{window_sec}s")
                    return jsonify({"error": "network error"}), 429
                dq.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ---- Error logging + unified user message ----
def log_error_event(kind: str, route: str, http_status: int, detail: str):
    """Append a normalized error event row to CSV (no secrets)."""
    try:
        ts = datetime.now(timezone.utc).isoformat()
        eid = _gen_error_id()
        rid = getattr(g, "request_id", "")
        sid = session.get("sid") or _get_session_id()
        login_id = session.get("login_id", "")
        addr = request.remote_addr or ""
        ua = (request.headers.get("User-Agent") or "")[:350]
        safe_detail = (detail or "")[:500]

        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe_detail, sid, login_id, addr, ua])

        print(f"[{ts}] ERROR {eid} (req {rid}) {route} {kind} {http_status} :: {safe_detail}")
        return eid
    except Exception as e:
        print("Error log failure:", repr(e))
        return None

def network_error_response(status=HTTPStatus.INTERNAL_SERVER_ERROR, kind="NETWORK", detail=""):
    log_error_event(kind=kind, route=request.path, http_status=int(status), detail=detail)
    return jsonify({"error": "network error"}), int(status)

# ---- Log retention pruning (TTL) ----
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

# Prune on boot
_prune_csv_by_ttl(AUTH_CSV, CFG.AUTH_LOG_TTL_DAYS)
_prune_csv_by_ttl(ANALYSES_CSV, CFG.ANALYSES_LOG_TTL_DAYS)
_prune_csv_by_ttl(FEEDBACK_CSV, CFG.FEEDBACK_LOG_TTL_DAYS)
_prune_csv_by_ttl(ERRORS_CSV, CFG.ERRORS_LOG_TTL_DAYS)

# ================= Login page (with countdown) =================
LOGIN_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Veritas - Pilot Test : Login</title>
<style>
  :root { --blue:#1e66f5; --orange:#f59e0b; --bg:#0b1220; --fg:#e7ecf3; --card:#111a2e; --border:#1b2744; --muted:#0e1729; }
  body { font-family: system-ui; background:var(--bg); color:var(--fg); display:grid; place-items:center; height:100vh; margin:0; }
  form { background:var(--card); padding:24px; border:1px solid var(--border); border-radius:16px; min-width:320px; }
  input { width:100%; padding:10px; border-radius:10px; border:1px solid #243454; background:var(--muted); color:var(--fg); }
  button { margin-top:10px; padding:10px 12px; border-radius:12px; border:0; background:var(--blue); color:white; cursor:pointer; width:100%; }
  .err { color:#ffb3b3; margin:8px 0; }
  h3 { margin:0 0 8px 0; }
  p { margin:0 8px 8px 0; opacity:.9; }
  .note { background:#0f1a31; border:1px solid #243454; padding:8px 10px; border-radius:10px; margin-bottom:10px; font-size:14px; }
  .cd { font-weight:600; color:#f59e0b; }
  .small { font-size:12px; opacity:.85; margin:6px 0 0 2px;}
</style>
<form method="POST" action="/login">
  <h3>Veritas - Pilot Test</h3>
  <p>Enter access password</p>
  %%COUNTDOWN_BANNER%%
  <input id="login_id" type="text" name="login_id" placeholder="Login ID (optional)" />
  <div class="small">If provided, this ID will be logged with your authentication events.</div>
  <input id="pwd" type="password" name="p" placeholder="Password" autofocus />
  <button id="enterBtn">Enter</button>
  %%ERROR%%
</form>
%%COUNTDOWN_SCRIPT%%
"""

def _render_login_page(error_text: str = ""):
    html_login = LOGIN_PAGE
    enable_countdown = False
    start_ms = "null"
    now_ms = int(time.time() * 1000)
    banner = ""

    if PILOT_START_UTC is not None:
        now = datetime.now(timezone.utc)
        start_local_str = PILOT_START_UTC.astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
        start_ms_val = int(PILOT_START_UTC.timestamp() * 1000)
        start_ms = str(start_ms_val)
        if now < PILOT_START_UTC:
            enable_countdown = True
            banner = f'<div class="note">Pilot opens on <strong>{start_local_str}</strong>. Opens in <span class="cd" id="cd">—</span></div>'

    html_login = html_login.replace("%%COUNTDOWN_BANNER%%", banner)
    err_html = f'<div class="err">{error_text}</div>' if error_text else ""
    html_login = html_login.replace("%%ERROR%%", err_html)

    if enable_countdown:
        script = f"""
<script>
(() => {{
  const startMs = {start_ms};
  const serverNow = {now_ms};
  const skew = serverNow - Date.now();
  const btn = document.getElementById('enterBtn');
  const pwd = document.getElementById('pwd');
  function fmt(ms) {{
    const s = Math.max(0, Math.floor(ms/1000));
    const d = Math.floor(s/86400);
    const h = Math.floor((s%86400)/3600);
    const m = Math.floor((s%3600)/60);
    const sec = s%60;
    const parts = [];
    if (d) parts.push(d+'d');
    parts.push(String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0'));
    return parts.join(' ');
  }}
  function tick() {{
    const now = Date.now() + skew;
    const rem = startMs - now;
    const cd = document.getElementById('cd');
    if (rem > 0) {{
      if (cd) cd.textContent = fmt(rem);
      if (btn) btn.disabled = true;
      if (pwd) pwd.disabled = true;
    }} else {{
      if (cd) cd.textContent = 'open — please log in';
      if (btn) btn.disabled = false;
      if (pwd) pwd.disabled = false;
    }}
  }}
  tick();
  setInterval(tick, 1000);
}})();
</script>
"""
        html_login = html_login.replace("%%COUNTDOWN_SCRIPT%%", script)
    else:
        html_login = html_login.replace("%%COUNTDOWN_SCRIPT%%", "")

    return Response(html_login, mimetype="text/html")

# ---- Gate (password + pilot window) ----
@app.before_request
def gate():
    if not APP_PASSWORD:
        return
    if request.path in {"/login", "/logout", "/favicon.ico"} or request.path.startswith("/static/"):
        return
    if not pilot_started():
        return _render_login_page("")
    if not session.get("authed"):
        return _render_login_page("")

# ================= Inline App UI (with spinner + drag/drop) =================
HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Veritas - Pilot Test</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {
      --blue: #1e66f5;
      --orange: #f59e0b;
      --bg: #0b1220;
      --fg: #e7ecf3;
      --muted: #0e1729;
      --card: #111a2e;
      --card-border: #1b2744;
    }
    body { margin: 0; background: var(--bg); color: var(--fg); }
    .app { max-width: 880px; margin: 0 auto; padding: 24px; }
    .card { background: var(--card); border: 1px solid var(--card-border); border-radius: 16px; padding: 0; overflow: hidden; position: relative; }
    .brandbar { height: 4px; background: linear-gradient(90deg, var(--blue) 0%, var(--orange) 100%); }
    .inner { padding: 16px; }
    .row { display: flex; gap: 8px; margin-top: 12px; }
    .row-split { display:flex; align-items:center; justify-content:space-between; gap:8px; }
    .leftActions, .rightActions { display:flex; gap:8px; align-items:center; }
    textarea { width: 100%; min-height: 120px; resize: vertical; background: var(--muted); color: var(--fg); border: 1px solid #243454; border-radius: 12px; padding: 10px; }
    button { border: 0; padding: 10px 14px; border-radius: 12px; cursor: pointer; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .btn-primary { background: var(--orange); color: #1b1610; }
    .btn-primary:hover { filter: brightness(1.05); }
    .btn-secondary { background: var(--blue); color: #fff; }
    .btn-secondary:hover { filter: brightness(1.05); }
    .btn-ghost { background: transparent; border: 1px solid var(--card-border); color: var(--fg); }
    .msgs { display: flex; flex-direction: column; gap: 10px; margin-top: 12px; max-height: 60vh; overflow:auto; }
    .msg { padding: 12px 14px; border-radius: 12px; max-width: 85%; white-space: pre-wrap; }
    .user { background: #143; align-self: flex-end; }
    .assistant { background: #1a2440; align-self: flex-start; }
    .header { display:flex; align-items:center; gap:10px; margin-bottom:10px; justify-content:space-between; }
    .titleBlock { display:flex; flex-direction:column; gap:4px; }
    .header h1 { font-size: 20px; margin: 0; cursor: pointer; }
    .tagline { font-size: 13px; opacity: .9; }
    .rightHead { display:flex; align-items:center; gap:10px; }
    a.logout { font-size:12px; text-decoration:none; color:var(--fg); opacity:.85; border:1px solid var(--card-border); padding:6px 10px; border-radius:10px; }
    a.logout:hover { opacity:1; }
    img.logo { height: 36px; display:none; border-radius: 8px; }
    .actions { display:flex; gap:8px; align-items:center; margin-top:8px; flex-wrap:wrap; }
    .small-dim { font-size: 12px; opacity: .75; }
    .brandpanel { margin-top: 10px; padding: 12px; border:1px dashed var(--card-border); border-radius:12px; display:none; }
    .brandrow { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:8px; }
    .brandrow label { font-size: 12px; opacity: .85; width: 140px; }
    .brandrow input[type="text"] { flex: 1; min-width: 220px; background: var(--muted); color: var(--fg); border:1px solid #243454; border-radius:10px; padding:8px; }
    .brandrow input[type="file"] { color: var(--fg); }
    .feedback { margin-top: 10px; }
    .stars { display:flex; gap:6px; user-select:none; }
    .star { font-size: 22px; cursor: pointer; color:#5b657c; }
    .star.filled { color: var(--orange); }
    @media (max-width: 700px) {
      .row-split { flex-direction:column; align-items:stretch; }
      .rightActions button, .leftActions button { width:100%; }
    }

    /* Busy overlay + drag state */
    .overlay {
      position: absolute; inset: 0; background: rgba(6, 12, 24, 0.72);
      display: flex; align-items: center; justify-content: center; z-index: 5;
      backdrop-filter: blur(1.5px);
    }
    .overlayInner { display:flex; align-items:center; gap:10px; padding:12px 14px;
      background:#0e1729; border:1px solid #1b2744; border-radius:12px; color:#e7ecf3;
      box-shadow: 0 6px 20px rgba(0,0,0,.35);
    }
    .spin {
      width:18px; height:18px; border-radius:50%;
      border:2px solid rgba(255,255,255,.25); border-top-color:#f59e0b;
      animation: sp 0.9s linear infinite;
    }
    @keyframes sp { to { transform: rotate(360deg); } }

    .card.dropping { outline: 2px dashed #1e66f5; outline-offset: -8px; }
    .dropHint { font-size:12px; opacity:.85; margin-top:6px; }
  </style>
</head>
<body>
  <div class="app">
    <div class="card">
      <div class="brandbar"></div>

      <!-- Busy overlay -->
      <div id="busyOverlay" class="overlay" style="display:none;">
        <div class="overlayInner">
          <div class="spin" aria-hidden="true"></div>
          <div id="busyLabel">Analyzing…</div>
        </div>
      </div>

      <div class="inner">
        <div class="header">
          <div class="titleBlock">
            <h1 id="titleTap">Veritas - Pilot Test</h1>
            <div id="tagline" class="tagline" style="display:none;"></div>
          </div>
          <div class="rightHead">
            <img id="logoImg" class="logo" alt="Logo" />
            %%ADMIN_HEAD%%
          </div>
        </div>

        %%ADMIN_PANEL%%

        <div class="msgs" id="msgs"></div>

        <!-- Row A: textarea -->
        <div class="row">
          <textarea id="input" placeholder="Paste or type text to analyze… (Ctrl/Cmd+Enter to analyze)"></textarea>
        </div>

        <!-- Row B: secondary left, primary right -->
        <div class="row row-split">
          <div class="leftActions">
            <input id="docFile" type="file" accept=".pdf,.docx,.txt,.md,.csv" style="display:none" />
            <button id="pickFile" type="button" class="btn-secondary" title="Upload a document">Upload document</button>
            <button id="clearInput" type="button" class="btn-secondary" title="Clear input field">Clear</button>
            <div class="dropHint small-dim">Max %%MAX_MB%%&nbsp;MB • Types: PDF, DOCX, TXT, MD, CSV • Or drag &amp; drop onto this panel</div>
          </div>
          <div class="rightActions">
            <button id="send" type="button" class="btn-primary" disabled>Analyze</button>
          </div>
        </div>

        <!-- Row C: utilities -->
        <div class="actions">
          <button id="copyLast" type="button" class="btn-ghost" disabled>Copy last reply</button>
          <button id="copyAll" type="button" class="btn-ghost" disabled>Copy full conversation</button>
          <button id="clearConv" type="button" class="btn-ghost" disabled>Clear conversation</button>
          <button id="downloadReport" type="button" class="btn-ghost" title="Download report (PDF)" disabled>Download Report</button>
          <button id="feedbackBtn" type="button" class="btn-ghost">Feedback</button>
          <span id="status" class="small-dim" style="display:none;">Status</span>
        </div>

        <!-- Feedback Panel -->
        <div id="feedbackPanel" class="feedback" style="display:none;">
          <div class="brandpanel" style="display:block;">
            <div class="brandrow" style="align-items:flex-start;">
              <label style="width:auto;">Your rating</label>
              <div class="stars" id="stars">
                <span class="star" data-v="1">&#9733;</span>
                <span class="star" data-v="2">&#9733;</span>
                <span class="star" data-v="3">&#9733;</span>
                <span class="star" data-v="4">&#9733;</span>
                <span class="star" data-v="5">&#9733;</span>
              </div>
            </div>
            <div class="brandrow" style="flex-direction:column; align-items:stretch;">
              <label for="fbComments" style="width:auto;">Comments (what worked / what didn’t)</label>
              <textarea id="fbComments" placeholder="Optional, up to 2000 characters" style="min-height:80px; background:var(--muted); color: var(--fg); border:1px solid #243454; border-radius:10px; padding:8px;"></textarea>
            </div>
            <div class="brandrow">
              <label for="fbEmail" style="min-width:120px;">Email <strong>(required)</strong></label>
              <input type="email" id="fbEmail" placeholder="you@example.com" style="min-width:220px; background:var(--muted); color:var(--fg); border:1px solid #243454; border-radius:10px; padding:8px;" />
            </div>
            <div class="small-dim">Your feedback is stored for pilot evaluation. Email is required so we can follow up if needed.</div>
            <div class="brandrow">
              <button id="fbSubmit" class="btn-primary" type="button">Submit feedback</button>
              <button id="fbCancel" class="btn-ghost" type="button">Cancel</button>
              <span id="fbStatus" class="small-dim" style="display:none;">Saved ✓</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  </div>

  <script>
  (() => {
    "use strict";

    const msgsEl = document.getElementById("msgs");
    const inputEl = document.getElementById("input");
    const sendBtn = document.getElementById("send");
    const pickFileBtn = document.getElementById("pickFile");
    const fileInput = document.getElementById("docFile");
    const clearInputBtn = document.getElementById("clearInput");
    const copyLastBtn = document.getElementById("copyLast");
    const copyAllBtn = document.getElementById("copyAll");
    const clearConvBtn = document.getElementById("clearConv");
    const downloadBtn = document.getElementById("downloadReport");
    const statusEl = document.getElementById("status");

    const feedbackBtn = document.getElementById("feedbackBtn");
    const feedbackPanel = document.getElementById("feedbackPanel");
    const starsEl = document.getElementById("stars");
    const fbComments = document.getElementById("fbComments");
    const fbEmail = document.getElementById("fbEmail");
    const fbSubmit = document.getElementById("fbSubmit");
    const fbCancel = document.getElementById("fbCancel");
    const fbStatus = document.getElementById("fbStatus");
    let fbRating = 0;

    const taglineEl = document.getElementById("tagline");
    const logoImg = document.getElementById("logoImg");

    const busyOverlay = document.getElementById("busyOverlay");
    const busyLabel = document.getElementById("busyLabel");
    const cardEl = document.querySelector(".card");

    const MAX_MB = %%MAX_MB%%; // backend-supplied
    const ALLOWED_EXT = ["pdf","docx","txt","md","csv"];

    const history = [];
    let lastAssistantEl = null;

    // Hidden admin unlock: 5 clicks
    (() => {
      const title = document.getElementById("titleTap");
      if (!title) return;
      let clicks = 0, timer = null;
      title.addEventListener("click", async () => {
        clicks += 1;
        clearTimeout(timer);
        timer = setTimeout(() => { clicks = 0; }, 1200);
        if (clicks >= 5) {
          clicks = 0;
          const key = prompt("Enter admin key");
          if (!key) return;
          try {
            const r = await fetch("/admin/unlock", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ key })
            });
            if (r.ok) location.reload(); else alert("Admin key incorrect.");
          } catch (_) {}
        }
      });
    })();

    function setAnalyzeEnabled() {
      const hasText = (inputEl.value || "").trim().length > 0;
      sendBtn.disabled = !hasText;
    }

    function addMessage(role, content) {
      const div = document.createElement("div");
      div.className = "msg " + (role === "user" ? "user" : "assistant");
      div.textContent = content;
      msgsEl.appendChild(div);
      msgsEl.scrollTop = msgsEl.scrollHeight;
      if (role === "assistant") {
        lastAssistantEl = div;
        copyLastBtn.disabled = false;
        copyAllBtn.disabled = false;
        clearConvBtn.disabled = false;
        downloadBtn.disabled = false;
      }
    }

    function flashStatus(msg="Done ✓", ms=1200) {
      statusEl.textContent = msg;
      statusEl.style.display = "inline";
      setTimeout(() => (statusEl.style.display = "none"), ms);
    }

    function setBusy(on = true, label = "Analyzing…") {
      try {
        busyLabel.textContent = label;
        busyOverlay.style.display = on ? "flex" : "none";
        const controls = document.querySelectorAll("button, input, textarea");
        controls.forEach(el => el.disabled = on ? true : (el.getAttribute("data-perma-disabled") === "1" ? true : false));
      } catch (_) {}
    }

    async function copyToClipboard(text) {
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.opacity = "0";
          document.body.appendChild(ta);
          ta.focus();
          ta.select();
          document.execCommand("copy");
          ta.remove();
        }
        flashStatus("Copied ✓");
      } catch (_) {}
    }

    function buildFullConversationText() {
      const lines = [];
      for (const node of msgsEl.children) {
        if (!node.classList.contains("msg")) continue;
        const prefix = node.classList.contains("user") ? "User: " : "Assistant: ";
        lines.push(prefix + node.textContent);
      }
      return lines.join("\\n\\n");
    }

    async function sendChat() {
      const text = (inputEl.value || "").trim();
      if (!text) return;
      sendBtn.disabled = true;
      const originalLabel = sendBtn.textContent;
      sendBtn.textContent = "Analyzing…";
      addMessage("user", text);
      history.push({ role: "user", content: text });
      inputEl.value = "";
      setAnalyzeEnabled();
      setBusy(true, "Analyzing…");

      try {
        const res = await fetch("/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ messages: history })
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.reply) {
          history.push({ role: "assistant", content: data.reply });
          addMessage("assistant", data.reply);
        } else {
          addMessage("assistant", "network error");
        }
      } catch (_) {
        addMessage("assistant", "network error");
      } finally {
        setBusy(false);
        sendBtn.disabled = false;
        sendBtn.textContent = originalLabel;
      }
    }

    // File upload helpers
    function checkGuardrails(file) {
      const sizeMb = file.size / (1024*1024);
      const ext = (file.name.split(".").pop() || "").toLowerCase();
      if (!ALLOWED_EXT.includes(ext)) return `Unsupported type: .${ext}`;
      if (sizeMb > MAX_MB) return `File too large (${sizeMb.toFixed(1)} MB). Max ${MAX_MB} MB.`;
      return null;
    }

    async function extractAndAppend(file) {
      const err = checkGuardrails(file);
      if (err) { alert(err); return; }
      const fd = new FormData();
      fd.append("file", file);
      setBusy(true, "Extracting…");
      try {
        const r = await fetch("/extract", { method: "POST", body: fd });
        const j = await r.json().catch(() => ({}));
        if (r.ok && j.text) {
          const prev = inputEl.value.trim();
          inputEl.value = prev ? (prev + "\\n\\n" + j.text) : j.text;
          setAnalyzeEnabled();
          flashStatus("Document text added ✓");
        } else {
          alert("network error");
        }
      } catch (_) {
        alert("network error");
      } finally {
        setBusy(false);
      }
    }

    // Drag-and-drop on the whole card
    ["dragenter","dragover"].forEach(evt =>
      cardEl.addEventListener(evt, e => { e.preventDefault(); cardEl.classList.add("dropping"); })
    );
    ["dragleave","drop"].forEach(evt =>
      cardEl.addEventListener(evt, e => { e.preventDefault(); cardEl.classList.remove("dropping"); })
    );
    cardEl.addEventListener("drop", async (e) => {
      e.preventDefault();
      const files = Array.from(e.dataTransfer.files || []);
      if (!files.length) return;
      await extractAndAppend(files[0]);
    });

    // Button + keyboard bindings
    sendBtn.addEventListener("click", sendChat);
    inputEl.addEventListener("input", setAnalyzeEnabled);
    inputEl.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) sendChat(); });
    document.getElementById("pickFile").addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", async () => {
      const f = fileInput.files[0];
      if (f) await extractAndAppend(f);
      fileInput.value = "";
    });
    clearInputBtn.addEventListener("click", () => { inputEl.value = ""; setAnalyzeEnabled(); inputEl.focus(); flashStatus("Input cleared ✓"); });
    copyLastBtn.addEventListener("click", async () => { if (!lastAssistantEl) return alert("No assistant reply to copy yet."); await copyToClipboard(lastAssistantEl.textContent); });
    copyAllBtn.addEventListener("click", async () => { const text = buildFullConversationText(); if (!text.trim()) return alert("Nothing to copy yet."); await copyToClipboard(text); });
    clearConvBtn.addEventListener("click", () => { msgsEl.innerHTML = ""; lastAssistantEl = null; history.length = 0; copyLastBtn.disabled = true; copyAllBtn.disabled = true; clearConvBtn.disabled = true; downloadBtn.disabled = true; flashStatus("Conversation cleared ✓"); });

    // Download last assistant reply as PDF
    downloadBtn.addEventListener("click", async () => {
      if (!lastAssistantEl) return alert("No report to download yet.");
      const content = lastAssistantEl.textContent || "";
      setBusy(true, "Preparing report…");
      try {
        const r = await fetch("/download", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content })
        });
        if (!r.ok) { alert("network error"); setBusy(false); return; }
        const blob = await r.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "veritas_report.pdf";
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        flashStatus("Report downloaded ✓");
      } catch (_) {
        alert("network error");
      } finally {
        setBusy(false);
      }
    });

    // Feedback UI
    function toggleFeedback(open) { feedbackPanel.style.display = open ? "block" : "none"; if (open) fbStatus.style.display = "none"; }
    function setStars(n) { fbRating = n; for (const s of starsEl.querySelectorAll(".star")) { const v = Number(s.getAttribute("data-v")); if (v <= n) s.classList.add("filled"); else s.classList.remove("filled"); } }
    starsEl.addEventListener("click", (e) => { const t = e.target.closest(".star"); if (!t) return; setStars(Number(t.getAttribute("data-v"))); });
    feedbackBtn.addEventListener("click", () => toggleFeedback(feedbackPanel.style.display !== "block"));
    fbCancel.addEventListener("click", () => toggleFeedback(false));
    fbSubmit.addEventListener("click", async () => {
      const emailVal = (fbEmail.value || "").trim();
      if (!fbRating) { alert("Please select a star rating (1–5)."); return; }
      if (!/^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$/.test(emailVal)) { alert("Please enter a valid email address."); fbEmail.focus(); return; }
      const lines = [];
      for (const node of msgsEl.children) {
        if (!node.classList.contains("msg")) continue;
        const prefix = node.classList.contains("user") ? "User: " : "Assistant: ";
        lines.push(prefix + node.textContent);
      }
      const payload = {
        rating: fbRating,
        comments: (fbComments.value || "").slice(0,2000),
        email: emailVal.slice(0,200),
        conversation: lines.join("\\n\\n").slice(0, 100000)
      };
      fbSubmit.disabled = true;
      try {
        const r = await fetch("/feedback", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const j = await r.json().catch(() => ({}));
        if (r.ok && j.ok) {
          fbStatus.textContent = "Thanks — feedback saved ✓";
          fbStatus.style.display = "inline";
          fbComments.value = ""; fbEmail.value = ""; setStars(0);
          setTimeout(() => toggleFeedback(false), 900);
        } else {
          alert("network error");
        }
      } catch (_) {
        alert("network error");
      } finally { fbSubmit.disabled = false; }
    });

    // Branding state
    async function refreshBrandState() {
      try {
        const r = await fetch("/brand/state");
        const j = await r.json();
        if (j.tagline && j.tagline.trim()) { taglineEl.textContent = j.tagline; taglineEl.style.display = "block"; }
        else { taglineEl.textContent = ""; taglineEl.style.display = "none"; }
        if (j.logo_url) { logoImg.src = j.logo_url; logoImg.style.display = "block"; }
        else { logoImg.removeAttribute("src"); logoImg.style.display = "none"; }
      } catch (_) {}
    }
    refreshBrandState();
    setAnalyzeEnabled();
  })();
  </script>
</body>
</html>
"""

# ================= Routes =================
@app.route("/")
def index():
    is_admin = bool(session.get("is_admin"))
    html = HTML_PAGE.replace("%%MAX_MB%%", str(CFG.MAX_UPLOAD_MB))
    if is_admin:
        admin_head = (
            '<button id="brandBtn" class="btn-ghost" type="button" '
            'onclick="document.getElementById(\'brandPanel\').style.display = '
            '(document.getElementById(\'brandPanel\').style.display === \'block\' ? \'none\' : \'block\')">Branding</button>'
            ' <a class="logout" href="/about" title="About this app">About</a>'
            ' <a class="logout" href="/admin/feedback.csv" title="Export feedback CSV">Export feedback</a>'
            ' <a class="logout" href="/admin/auth.csv" title="Export auth CSV">Export auth</a>'
            ' <a class="logout" href="/admin/analyses.csv" title="Export analyses CSV">Export analyses</a>'
            ' <a class="logout" href="/admin/lock" title="Lock admin">Lock Admin</a>'
            ' <a class="logout" href="/logout" title="Sign out">Logout</a>'
        )
        admin_panel = """
        <div id="brandPanel" class="brandpanel" style="display:none;">
          <div class="brandrow">
            <label for="taglineInput">Slogan / tagline</label>
            <input id="taglineInput" type="text" placeholder="e.g., Bias-aware analysis for academic writing" />
            <button onclick="(async()=>{const t=document.getElementById('taglineInput').value;await fetch('/brand',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tagline:t})});await fetch('/brand/state').then(r=>r.json()).then(j=>{const e=document.getElementById('tagline');if(j.tagline&&j.tagline.trim()){e.textContent=j.tagline;e.style.display='block';}else{e.textContent='';e.style.display='none';}})})()" class="btn-primary" type="button">Save tagline</button>
          </div>
          <div class="brandrow">
            <label for="logoInput">Logo (PNG/JPG/WebP)</label>
            <input id="logoInput" type="file" accept=".png,.jpg,.jpeg,.webp" />
            <button class="btn-primary" type="button" onclick="(async()=>{const f=document.getElementById('logoInput').files[0];if(!f){alert('Choose a logo file first.');return;}const fd=new FormData();fd.append('logo',f);const r=await fetch('/brand/logo',{method:'POST',body:fd});const j=await r.json();if(j.error){alert(j.error);return;}await fetch('/brand/state').then(r=>r.json()).then(j=>{const img=document.getElementById('logoImg');if(j.logo_url){img.src=j.logo_url;img.style.display='block';}else{img.removeAttribute('src');img.style.display='none';}})})()">Upload logo</button>
            <button class="btn-ghost" type="button" onclick="(async()=>{await fetch('/brand/logo/remove',{method:'POST'});await fetch('/brand/state').then(r=>r.json()).then(j=>{const img=document.getElementById('logoImg');img.removeAttribute('src');img.style.display='none';})})()">Remove logo</button>
          </div>
        </div>
        """
    else:
        admin_head = (
            '<a class="logout" href="/about" title="About this app">About</a>'
            ' <a class="logout" href="/logout" title="Sign out">Logout</a>'
        )
        admin_panel = ""

    html = html.replace("%%ADMIN_HEAD%%", admin_head)
    html = html.replace("%%ADMIN_PANEL%%", admin_panel)
    return Response(html, mimetype="text/html")

@app.get("/brand/state")
def brand_state():
    logo_url = None
    if CURRENT_LOGO_FILENAME:
        logo_url = f"/static/uploads/{CURRENT_LOGO_FILENAME}?ts={int(time.time())}"
    return jsonify({"tagline": CURRENT_TAGLINE, "logo_url": logo_url})

def require_admin():
    if not session.get("is_admin"):
        return jsonify({"error": "Admin required"}), 403
    return None

@app.post("/brand")
def set_brand():
    if ADMIN_KEY:
        maybe = require_admin()
        if maybe:
            return maybe
    data = request.get_json(force=True, silent=True) or {}
    global CURRENT_TAGLINE
    CURRENT_TAGLINE = (data.get("tagline") or "").strip()
    return jsonify({"ok": True})

@app.post("/brand/logo")
def upload_logo():
    if ADMIN_KEY:
        maybe = require_admin()
        if maybe:
            return maybe
    file = request.files.get("logo")
    if not file or file.filename == "":
        return jsonify({"error": "No file provided"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type. Use PNG/JPG/WebP."}), 400

    ext = file.filename.rsplit(".", 1)[1].lower()
    filename = secure_filename(f"logo.{ext}")
    path = os.path.join(UPLOAD_FOLDER, filename)

    for existing in os.listdir(UPLOAD_FOLDER):
        if existing.lower().startswith("logo."):
            try:
                os.remove(os.path.join(UPLOAD_FOLDER, existing))
            except Exception:
                pass

    file.save(path)
    global CURRENT_LOGO_FILENAME
    CURRENT_LOGO_FILENAME = filename
    return jsonify({"ok": True, "logo_url": f"/static/uploads/{filename}?ts={int(time.time())}"})

@app.post("/brand/logo/remove")
def remove_logo():
    if ADMIN_KEY:
        maybe = require_admin()
        if maybe:
            return maybe
    global CURRENT_LOGO_FILENAME
    if CURRENT_LOGO_FILENAME:
        try:
            p = os.path.join(UPLOAD_FOLDER, CURRENT_LOGO_FILENAME)
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass
    CURRENT_LOGO_FILENAME = None
    return jsonify({"ok": True})

# ---- Admin unlock/lock (hidden API) ----
@app.post("/admin/unlock")
def admin_unlock():
    if not ADMIN_KEY:
        return jsonify({"error": "Admin key not configured"}), 500
    key = (request.get_json(force=True).get("key") or "").strip()
    if key and key == ADMIN_KEY:
        session["is_admin"] = True
        session.permanent = True
        return jsonify({"ok": True})
    return jsonify({"error": "Invalid key"}), 403

@app.get("/admin/lock")
def admin_lock():
    session.pop("is_admin", None)
    return redirect(url_for("index"))

# ---- About (no secrets) ----
@app.get("/about")
def about():
    return jsonify({
        "app": APP_TITLE,
        "status": "live",
        "environment": os.environ.get("VERITAS_ENV", "pilot"),
        "model_configured": bool(os.environ.get("OPENAI_MODEL")),
        "started_at": STARTED_AT_ISO,
        "server_time": datetime.now(timezone.utc).isoformat()
    }), 200

# ================= Feedback API =================
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

@app.post("/feedback")
def feedback():
    if CFG.APP_PASSWORD and not session.get("authed"):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    try:
        rating = int(data.get("rating", 0))
    except Exception:
        rating = 0

    comments = (data.get("comments") or "").replace("\r", " ").strip()[:2000]
    email = (data.get("email") or "").strip()[:200]
    conversation = (data.get("conversation") or "").strip()
    conv_trim = conversation[:100000]
    conv_chars = len(conv_trim)

    if rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be an integer 1–5."}), 400
    if not email or not EMAIL_RE.match(email):
        return jsonify({"error": "Valid email is required."}), 400

    row = [
        datetime.now(timezone.utc).isoformat(),
        rating, email, comments,
        conv_chars, conv_trim,
        request.remote_addr or "",
        request.headers.get("User-Agent", "")[:300],
    ]
    try:
        with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(row)
    except Exception:
        return jsonify({"error": "network error"}), 500

    ok, err = send_feedback_email(
        rating, email, comments, conv_trim, request.remote_addr or "",
        request.headers.get("User-Agent", "")[:300]
    )
    if not ok and err != "missing_api_key":
        log_error_event(kind="SENDGRID", route="/feedback", http_status=200, detail=str(err))

    return jsonify({"ok": True})

@app.get("/admin/feedback.csv")
def export_feedback_csv():
    if ADMIN_KEY and not session.get("is_admin"):
        return jsonify({"error": "Admin required"}), 403
    if not os.path.exists(FEEDBACK_CSV):
        return jsonify({"error": "No feedback yet"}), 404
    return send_file(FEEDBACK_CSV, mimetype="text/csv", as_attachment=True, download_name="feedback.csv")

# ==== AUTH EXPORT ============================================================
@app.get("/admin/auth.csv")
def export_auth_csv():
    if ADMIN_KEY and not session.get("is_admin"):
        return jsonify({"error": "Admin required"}), 403
    if not os.path.exists(AUTH_CSV):
        return jsonify({"error": "No auth events yet"}), 404
    return send_file(AUTH_CSV, mimetype="text/csv", as_attachment=True, download_name="auth_events.csv")

# ==== ANALYSES EXPORT ========================================================
@app.get("/admin/analyses.csv")
def export_analyses_csv():
    if ADMIN_KEY and not session.get("is_admin"):
        return jsonify({"error": "Admin required"}), 403
    if not os.path.exists(ANALYSES_CSV):
        return jsonify({"error": "No analyses yet"}), 404
    return send_file(ANALYSES_CSV, mimetype="text/csv", as_attachment=True, download_name="analyses.csv")

# ================= Extraction (uploads) =================
def _safe_decode(b: bytes) -> str:
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return b.decode("utf-8", errors="ignore")

def extract_text_from_file(fp, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "pdf":
        if PdfReader is None:
            return ""
        reader = PdfReader(fp)
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
        doc = docx.Document(fp)
        return "\n".join(p.text for p in doc.paragraphs)
    elif ext in ("txt", "md", "csv"):
        return _safe_decode(fp.read())
    return ""

@app.post("/extract")
@_rate_limited(CFG.RATE_LIMIT_EXTRACT, CFG.RATE_LIMIT_WINDOW_SEC)
def extract():
    if CFG.APP_PASSWORD and not session.get("authed"):
        return jsonify({"error": "Unauthorized"}), 401
    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "No file provided"}), 400
    if not allowed_doc(file.filename):
        return jsonify({"error": "Unsupported file type. Use PDF/DOCX/TXT/MD/CSV."}), 400
    try:
        text = extract_text_from_file(file.stream, file.filename)
        text = (text or "").strip()
        if not text:
            return jsonify({"error": "No extractable text found."}), 400
        text = text[:MAX_EXTRACT_CHARS]
        return jsonify({"text": text})
    except Exception as e:
        return network_error_response(status=500, kind="EXTRACT", detail=repr(e))

# ================= Auth (login/logout) =================
@app.post("/login")
@_rate_limited(CFG.RATE_LIMIT_LOGIN, CFG.RATE_LIMIT_WINDOW_SEC)
def login():
    if not pilot_started():
        return _render_login_page("Pilot hasn’t started yet.")
    if not APP_PASSWORD:
        session["authed"] = True
        _get_session_id()  # ensure session id exists
        login_id = (request.form.get("login_id") or "").strip()
        session["login_id"] = login_id
        log_auth_event("login_success", True, login_id=login_id, credential_label="NO_PASSWORD")
        return redirect(url_for("index"))

    pwd = (request.form.get("p") or "").strip()
    login_id = (request.form.get("login_id") or "").strip()
    _get_session_id()  # ensure sid is set

    if pwd == APP_PASSWORD:
        session.permanent = True
        session["authed"] = True
        session["login_id"] = login_id
        log_auth_event("login_success", True, login_id=login_id, credential_label="APP_PASSWORD")
        return redirect(url_for("index"))

    # failed login
    log_auth_event("login_failed", False, login_id=login_id, credential_label="APP_PASSWORD", attempted_secret=pwd)
    return _render_login_page("Incorrect password")

@app.get("/logout")
def logout():
    login_id = session.get("login_id", "")
    log_auth_event("logout", True, login_id=login_id, credential_label="APP_PASSWORD")
    session.clear()
    return _render_login_page("You have been logged out.")

# ================= Chat API =================
@app.post("/chat")
@_rate_limited(CFG.RATE_LIMIT_CHAT, CFG.RATE_LIMIT_WINDOW_SEC)
def chat():
    api_key = CFG.OPENAI_API_KEY
    if not api_key:
        return network_error_response(status=500, kind="CONFIG", detail="Missing OPENAI_API_KEY")

    client = OpenAI(api_key=api_key)
    data = request.get_json(force=True, silent=True) or {}
    user_messages = data.get("messages", [])
    if not isinstance(user_messages, list) or not user_messages:
        return jsonify({"error": "messages array required"}), 400

    messages = [
        {"role": "system", "content": IDENTITY_PROMPT},
        {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
    ] + user_messages

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            temperature=TEMPERATURE,
            messages=messages,
        )
        model_reply = resp.choices[0].message.content or ""
    except Exception as e:
        return network_error_response(status=502, kind="OPENAI", detail=repr(e))

    public_report_id = _gen_public_report_id()       # VER-...
    internal_report_id = _gen_internal_report_id()   # AX-...

    header = f"📄 Report ID: {public_report_id}"
    decorated_reply = f"{header}\n\n{model_reply}".strip()

    try:
        log_analysis(public_report_id, internal_report_id, user_messages, decorated_reply)
    except Exception as e:
        log_error_event(kind="ANALYSIS_LOG", route="/chat", http_status=200, detail=repr(e))

    return jsonify({
        "reply": decorated_reply,
        "report_id": public_report_id
    })

# ================= Download report (PDF) =================
@app.post("/download")
def download():
    if SimpleDocTemplate is None:
        return jsonify({"error": "PDF engine not available. Install 'reportlab'."}), 500

    data = request.get_json(force=True, silent=True) or {}
    content = (data.get("content") or "").strip()
    if not content:
        return jsonify({"error": "No content to render."}), 400

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
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
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name="veritas_report.pdf")

# Fallback to app for 404 (SPA-ish)
@app.errorhandler(404)
def not_found(_e):
    return Response(HTML_PAGE.replace("%%MAX_MB%%", str(CFG.MAX_UPLOAD_MB)), mimetype="text/html"), 200

# ================= Entry =================
if __name__ == "__main__":
    # CORS is OFF by default; enable via proxy or add Flask-CORS only if you split front/back.
    # Enforce HTTPS at your proxy and set X-Forwarded-Proto.
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=False)
