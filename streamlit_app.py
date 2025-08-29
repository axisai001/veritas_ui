# streamlit_app.py — Veritas (Streamlit)
# Tabs: Analyze · Feedback · Support · Help (help is last)
# History & Data Explorer moved to pages/01_Admin.py (admin-only)
# Report time zone removed from UI, still tracked internally
# Session kept; random session ID tracked internally (not shown)

import os
import io
import csv
import time
import json
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

# Optional parsers
try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None
try:
    import docx
except Exception:
    docx = None

# Optional PDF (ReportLab)
try:
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfbase.pdfmetrics import stringWidth
except Exception:
    SimpleDocTemplate = None

# ===== Settings
try:
    from config import load_settings
    settings = load_settings()
except Exception:
    class _FallbackSettings:
        openai_api_key = os.environ.get("OPENAI_API_KEY", "")
        openai_model = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo-0125")
        auth_log_ttl_days = int(os.environ.get("AUTH_LOG_TTL_DAYS", "365"))
    settings = _FallbackSettings()

APP_TITLE = os.environ.get("APP_TITLE", "Veritas — Pilot Test")
MODEL = getattr(settings, "openai_model", os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo-0125"))
try:
    TEMPERATURE = float(os.environ.get("OPENAI_TEMPERATURE", "0.2"))
except Exception:
    TEMPERATURE = 0.2

# Timezone (tracked internally)
def _safe_zoneinfo(name: str, fallback: str = "UTC") -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except Exception:
        return ZoneInfo(fallback)

PILOT_TZ_NAME = os.environ.get("VERITAS_TZ", "America/Denver")
PILOT_TZ = _safe_zoneinfo(PILOT_TZ_NAME, "UTC")
PILOT_START_AT = os.environ.get("PILOT_START_AT", "")
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

# Rate limits
RATE_LIMIT_LOGIN = int(os.environ.get("RATE_LIMIT_LOGIN", "5"))
RATE_LIMIT_CHAT  = int(os.environ.get("RATE_LIMIT_CHAT",  "6"))
RATE_LIMIT_WINDOW_SEC = int(os.environ.get("RATE_LIMIT_WINDOW_SEC", "60"))

# Uploads
try:
    MAX_UPLOAD_MB = float(os.environ.get("MAX_UPLOAD_MB", "10"))
except Exception:
    MAX_UPLOAD_MB = 10.0
MAX_EXTRACT_CHARS = int(os.environ.get("MAX_EXTRACT_CHARS", "50000"))

# TTLs
AUTH_LOG_TTL_DAYS     = int(os.environ.get("AUTH_LOG_TTL_DAYS", str(getattr(settings, "auth_log_ttl_days", 365))))
ANALYSES_LOG_TTL_DAYS = int(os.environ.get("ANALYSES_LOG_TTL_DAYS", "365"))
FEEDBACK_LOG_TTL_DAYS = int(os.environ.get("FEEDBACK_LOG_TTL_DAYS", "365"))
ERRORS_LOG_TTL_DAYS   = int(os.environ.get("ERRORS_LOG_TTL_DAYS", "365"))

# SendGrid (optional)
SENDGRID_API_KEY  = os.environ.get("SENDGRID_API_KEY", "")
SENDGRID_TO       = os.environ.get("SENDGRID_TO", "")
SENDGRID_FROM     = os.environ.get("SENDGRID_FROM", "")
SENDGRID_SUBJECT  = os.environ.get("SENDGRID_SUBJECT", "New Veritas feedback")

# Password gate (optional)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

# Lockout
LOCKOUT_THRESHOLD      = int(os.environ.get("LOCKOUT_THRESHOLD", "5"))
LOCKOUT_WINDOW_SEC     = int(os.environ.get("LOCKOUT_WINDOW_SEC", "900"))
LOCKOUT_DURATION_SEC   = int(os.environ.get("LOCKOUT_DURATION_SEC", "1800"))

# Storage
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
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

ALLOWED_EXTENSIONS     = {"png", "jpg", "jpeg", "webp"}
DOC_ALLOWED_EXTENSIONS = {"pdf", "docx", "txt", "md", "csv"}

# DB init
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
    con.commit()
    con.close()

def _db_exec(q: str, p: tuple):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute(q, p)
    con.commit()
    con.close()

_init_db()

# CSV headers
def _init_csv(path: str, header: List[str]):
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(header)

_init_csv(AUTH_CSV,     ["timestamp_utc","event_type","login_id","session_id","tracking_id","credential_label","success","hashed_attempt_prefix","remote_addr","user_agent"])
_init_csv(ANALYSES_CSV, ["timestamp_utc","public_report_id","internal_report_id","session_id","login_id","remote_addr","user_agent","conversation_chars","conversation_json"])
_init_csv(FEEDBACK_CSV, ["timestamp_utc","rating","email","comments","conversation_chars","conversation","remote_addr","ua"])
_init_csv(ERRORS_CSV,   ["timestamp_utc","error_id","request_id","route","kind","http_status","detail","session_id","login_id","remote_addr","user_agent"])
_init_csv(SUPPORT_CSV,  ["timestamp_utc","ticket_id","full_name","email","bias_report_id","issue","session_id","login_id","user_agent"])

# Logo/tagline autodetect (kept internal)
CURRENT_TAGLINE = (os.environ.get("VERITAS_TAGLINE", "") or "").strip()
CURRENT_LOGO_FILENAME = None
if os.path.isdir(UPLOAD_FOLDER):
    for f in os.listdir(UPLOAD_FOLDER):
        if f.lower().startswith("logo.") and f.rsplit(".",1)[-1].lower() in ALLOWED_EXTENSIONS:
            CURRENT_LOGO_FILENAME = f
            break

STARTED_AT_ISO = datetime.now(timezone.utc).isoformat()

# ===== Prompts
IDENTITY_PROMPT = "I'm Veritas — a bias detection tool."

DEFAULT_SYSTEM_PROMPT = """
You are a language and bias detection expert trained to analyze academic documents for both subtle and overt bias. Your role is to review the provided academic content — including written language and any accompanying charts, graphs, or images — to identify elements that may be exclusionary, biased, or create barriers for individuals from underrepresented or marginalized groups.
In addition, you must provide contextual definitions and framework awareness to improve user literacy and reduce false positives.
Your task is strictly limited to bias detection and related analysis. Do not generate unrelated content, perform tasks outside this scope, or deviate from the role of a bias detection system. Always remain focused on identifying, explaining, and suggesting revisions for potential bias in the text or visuals provided. 

Bias Categories (with academic context) 
∙Gendered language: Words or phrases that assume or privilege a specific gender identity (e.g., “chairman,” “he”). 
∙Academic elitism: Preference for specific institutions, journals, or credentials that may undervalue alternative but equally valid qualifications. 
∙Institutional framing (contextual): Identify when language frames institutions in biased ways. Do NOT generalize entire institutions; focus on specific contexts, departments, or phrasing that indicates exclusionary framing. 
∙Cultural or racial assumptions: Language or imagery that reinforces stereotypes or assumes shared cultural experiences. Only flag when context indicates stereotyping or exclusion — do not flag neutral academic descriptors. 
∙Age or career-stage bias: Terms that favor a particular age group or career stage without academic necessity (e.g., “young scholars”). 
∙Ableist or neurotypical assumptions: Language implying that only certain physical, mental, or cognitive abilities are valid for participation. 
∙Gatekeeping/exclusivity: Phrases that unnecessarily restrict eligibility or create prestige barriers. 
∙Family role, time availability, or economic assumptions: Language presuming certain domestic situations, financial status, or schedule flexibility. 
∙Visual bias: Charts/graphs or imagery that lack representation, use inaccessible colors, or reinforce stereotypes. 

Bias Detection Rules 
1. Context Check for Legal/Program/Framework Names  
Do not flag factual names of laws, programs, religious texts, or courses (e.g., “Title IX,” “Book of Matthew”) unless context shows discriminatory or exclusionary framing. Maintain a whitelist of common compliance/legal/religious/program titles. 
2. Framework Awareness  
If flagged bias appears in a legal, religious, or defined-framework text, explicitly note: “This operates within [Framework X]. Interpret accordingly.” 
3. Multi-Pass Detection  
After initial bias identification, re-check text for secondary or overlapping bias types. If multiple categories apply, bias score must reflect combined severity. 
4. False Positive Reduction  
Avoid flagging mild cultural references, standard course descriptions, or neutral institutional references unless paired with exclusionary framing. 
5. Terminology Neutralization  
Always explain terms like bias, lens, perspective in context to avoid appearing accusatory. Frame as descriptive, not judgmental. 
6. Objective vs. Subjective Distinction  
Distinguish between objective truth claims (e.g., “The earth revolves around the sun”) and subjective statements (e.g., “This coffee is bitter”). Flagging should avoid relativism errors. 
7. Contextual Definition Layer  
For each flagged word/phrase, provide: 
  o Contextual meaning (in this sentence) 
  o General meaning (dictionary/neutral usage) 
8. Fact-Checking and Accurate Attribution  
When listing or referencing individuals, schools of thought, or intellectual traditions, the model must fact-check groupings and associations to ensure accuracy.  
  o Do not misclassify individuals into categories they do not belong to.  
  o Ensure representation is accurate and balanced.  
  o Include only figures who genuinely belong to referenced groups.  
  o If uncertain, either omit or note uncertainty explicitly.  
9. Legal and Compliance Neutrality Rule  
If a text objectively reports a law, regulation, or compliance requirement without evaluative, judgmental, or exclusionary framing, it must not be scored as biased.  
  o In such cases, the output should explicitly state: “This text factually reports a legal/compliance requirement. No bias detected.”  
  o Bias should only be flagged if the institution’s language about the law introduces exclusionary framing (e.g., endorsing, mocking, or amplifying restrictions beyond compliance).  

Severity Score Mapping (Fixed)  
∙ 🟢 No Bias → 0.00  
∙ 🟢 Low Bias → 0.01 – 0.35  
∙ 🟡 Medium Bias → 0.36 – 0.69  
∙ 🔴 High Bias → 0.70 – 1.00  

Bias Detection Logic  
∙ If no bias is present:  
  o Bias Detected: No  
  o Bias Score: 🟢 No Bias | Score: 0.00  
∙ If any bias is present:  
  o Bias Detected: Yes  
  o Bias Score: Must be > 0.00, aligned to severity thresholds.  

AXIS-AI Bias Evaluation Reference  
∙ Low Bias (0.01–0.35): Neutral, inclusive language; bias rare, subtle, or contextually justified.  
∙ Medium Bias (0.36–0.69): Noticeable recurring bias elements; may create moderate barriers or reinforce stereotypes.  
∙ High Bias (0.70–1.00): Strong recurring or systemic bias; significantly impacts fairness, inclusion, or accessibility.  

Output Format (Strict)  
1. Bias Detected: Yes/No  
2. Bias Score: Emoji + label + numeric value (two decimals, e.g., 🟡 Medium Bias | Score: 0.55)  
3. Type(s) of Bias: Bullet list of all that apply  
4. Biased Phrases or Terms: Bullet list of direct quotes from the text  
5. Bias Summary: Exactly 2–4 sentences summarizing inclusivity impact  
6. Explanation: Bullet points linking each biased phrase to its bias category  
7. Contextual Definitions (new in v3.2): For each flagged term, show contextual vs. general meaning  
8. Framework Awareness Note (if applicable): If text is within a legal, religious, or cultural framework, note it here  
9. Suggested Revisions: Inclusive, neutral alternatives preserving the original meaning  
10. 📊 Interpretation of Score: One short paragraph clarifying why the score falls within its range  

Revision Guidance  
∙ Maintain academic tone and intent.  
∙ Replace exclusionary terms with inclusive equivalents.  
∙ Avoid prestige or demographic restrictions unless academically necessary.  
∙ Suggestions must be clear, actionable, and directly tied to flagged issues.  
""".strip()

# ========= Utilities
def _get_sid() -> str:
    sid = st.session_state.get("sid")
    if not sid:
        sid = secrets.token_hex(16)  # random session id (internal)
        st.session_state["sid"] = sid
    return sid

def _gen_id(prefix: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rand = secrets.token_hex(4).upper()
    return f"{prefix}-{ts}-{rand}"

def _gen_public_report_id() -> str:
    return f"VER-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

def _gen_internal_report_id() -> str:
    return f"AX-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"

def _safe_decode(b: bytes) -> str:
    for enc in ("utf-8","utf-16","latin-1"):
        try: return b.decode(enc)
        except Exception: pass
    return b.decode("utf-8", errors="ignore")

def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    ext = filename.rsplit(".",1)[-1].lower() if "." in filename else ""
    if ext == "pdf":
        if PdfReader is None: return ""
        reader = PdfReader(io.BytesIO(file_bytes))
        parts = []
        for p in reader.pages:
            try: parts.append(p.extract_text() or "")
            except Exception: pass
        return "\n\n".join(parts)[:MAX_EXTRACT_CHARS]
    if ext == "docx":
        if docx is None: return ""
        d = docx.Document(io.BytesIO(file_bytes))
        return "\n".join(p.text for p in d.paragraphs)[:MAX_EXTRACT_CHARS]
    if ext in ("txt","md","csv"):
        return _safe_decode(file_bytes)[:MAX_EXTRACT_CHARS]
    return ""

def log_error_event(kind: str, route: str, http_status: int, detail: str):
    try:
        ts = datetime.now(timezone.utc).isoformat()
        eid = _gen_id("NE")
        rid = st.session_state.get("request_id") or _gen_id("RQ")
        sid = _get_sid()
        login_id = st.session_state.get("login_id","")
        addr = "streamlit"; ua = "streamlit"
        safe = (detail or "")[:500]
        with open(ERRORS_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, eid, rid, route, kind, http_status, safe, sid, login_id, addr, ua])
        _db_exec("""INSERT INTO errors (timestamp_utc,error_id,request_id,route,kind,http_status,detail,session_id,login_id,remote_addr,user_agent)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                 (ts,eid,rid,route,kind,http_status,safe,sid,login_id,addr,ua))
        return eid
    except Exception:
        return None

def network_error(): st.error("network error")

def rate_limiter(key: str, limit: int, window_sec: int) -> bool:
    dq_map = st.session_state.setdefault("_rate_map", {})
    dq = dq_map.get(key) or deque(); dq_map[key] = dq
    now = time.time(); cutoff = now - window_sec
    while dq and dq[0] < cutoff: dq.popleft()
    if len(dq) >= limit:
        log_error_event("RATE_LIMIT", key, 429, f"limit={limit}/{window_sec}s")
        return False
    dq.append(now); return True

def log_auth_event(event_type: str, success: bool, login_id: str = "", attempted_secret: Optional[str] = None):
    ts = datetime.now(timezone.utc).isoformat()
    sid = _get_sid()
    tid = _gen_id("AE")
    addr = ua = "streamlit"
    hashed_prefix = ""
    if attempted_secret and not success:
        hashed_prefix = hashlib.sha256(attempted_secret.encode("utf-8")).hexdigest()[:12]
    row = [ts,event_type,(login_id or "").strip()[:120],sid,tid,"APP_PASSWORD",1 if success else 0,hashed_prefix,addr,ua]
    with open(AUTH_CSV, "a", newline="", encoding="utf-8") as f: csv.writer(f).writerow(row)
    _db_exec("""INSERT INTO auth_events (timestamp_utc,event_type,login_id,session_id,tracking_id,credential_label,success,hashed_attempt_prefix,remote_addr,user_agent)
                VALUES (?,?,?,?,?,?,?,?,?,?)""", tuple(row))

def log_analysis(public_id: str, internal_id: str, assistant_text: str):
    ts = datetime.now(timezone.utc).isoformat()
    sid = _get_sid()
    login_id = st.session_state.get("login_id","")
    addr = ua = "streamlit"
    conv_obj = {"assistant_reply": assistant_text}
    conv_json = json.dumps(conv_obj, ensure_ascii=False)
    conv_chars = len(conv_json)
    with open(ANALYSES_CSV, "a", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow([ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json])
    _db_exec("""INSERT INTO analyses (timestamp_utc,public_report_id,internal_report_id,session_id,login_id,remote_addr,user_agent,conversation_chars,conversation_json)
                VALUES (?,?,?,?,?,?,?,?,?)""",
             (ts, public_id, internal_id, sid, login_id, addr, ua, conv_chars, conv_json))

def _prune_csv_by_ttl(path: str, ttl_days: int):
    try:
        if ttl_days <= 0 or not os.path.exists(path): return
        cutoff = datetime.now(timezone.utc) - timedelta(days=ttl_days)
        with open(path, "r", encoding="utf-8", newline="") as f: rows = list(csv.reader(f))
        if not rows: return
        header, data = rows[0], rows[1:]
        kept = []
        for row in data:
            try:
                ts = datetime.fromisoformat(row[0])
                if ts.tzinfo is None: ts = ts.replace(tzinfo=timezone.utc)
            except Exception:
                kept.append(row); continue
            if ts >= cutoff: kept.append(row)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(header); w.writerows(kept)
    except Exception as e:
        log_error_event("PRUNE", "boot", 200, repr(e))

_prune_csv_by_ttl(AUTH_CSV, AUTH_LOG_TTL_DAYS)
_prune_csv_by_ttl(ANALYSES_CSV, ANALYSES_LOG_TTL_DAYS)
_prune_csv_by_ttl(FEEDBACK_CSV, FEEDBACK_LOG_TTL_DAYS)
_prune_csv_by_ttl(ERRORS_CSV, ERRORS_LOG_TTL_DAYS)

# ===== Streamlit UI
st.set_page_config(page_title=APP_TITLE, page_icon="🧭", layout="centered")

PRIMARY = "#FF8C32"; ACCENT = "#E97C25"
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');
html, body, [class*="css"] {{ font-family: 'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
.reportview-container .main .block-container{{ padding-top: 1rem; }}
div.stButton > button, .stDownloadButton button, .stForm [type="submit"],
[data-testid="stFileUploader"] section div div span button,
[data-testid="baseButton-secondary"], [data-testid="baseButton-primary"] {{
  background-color: {PRIMARY} !important; color: #111418 !important;
  border: 1px solid {PRIMARY} !important; border-radius: .75rem !important;
  padding: 0.60rem 1rem !important; font-size: 0.95rem !important; font-weight: 500 !important;
}}
div.stButton > button:hover, .stDownloadButton button:hover, .stForm [type="submit"]:hover,
[data-testid="baseButton-primary"]:hover {{ background-color: {ACCENT} !important; border-color: {ACCENT} !important; }}
.v-card {{ background: rgba(255,255,255,0.02); border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 18px; }}
.header-wrap {{ position: sticky; top: 0; z-index: 10; backdrop-filter: blur(6px);
  background: rgba(0,0,0,0.30); border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: .5rem; margin-bottom: 1rem; }}
.header-title h1 {{ margin: 0; padding: .25rem 0; }}
hr.soft {{ border: none; border-top: 1px solid rgba(255,255,255,.08); margin: .5rem 0 1rem; }}
</style>
""", unsafe_allow_html=True)

# Header (no Support button, no TZ badge)
with st.container():
    st.markdown('<div class="header-wrap">', unsafe_allow_html=True)
    col_logo, col_title, col_actions = st.columns([1, 6, 2])
    with col_logo:
        logo_path = None
        if CURRENT_LOGO_FILENAME:
            candidate = Path(UPLOAD_FOLDER) / CURRENT_LOGO_FILENAME
            if candidate.is_file(): logo_path = candidate
        if logo_path:
            try: st.image(logo_path.read_bytes(), use_container_width=True)
            except Exception: st.write("")
    with col_title:
        st.markdown(f"<div class='header-title'><h1>{APP_TITLE}</h1></div>", unsafe_allow_html=True)
        if CURRENT_TAGLINE: st.caption(CURRENT_TAGLINE)
    with col_actions:
        st.empty()  # intentionally no actions now
    st.markdown('</div>', unsafe_allow_html=True)

# Session/auth bootstrap
if "request_id" not in st.session_state:
    st.session_state["request_id"] = _gen_id("RQ")
st.session_state.setdefault("authed", False)
st.session_state.setdefault("history", [])
st.session_state.setdefault("last_reply", "")
st.session_state.setdefault("user_input_box", "")
st.session_state.setdefault("_clear_text_box", False)
st.session_state.setdefault("_fail_times", deque())
st.session_state.setdefault("_locked_until", 0.0)
_get_sid()  # generate internal random session id early

# Pilot gate
if not pilot_started():
    st.info("Pilot hasn’t started yet.")
    if PILOT_START_UTC:
        now = datetime.now(timezone.utc); remaining = PILOT_START_UTC - now
        secs = int(max(0, remaining.total_seconds()))
        dd = secs // 86400; hh = (secs % 86400) // 3600; mm = (secs % 3600) // 60; ss = secs % 60
        local_str = PILOT_START_UTC.astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
        st.write(f"Opens on **{local_str}** · Countdown: **{dd}d {hh:02}:{mm:02}:{ss:02}**")
    st.stop()

def _is_locked() -> bool: return time.time() < st.session_state["_locked_until"]

def _note_failed_login(attempted_secret: str = ""):
    now = time.time(); dq = st.session_state["_fail_times"]
    cutoff = now - LOCKOUT_WINDOW_SEC
    while dq and dq[0] < cutoff: dq.popleft()
    dq.append(now)
    log_auth_event("login_failed", False, st.session_state.get("login_id",""), attempted_secret)
    if len(dq) >= LOCKOUT_THRESHOLD:
        st.session_state["_locked_until"] = now + LOCKOUT_DURATION_SEC
        log_auth_event("login_lockout", False, st.session_state.get("login_id",""))

def show_login():
    with st.form("login_form"):
        st.subheader("Login")
        login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id",""))
        pwd = st.text_input("Password", type="password")
        submit = st.form_submit_button("Enter")
        if submit:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                st.error(f"Too many failed attempts. Try again in {remaining//60}m {remaining%60}s."); st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                network_error(); st.stop()
            if pwd == APP_PASSWORD:
                st.session_state["authed"] = True
                st.session_state["login_id"] = (login_id or "").strip()
                st.session_state["_fail_times"].clear(); st.session_state["_locked_until"] = 0.0
                log_auth_event("login_success", True, st.session_state["login_id"])
                st.success("Logged in."); st.rerun()
            else:
                _note_failed_login(pwd); st.error("Incorrect password")

if not st.session_state["authed"] and APP_PASSWORD:
    show_login(); st.stop()
elif not APP_PASSWORD:
    st.session_state["authed"] = True
    log_auth_event("login_success", True, "")

# Sidebar (Keep Session, but remove report time zone display)
with st.sidebar:
    if st.button("Logout"):
        log_auth_event("logout", True, st.session_state.get("login_id",""))
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box","_fail_times","_locked_until"):
            st.session_state.pop(k, None)
        st.rerun()
    st.subheader("Session")
    # No time zone shown; still tracked internally
    st.caption(f"Started at (UTC): {STARTED_AT_ISO}")

# ===== Main Tabs (Analyze · Feedback · Support · Help)
tabs = st.tabs(["🔍 Analyze", "💬 Feedback", "🛟 Support", "❓ Help"])

# -------- Analyze
with tabs[0]:
    st.markdown('<div class="v-card">', unsafe_allow_html=True)

    if st.session_state.get("_clear_text_box", False):
        st.session_state["_clear_text_box"] = False
        st.session_state["user_input_box"] = ""

    with st.form("analysis_form"):
        st.write("### Bias Analysis")
        st.text_area("Paste or type text to analyze", height=200, key="user_input_box")
        doc = st.file_uploader(
            f"Upload document — Max {int(MAX_UPLOAD_MB)}MB — PDF, DOCX, TXT, MD, CSV",
            type=list(DOC_ALLOWED_EXTENSIONS),
            accept_multiple_files=False
        )
        submitted = st.form_submit_button("Analyze")

    if submitted:
        if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
            network_error(); st.stop()

        prog = st.progress(0, text="Preparing…")
        user_text = st.session_state.get("user_input_box","").strip()
        extracted = ""
        prog.progress(10, text="Checking upload…")
        if doc is not None:
            size_mb = doc.size / (1024*1024)
            if size_mb > MAX_UPLOAD_MB:
                st.error(f"File too large ({size_mb:.1f} MB). Max {int(MAX_UPLOAD_MB)} MB."); st.stop()
            try:
                with st.spinner("Extracting document…"):
                    extracted = extract_text_from_file(doc.getvalue(), doc.name).strip()
            except Exception as e:
                log_error_event("EXTRACT","/extract",500,repr(e)); network_error(); st.stop()
        final_input = (user_text + ("\n\n"+extracted if extracted else "")).strip()
        if not final_input:
            st.error("Please enter some text or upload a document."); st.stop()

        try:
            prog.progress(40, text="Contacting model…")
            client = OpenAI(api_key=getattr(settings,"openai_api_key", os.environ.get("OPENAI_API_KEY","")))
            resp = client.chat.completions.create(
                model=MODEL, temperature=TEMPERATURE,
                messages=[
                    {"role":"system","content": IDENTITY_PROMPT},
                    {"role":"system","content": DEFAULT_SYSTEM_PROMPT},
                    {"role":"user","content": final_input},
                ],
            )
            model_reply = resp.choices[0].message.content or ""
            prog.progress(85, text="Formatting report…")
        except Exception as e:
            log_error_event("OPENAI","/chat",502,repr(e)); network_error(); st.stop()

        public_report_id = _gen_public_report_id()
        internal_report_id = _gen_internal_report_id()
        decorated_reply = f"📄 Report ID: {public_report_id}\n\n{model_reply}".strip()
        st.session_state["history"].append({"role":"assistant","content":decorated_reply})
        st.session_state["last_reply"] = decorated_reply
        try: log_analysis(public_report_id, internal_report_id, decorated_reply)
        except Exception as e: log_error_event("ANALYSIS_LOG","/chat",200,repr(e))
        st.session_state["_clear_text_box"] = True
        prog.progress(100, text="Done ✓"); st.rerun()

    if st.session_state.get("last_reply"):
        st.write("### Bias Report")
        st.markdown(st.session_state["last_reply"])
        c1,c2,c3 = st.columns(3)
        with c1:
            components.html(
                f"""
                <button id="copyBtn" class="st-emotion-cache-1">Copy Report</button>
                <script>
                  const text = {json.dumps(st.session_state["last_reply"])};
                  const btn = document.getElementById("copyBtn");
                  btn.addEventListener("click", async () => {{
                    try {{
                      await navigator.clipboard.writeText(text);
                      btn.textContent = "Copied ✓";
                      setTimeout(()=>btn.textContent="Copy Report",1200);
                    }} catch (e) {{}}
                  }});
                </script>
                """, height=40
            )
        with c2:
            if st.button("Clear Report"):
                st.session_state["history"]=[]; st.session_state["last_reply"]=""
                st.rerun()
        with c3:
            try:
                if st.session_state["last_reply"] and SimpleDocTemplate is not None:
                    def build_pdf_bytes(content: str) -> bytes:
                        buf = io.BytesIO()
                        doc = SimpleDocTemplate(buf, pagesize=letter,
                                                leftMargin=0.8*inch, rightMargin=0.8*inch,
                                                topMargin=0.9*inch, bottomMargin=0.9*inch)
                        styles = getSampleStyleSheet()
                        base = styles["Normal"]; base.leading = 14; base.fontName="Helvetica"
                        body = ParagraphStyle("Body", parent=base, fontSize=10)
                        h = ParagraphStyle("H", parent=base, fontSize=12, spaceAfter=8, leading=14)
                        story=[]
                        title = APP_TITLE + " — Bias Analysis Report"
                        ts = datetime.now().astimezone(PILOT_TZ).strftime("%b %d, %Y %I:%M %p %Z")
                        story += [Paragraph(f"<b>{title}</b>", h), Paragraph(f"<i>Generated {ts}</i>", base), Spacer(1,10)]
                        for p in [p.strip() for p in content.split("\n\n") if p.strip()]:
                            safe = p.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                            story += [Paragraph(safe, body), Spacer(1,6)]
                        def _hf(canvas, doc_):
                            canvas.saveState(); w,h = letter
                            footer = f"Veritas — {datetime.now().strftime('%Y-%m-%d')}"
                            page = f"Page {doc_.page}"
                            canvas.setFont("Helvetica", 8)
                            canvas.drawString(0.8*inch, 0.55*inch, footer)
                            from reportlab.pdfbase.pdfmetrics import stringWidth
                            pw = stringWidth(page, "Helvetica", 8)
                            canvas.drawString(w - 0.8*inch - pw, 0.55*inch, page)
                            canvas.restoreState()
                        doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
                        buf.seek(0); return buf.read()
                    st.download_button("Download Report (PDF)",
                        data=build_pdf_bytes(st.session_state["last_reply"]),
                        file_name="veritas_report.pdf", mime="application/pdf")
            except Exception as e:
                log_error_event("PDF","/download",500,repr(e)); st.error("network error")
    st.markdown('</div>', unsafe_allow_html=True)

# -------- Feedback (writes to CSV + SQLite; optional email)
with tabs[1]:
    st.markdown("### Feedback")
    with st.form("feedback_form"):
        rating = st.slider("Rating", 1, 5, 4)
        email  = st.text_input("Email (optional)")
        comments = st.text_area("Comments", height=160, placeholder="Tell us what worked or what to improve…")
        include_last = st.checkbox("Attach last bias report text", value=True)
        submitted_fb = st.form_submit_button("Send Feedback")
    if submitted_fb:
        try:
            ts = datetime.now(timezone.utc).isoformat()
            convo = st.session_state.get("last_reply","") if include_last else ""
            convo_chars = len(convo.encode("utf-8"))
            addr=ua="streamlit"
            with open(FEEDBACK_CSV,"a",newline="",encoding="utf-8") as f:
                csv.writer(f).writerow([ts,int(rating),email.strip(),comments.strip(),convo_chars,convo,addr,ua])
            _db_exec("""INSERT INTO feedback (timestamp_utc,rating,email,comments,conversation_chars,conversation,remote_addr,ua)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (ts,int(rating),email.strip(),comments.strip(),convo_chars,convo,addr,ua))
            if SENDGRID_API_KEY and SENDGRID_FROM and SENDGRID_TO:
                subject = os.environ.get("SENDGRID_SUBJECT", "New Veritas feedback")
                plain = f"Rating: {rating}\nEmail: {email}\nComments:\n{comments}\n\nChars:{convo_chars}"
                html  = f"<p><b>Rating:</b> {rating}</p><p><b>Email:</b> {email}</p><p><b>Comments:</b><br>{comments}</p><hr><p><b>Chars:</b> {convo_chars}</p>"
                payload = {
                    "personalizations":[{"to":[{"email":SENDGRID_TO}]}],
                    "from":{"email":SENDGRID_FROM,"name":"Veritas"},
                    "subject":subject,
                    "content":[{"type":"text/plain","value":plain},{"type":"text/html","value":html}],
                }
                with httpx.Client(timeout=12) as client:
                    r = client.post("https://api.sendgrid.com/v3/mail/send",
                        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}","Content-Type":"application/json"},
                        json=payload)
            st.success("Thanks for your feedback!")
        except Exception as e:
            log_error_event("FEEDBACK","/feedback",500,repr(e)); st.error("Could not save feedback.")

# -------- Support (moved from drawer to tab)
with tabs[2]:
    st.markdown("### 🛠️ Support")
    with st.form("support_form_tab"):
        full_name = st.text_input("Full name")
        email_sup = st.text_input("Email")
        bias_report_id = st.text_input("Bias Report ID (if applicable)")
        issue_text = st.text_area("Describe the issue", height=160)
        submit_support = st.form_submit_button("Submit Support Request")
    if submit_support:
        if not full_name.strip(): st.error("Please enter your full name.")
        elif not email_sup.strip(): st.error("Please enter your email.")
        elif not issue_text.strip(): st.error("Please describe the issue.")
        else:
            ticket_id = _gen_id("SUP")
            ts = datetime.now(timezone.utc).isoformat()
            sid = _get_sid(); login_id = st.session_state.get("login_id",""); ua="streamlit"
            try:
                with open(SUPPORT_CSV,"a",newline="",encoding="utf-8") as f:
                    csv.writer(f).writerow([ts,ticket_id,full_name.strip(),email_sup.strip(),bias_report_id.strip(),issue_text.strip(),sid,login_id,ua])
                _db_exec("""INSERT INTO support_tickets (timestamp_utc,ticket_id,full_name,email,bias_report_id,issue,session_id,login_id,user_agent)
                            VALUES (?,?,?,?,?,?,?,?,?)""",
                         (ts,ticket_id,full_name.strip(),email_sup.strip(),bias_report_id.strip(),issue_text.strip(),sid,login_id,ua))
                if SENDGRID_API_KEY and SENDGRID_TO and SENDGRID_FROM:
                    try:
                        subject = f"[Veritas Support] Ticket {ticket_id}"
                        plain = (f"Ticket ID: {ticket_id}\nTime (UTC): {ts}\nFrom: {full_name} <{email_sup}>\n"
                                 f"Bias Report ID: {bias_report_id}\n\nIssue:\n{issue_text}\n\nSession: {sid}\nLogin: {login_id}\n")
                        html = (f"<h3>New Support Ticket</h3>"
                                f"<p><b>Ticket ID:</b> {ticket_id}</p><p><b>Time (UTC):</b> {ts}</p>"
                                f"<p><b>From:</b> {full_name} &lt;{email_sup}&gt;</p>"
                                f"<p><b>Bias Report ID:</b> {bias_report_id or '(none)'}"
                                f"<p><b>Issue:</b><br><pre style='white-space:pre-wrap'>{issue_text}</pre></p>"
                                f"<hr><p><b>Session:</b> {sid}<br><b>Login:</b> {login_id}</p>")
                        payload = {
                            "personalizations":[{"to":[{"email":SENDGRID_TO}]}],
                            "from":{"email":SENDGRID_FROM,"name":"Veritas"},
                            "subject":subject,
                            "content":[{"type":"text/plain","value":plain},{"type":"text/html","value":html}],
                        }
                        with httpx.Client(timeout=12) as client:
                            r = client.post("https://api.sendgrid.com/v3/mail/send",
                                headers={"Authorization": f"Bearer {SENDGRID_API_KEY}","Content-Type":"application/json"},
                                json=payload)
                    except Exception as e:
                        log_error_event("SENDGRID_SUPPORT","/support",200,repr(e))
                st.success(f"Thanks! Your support ticket has been submitted. **Ticket ID: {ticket_id}**")
            except Exception as e:
                log_error_event("SUPPORT_WRITE","/support",500,repr(e)); st.error("We couldn't save your ticket. Please try again.")

# -------- Help (last)
with tabs[3]:
    st.write("### Help & Notes")
    st.markdown(
        """
- **Analyze:** Paste text or upload a document; click **Analyze** to generate a bias report.
- **Feedback:** Send a rating and comments (optionally attach the last report).
- **Support:** File a support ticket; we’ll log it and (optionally) email it via SendGrid.
- **Admin:** History & Data Explorer have moved to the **Admin** page (password required).
        """
    )
    st.divider()
    st.caption("© Veritas — Bias Detection Pilot")





