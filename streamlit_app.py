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
# - Pre-login screen lets user choose "User" or "Admin" sign-in (label hidden).
# - Admin tab only appears when authenticated as admin.
# - No admin login UI after login for regular users.
# - Cancel buttons removed on login forms.
# - Admin sessions bypass the Privacy/Terms acknowledgment gate.

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

# Hard-coded allowlist of admin emails (empty set => allow any email if password matches)
ADMIN_EMAILS = {"a.parra@axislabs.ai", "d.pineau@axislabs.ai"}

# Optional: also accept a comma-separated env var ADMIN_EMAILS to extend/override
_raw = os.environ.get("ADMIN_EMAILS", "")
if _raw:
    ADMIN_EMAILS |= {e.strip().lower() for e in _raw.split(",") if e.strip()}
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
    # ---- Pilot end window (lock after this time) ----
PILOT_END_AT = os.environ.get("PILOT_END_AT", "")
PILOT_END_UTC = _parse_pilot_start_to_utc(PILOT_END_AT)  # reuse same parser

def pilot_active() -> bool:
    """Return True if current time is between start and end window."""
    now = datetime.now(timezone.utc)
    if PILOT_START_UTC and now < PILOT_START_UTC:
        return False
    if PILOT_END_UTC and now > PILOT_END_UTC:
        return False
    return True

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
Veritas Schema v3.1 establishes a unified, compliance-ready framework for analyzing bias 
across all industries. It integrates the structural logic of Veritas v3.3 with enhanced security 
and typological precision based on the following embedded sources:​
[Security Protocols Embedded into Schema.pdf §III–V],​
[Bias, Misinformation Patterns, & Reasoning Fallacies Typology.pdf §II–IV],​
and [Veritas Legacy User Experience Analysis.docx §I–III]. 
Step 1 — Safety First 
Overview 
Before any text analysis, Veritas must perform pre-screening for sensitive or illegal 
content.​
This protocol draws from the AXIS Security Protocol Handbook § IV (Safety 
Messages) and is mandatory for all deployments. 
Veritas must apply a two-tier distinction process — separating legitimate discussion or 
citation from self-referential or criminal intent.​
If content is flagged at Tier 2 as genuinely unsafe or unlawful, analysis stops immediately 
and returns the prescribed safety message only. 
 
I. Contextual Safety Distinction Layer (CSDL) 
Purpose: Prevent false positives when the text references sensitive or criminal topics in 
an academic, journalistic, analytical, or legal context. 
Detection Logic: 
Tier 
Condition 
Action 
 
Tier 
Condition 
Action 
Tier 1 – Context 
Recognition 
Text describes, critiques, or reports on 
self-harm, violence, or illegal activity 
from a third-person or research 
perspective. 
Proceed with normal Veritas 
analysis. No safety stop. ​
Example: “A 2021 study 
examined suicide prevention 
programs in universities.” 
Tier 2 – Self-
Referential or 
Action-Oriented 
Risk 
Text includes first-person or 
imperative phrasing implying intent, 
planning, or direct endorsement of 
harm or illegality. 
Trigger immediate Safety 
Stop. Output only the 
prescribed safety message. ​
Example: “I want to hurt 
myself.” / “I plan to 
attack…” 
Heuristic Markers: 
∙Pronoun context (“I,” “we,” “myself”) + action verbs = Tier 2 risk. 
∙Neutral reporting verbs (“studied,” “reported,” “analyzed”) + third-party subjects 
= Tier 1 safe. 
∙Presence of scholarly or media attribution (citations, “according to,” “in a study,” 
“researchers found”) → Tier 1 safe. 
(Cited: AXIS Security Protocols § IV and § III.5; Veritas Schema § I Safety Screening 
Addendum) 
 
II. Prescribed Safety Messages (Tier 2 Trigger Only) 
If Tier 2 conditions are met, analysis halts and Veritas outputs only one of the following: 
∙Self-harm / suicide:​
⚠️ “If you are in crisis or thinking about suicide, please call or text 988 to 
connect with the Suicide & Crisis Lifeline, or seek help from a qualified 
professional immediately. Per Safety Rule, analysis stops here.” 
∙Violence / terrorism:​
⚠️ “This text contains a credible threat. For safety and legal compliance, analysis 
stops here.” 
∙Child exploitation:​
⚠️ “This text references illegal child exploitation material. Analysis stops here.” 
∙Illegal activities:​
⚠️ “This text requests instructions or facilitation of illegal acts. Analysis stops 
here.” 
(Cited: AXIS Security Protocols § IV.1–4) 
 
III. Academic / Media Protection Clause 
Veritas must never flag or halt analysis solely because the text contains sensitive topics 
within an educational, policy, or news framework.​
Examples that must not trigger a safety stop: 
∙“A documentary on extremist rhetoric analyzed online recruitment tactics.” 
∙“The article described a court case involving financial fraud.” 
∙“Researchers discussed suicide prevention methods.” 
Only self-referential or instructional intent qualifies for a safety stop.​
Veritas’ decision engine must verify source tone, grammatical person, and narrative 
role before applying Tier 2 rules. 
 
IV. Reflection Continuity (Prism Alignment) 
If Veritas invokes a Safety Stop, The Prism inherits the same logic and outputs only: 
“Veritas triggered a safety rule. This universe has ended — I cannot reflect further.” 
If Veritas proceeds under Tier 1 safe context, Prism may be interpreted normally. 
(Cited: AXIS Security Protocols § IV and § V; Veritas–Prism Co-Compliance Pipeline) 
Step 2 — Pre-Input Settings 
​
Veritas uses a 3×3 tone-length matrix to ensure precision and interpretive consistency. Both 
Veritas and Prism are governed by shared protocol rules (Security Protocols §III.4). The 
system auto-locks the tone and explanation pair to avoid manipulation or reinterpretation 
across systems.​
 
 
Tone / Length 
Short 
Medium 
Comprehensive 
🟣 Academic 
Concise scholarly 
clarity 
Structured 
contextual analysis 
Full academic 
synthesis with 
citations 
🟠 Technical 
Data-driven 
summary 
Methodological 
explanation 
Full procedural 
model 
🔷 Simple 
Plain-language 
takeaway 
Conversational yet 
clear 
Accessible full 
breakdown without 
jargon 
(Cited: Security Protocols §III.4, Veritas UX §II Trends on Clarity & Accessibility) 
Step 3 — Schema Fields 
​
Each Veritas report must follow this schema structure:​
1. Fact — Empirical, uncontested statements.​
2. Bias — Only if present; aligned with recognized bias categories (see Bias Typology §II).​
3. Explanation — Clarify detected issues per tone-length matrix.​
4. Revision — Rewrite text inclusively, factually, and logically. 
Step 4 — Nothing Flagged Rule 
​
If no bias is detected, Veritas must output exactly:​
“No bias detected.”​
No additional commentary, schema fields, or visualizations are permitted. (Cited: Security 
Protocols §III.1) 
Step 5 — Integrated Security Compliance 
​
Both Veritas and Prism must comply with the AXIS Security Protocol Handbook, Version 1.​
These systems act as co-equal entities under the shared pipeline standard (Security 
Protocols §II–III). ​
Each is bound to recognize, enforce, and cross-audit:​
• Shared refusal templates (Security §II.1)​
• Audit logging (Security §II.2)​
• Rate-limiting (Security §II.3)​
• Cross-contamination prevention (Security §II.5)​
(Cited: AXIS Security Handbook §II–IV) 
Step 6 — Bias Typology Integration 
​
Bias categories align with overarching bias frameworks (Bias Typology §II). Example 
mappings:​
- Gendered Language → Identity Bias​
- Institutional Bias → Systemic Bias​
- Age Bias → Stereotyping Bias​
- Ableist/Neurotypical Assumptions → Ability Bias​
- Cultural/Racial Assumptions → Stereotyping Bias​
- Economic/Class Bias → Structural Bias​
- Gatekeeping/Exclusivity → Selection Bias​
- Visual/Representation Bias → Cultural Bias​
- False Balance → Media Bias
"""
STRICT_OUTPUT_TEMPLATE = """ 
1. Fact:
- <empirical or uncontested statement(s) extracted from text>

2. Bias:
- Detected: <Yes/No>
- Type(s): <bias type(s) if present, aligned with Bias Typology Section II>
- Example(s): "<biased phrase 1>", "<biased phrase 2>"

3. Explanation:
<Clarify detected issues per tone-length matrix.>

4. Revision:
<Rewrite the entire text directly and completely.
Produce a single, polished version that is inclusive, factual, and logically sound
while preserving the author's original intent and tone.
All previously detected bias, misinformation patterns, and reasoning fallacies
must be corrected, rephrased, or removed entirely.
Do NOT explain how to revise; output only the fully revised text.>
"""

# ===== Enforcement Helpers (Schema V3.2a & Safety Compliance) =====
import re

SECTION_REGEXES = [
    r"^\s*(?:1\.\s*)?Fact:",
    r"^\s*(?:2\.\s*)?Bias:",
    r"^\s*(?:3\.\s*)?Explanation:",
    r"^\s*(?:4\.\s*)?Revision:",
]

def _looks_strict(md: str) -> bool:
    """
    Verify if the model output matches the strict Veritas schema or a valid safety message.
    """
    text = (md or "").strip()

    if re.fullmatch(r"No bias detected\.", text, flags=re.IGNORECASE):
        return True
    safety_patterns = [
        r"If you are in crisis or thinking about suicide, please call or text 988",
        r"This text contains a credible threat",
        r"This text references illegal child exploitation material",
        r"This text requests instructions or facilitation of illegal acts",
        r"This text contains a request for sensitive credentials or security keys",
    ]
    for pattern in safety_patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            return True
    for rx in SECTION_REGEXES:
        if re.search(rx, text, flags=re.MULTILINE) is None:
            return False
    return True


def _build_user_instruction(input_text: str) -> str:
    """
    Build the Veritas analysis instruction prompt for the model.
    """
    return f"""You are Veritas, a factual analysis and correction model.
Analyze the TEXT below strictly following the four-section schema:
1. Fact
2. Bias
3. Explanation
4. Revision

Output only those four numbered sections — nothing else.
Do NOT include any headers such as "=== OUTPUT TEMPLATE (copy exactly) ===" or explanatory text.
Each section must appear once and in the same order.

For the Revision section, rewrite the entire passage completely and directly,
producing a single polished version that is inclusive, factual, and logically sound,
while preserving the author's original intent and tone.
All previously detected bias must be corrected, rephrased, or removed.
Do NOT explain how to revise; output only the fully rewritten text.

{STRICT_OUTPUT_TEMPLATE}

=== TEXT TO ANALYZE (verbatim) ===
{input_text}
"""
# ===== Veritas Local Safety Enforcement (Tier 1 & Tier 2) =====
def _run_safety_precheck(user_text: str) -> str | None:
    """
    Local Contextual Safety Distinction Layer (CSDL)
    Enforces Tier 1 vs Tier 2 security before model execution.
    Returns a Tier 2 safety message if triggered; otherwise None.
    (Cited: AXIS Security Protocol Handbook Section IV; Veritas Schema Sections I–II)
    """
    text = user_text.strip().lower()


    # --- Tier 2: Self-harm / suicide intent ---
    if re.search(r"\b(i\s*(want|plan|intend|am\s*going)\s*to\s*(kill|harm|hurt)\s*(myself|me)\b)", text):
        return (
            "⚠️ If you are in crisis or thinking about suicide, please call or text 988 to connect with the "
            "Suicide & Crisis Lifeline, or seek help from a qualified professional immediately. "
            "Per Safety Rule, analysis stops here."
        )

    # --- Tier 2: Violence or terrorism planning ---
    if re.search(r"\b(i\s*(plan|intend|will|want)\s*to\s*(attack|shoot|bomb|kill|harm)\b)", text):
        return (
            "⚠️ This text contains a credible threat. "
            "For safety and legal compliance, analysis stops here."
        )

    # --- Tier 2: Child exploitation / illegal material ---
    if re.search(r"child\s*(porn|sexual|exploitation|abuse)", text):
        return (
            "⚠️ This text references illegal child-exploitation material. "
            "Analysis stops here."
        )

    # --- Tier 2: Requests for illegal instructions or acts ---
    if re.search(
        r"(how\s*to\s*(make|build|create)\s*(a\s*bomb|explosive|weapon)|buy\s*drugs|fake\s*id|hack\s*(a|into)|"
        r"access\s*unauthorized\s*(system|server|database)|obtain\s*illegal)",
        text,
    ):
        return (
            "⚠️ This text requests or promotes illegal activity. "
            "For safety and legal compliance, analysis stops here."
        )

    # --- Tier 2: Sensitive credential or data-security requests ---
    cred_pattern = r"api\s*key|access\s*token|password|secret\s*key|credentials?|private\s*key"
    if re.search(cred_pattern, text):
        tier2_markers = [
            r"\b(send|give|share|show|provide|need|reveal|use)\b",
            r"\b(my|your|the)\s+(api\s*key|access\s*token|password|credentials?)\b",
            r"\b(can|could|will|would|please)\s+(you|u)\s*(share|send|show|give)\b",
        ]
        for marker in tier2_markers:
            if re.search(marker, text):
                return (
                    "⚠️ This text contains a request for sensitive credentials or security keys. "
                    "For safety and legal compliance under AXIS Security Protocol Section IV.6, analysis stops here."
                )
        return None

    # --- Tier 1: Safe academic / third-person / analytic contexts ---
    academic_markers = [
        r"study\s*(found|examined|analyzed)",
        r"researchers?\s*(reported|studied)",
        r"according\s*to",
        r"article\s*(discussed|described)",
        r"court\s*case",
        r"policy\s*analysis",
    ]
    for marker in academic_markers:
        if re.search(marker, text):
            return None  # Tier 1 → safe to proceed

    # Default: no Tier 2 trigger detected → proceed normally
    return None

# --- Prompt Injection / Disclosure Detection (AXIS Security §IV.7) ---
def _detect_prompt_injection(text: str) -> bool:
    """
    Detects prompt-injection or system-prompt disclosure attempts.
    Triggers on any input requesting to reveal internal prompts, schemas, or instructions.
    """
    lowered = text.lower().strip()
    patterns = [
        r"\b(show|display|print|reveal|send|give|share)\b.*\b(prompt|schema|system|instructions?|rules?)\b",
        r"\bwhat\s+is\s+(your|the)\s+(prompt|system|schema)\b",
        r"\b(ignore|bypass)\s+(all\s+)?(previous|safety|security)\s+instructions\b",
        r"\b(i\s+want\s+to\s+see\s+(your|the)\s+(prompt|schema|system))\b",
    ]
    for pattern in patterns:
        if re.search(pattern, lowered):
            return True
    return False

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
  background-color: {PRIMARY} !important;
  color: #111418 !important;
  border: 1px solid {PRIMARY} !important;
  border-radius: .75rem !important;
  box-shadow: none !important;
  padding: 0.60rem 1rem !important;
  font-size: 0.95rem !important;
  font-weight: 500 !important;
}}

.stForm button[type="submit"],
.stForm [data-testid="baseButton-primary"],
.stForm [data-testid="baseButton-secondary"] {{
  white-space: nowrap !important;
  word-break: normal !important;
  overflow: visible !important;
  width: auto !important;
  min-width: 180px !important;
  height: auto !important;
  display: inline-flex !important;
  align-items: center !important;
  justify-content: center !important;
}}

/* === Veritas Action Buttons === */
.stForm button[type="submit"] {{
  text-transform: uppercase !important;
  letter-spacing: 0.5px !important;
}}
.stForm button[type="submit"]:first-child {{
  background: linear-gradient(90deg, #ff8c32, #e97c25) !important;
  color: #111418 !important;
}}
.stForm button[type="submit"]:nth-child(2) {{
  background: rgba(255,255,255,0.08) !important;
  border: 1px solid rgba(255,255,255,0.25) !important;
  color: #fff !important;
}}

/* --- Hide Streamlit top-right toolbar (⋮), GitHub/viewer badges, and deploy buttons --- */
.stApp [data-testid="stToolbar"] {{ visibility: hidden !important; height: 0 !important; }}
.stApp [data-testid="stToolbar"] * {{ display: none !important; }}

/* Legacy/aux hooks Streamlit sometimes uses */
#MainMenu {{ visibility: hidden !important; }}
footer {{ visibility: hidden !important; }}
a.viewerBadge_link__1S137 {{ display: none !important; }}
.stDeployButton, [data-testid="stDeployButton"] {{ display: none !important; }}

/* Hide any “View source on GitHub” style header buttons if present */
header [data-testid="baseButton-headerNoPadding"],
header a[href*="github.com"] {{
  display: none !important;
}}
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

# ====== Acknowledgment Gate (pre-UI; admins bypass) ======
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
    if st.session_state.get("ack_ok", False):
        return
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

    # Hidden-label toggle between user/admin
    auth_choice = st.radio(
        label="",
        options=["User", "Admin"],
        index=(0 if st.session_state.get("auth_view", "user") == "user" else 1),
        horizontal=True,
        label_visibility="collapsed"
    )

    st.session_state["auth_view"] = "admin" if auth_choice == "Admin" else "user"

    if st.session_state["auth_view"] == "user":
        # ---- Normal User Login ----
        with st.form("login_form_user"):
            login_id = st.text_input("Login ID (optional)", value=st.session_state.get("login_id", ""))
            pwd = st.text_input("Password", type="password")
            submit = st.form_submit_button("Enter")

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
            submit_admin = st.form_submit_button("Admin Enter")

        if submit_admin:
            if _is_locked():
                remaining = int(st.session_state["_locked_until"] - time.time())
                mins = max(0, remaining // 60); secs = max(0, remaining % 60)
                st.error(f"Too many failed attempts. Try again in {mins}m {secs}s.")
                st.stop()
            if not rate_limiter("login", RATE_LIMIT_LOGIN, RATE_LIMIT_WINDOW_SEC):
                st.error("network error"); st.stop()

            # Validate admin credentials (optional email allow-list)
            email_ok = (not ADMIN_EMAILS) or (admin_email.strip().lower() in ADMIN_EMAILS)
            if email_ok and (admin_pwd == ADMIN_PASSWORD):
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

# --- EARLY Privacy/Terms gate (pre-UI), admins bypass ---
if not st.session_state.get("is_admin", False):
    if not st.session_state.get("ack_ok", False):
        require_acknowledgment()
        st.stop()  # Prevent any UI from rendering until acknowledged

# ====== Sidebar ======
with st.sidebar:
    st.markdown(f"<h2 style='margin:.25rem 0 .75rem 0;'>{APP_TITLE}</h2>", unsafe_allow_html=True)
    if st.button("Logout"):
        log_auth_event("logout", True, login_id=st.session_state.get("login_id", ""), credential_label="APP_PASSWORD")
        for k in ("authed","history","last_reply","login_id","user_input_box","_clear_text_box",
                  "_fail_times","_locked_until","show_support","is_admin","ack_ok","auth_view"):
            st.session_state.pop(k, None)
        _safe_rerun()

# ================= Tabs =================
tab_names = ["🔍 Analyze", "💬 Feedback", "🛟 Support", "❓ Help"]
# Only reveal Admin tab if authenticated as admin
if st.session_state.get("is_admin", False):
    tab_names.append("🛡️ Admin")
tabs = st.tabs(tab_names)

# -------------------- Analyze Tab --------------------
with tabs[0]:
    # st.markdown('<div class="v-card" id="analyze-card">', unsafe_allow_html=True)

    if st.session_state.get("_clear_text_box", False):
        st.session_state["_clear_text_box"] = False
        st.session_state["user_input_box"] = ""

    with st.form("analysis_form"):
        st.markdown("""
            <h3 style="margin-bottom:0.25rem;">Veritas Analysis</h3>
            <p style="font-size:0.95rem; opacity:0.85; margin-top:0;">
                Bias, Misinformation, and Reasoning Fallacy Detection
            </p>
        """, unsafe_allow_html=True)
        st.text_area(
            "Paste or type text to analyze",
            height=200,
            key="user_input_box",
            help="Your pasted content is used for analysis but won’t be printed below—only the Veritas report appears."
        )

        doc = st.file_uploader(
            f"Upload document (drag & drop) — Max {int(MAX_UPLOAD_MB)}MB — Types: PDF, DOCX, TXT, MD, CSV",
            type=list(DOC_ALLOWED_EXTENSIONS),
            accept_multiple_files=False,
            key=f"doc_uploader_{st.session_state['doc_uploader_key']}"  # NEW: dynamic key so we can reset on New Analysis
        )

        bcol1, bcol2, _spacer = st.columns([2,2,6])
        with bcol1:
            submitted = st.form_submit_button("Engage Veritas")
        with bcol2:
            new_analysis = st.form_submit_button("Reset Canvas")

    # NEW: safer reset handler for New Analysis
    if 'new_analysis' in locals() and new_analysis:
        # Do not write directly to the text-area's key here. Use the clear flag, which is honored above.
        st.session_state["_clear_text_box"] = True
        st.session_state["last_reply"] = ""
        st.session_state["history"] = []
        # Force the file_uploader to remount with a fresh key (clears the selected file)
        st.session_state["doc_uploader_key"] += 1
        _safe_rerun()

    # --- Handle Veritas Analysis only when submitted ---
if submitted:
    # --- Detect if this is a Red Team test ---
    redteam_flag = 0
    user_login = st.session_state.get("login_id", "").lower()
    if "redteam" in user_login or "tester" in user_login:
        redteam_flag = 1

    if not rate_limiter("chat", RATE_LIMIT_CHAT, RATE_LIMIT_WINDOW_SEC):
        st.error("network error")
        st.stop()

    try:
        prog = st.progress(0, text="Preparing…")
    except TypeError:
        prog = st.progress(0)

    user_text = st.session_state.get("user_input_box", "").strip()
    extracted = ""
    try:
        prog.progress(10)
    except Exception:
        pass

    if doc is not None:
        size_mb = doc.size / (1024 * 1024)
        if size_mb > MAX_UPLOAD_MB:
            st.error(f"File too large ({size_mb:.1f} MB). Max {int(MAX_UPLOAD_MB)} MB.")
            st.stop()
        try:
            with st.spinner("Extracting document…"):
                def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                    if ext == "pdf":
                        if PdfReader is None: return ""
                        reader = PdfReader(io.BytesIO(file_bytes))
                        parts = [page.extract_text() or "" for page in reader.pages]
                        return "\n\n".join(parts)[:MAX_EXTRACT_CHARS]
                    elif ext == "docx":
                        if docx is None: return ""
                        buf = io.BytesIO(file_bytes)
                        doc_obj = docx.Document(buf)
                        text = "\n".join(p.text for p in doc_obj.paragraphs)
                        return text[:MAX_EXTRACT_CHARS]
                    elif ext in ("txt", "md", "csv"):
                        return file_bytes.decode("utf-8", errors="ignore")[:MAX_EXTRACT_CHARS]
                    return ""
                extracted = (extract_text_from_file(doc.getvalue(), doc.name) or "").strip()
        except Exception as e:
            log_error_event("EXTRACT", "/extract", 500, repr(e))
            st.error("network error")
            st.stop()

    # ✅ Build combined input only during submit
    final_input = (user_text + ("\n\n" + extracted if extracted else "")).strip()

    if not final_input:
        st.error("Please enter some text or upload a document.")
        st.stop()

    api_key = getattr(settings, "openai_api_key", os.environ.get("OPENAI_API_KEY", ""))
    if not api_key:
        st.error("Missing OpenAI API key. Set OPENAI_API_KEY.")
        st.stop()

    # --- Tier-1 / Tier-2 Local Safety Enforcement ---
    safety_message = _run_safety_precheck(final_input)
    if safety_message:
        st.markdown(safety_message)
        st.stop()

    # --- Prompt Injection / Disclosure Detection ---
    if _detect_prompt_injection(final_input):
        log_error_event("PROMPT_INJECTION", "/analyze", 403, "Prompt disclosure attempt blocked")
        st.markdown("""
        <div style="background-color:#7a0000;color:white;padding:1rem;border-radius:10px;font-weight:600;text-align:center;">
        ⚠️ <strong>Disclosure Attempt Blocked under AXIS Security §IV.7</strong><br>
        Veritas has detected an attempt to reveal internal schema or prompt logic.<br>
        Action logged; analysis terminated.
        </div>
        """, unsafe_allow_html=True)
        st.stop()

    # --- Proceed with Veritas analysis ---
    user_instruction = _build_user_instruction(final_input)
    try:
        prog.progress(40, text="Contacting model…")
    except Exception:
        prog.progress(40)

    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=MODEL,
        temperature=ANALYSIS_TEMPERATURE,
        messages=[
            {"role": "system", "content": IDENTITY_PROMPT},
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": user_instruction},
        ],
    )

    try:
        prog.progress(70, text="Processing model response…")
        final_report = resp.choices[0].message.content.strip()
        closing_line = (
            "This analysis has identified bias, misinformation patterns, and reasoning fallacies "
            "in the text provided. If you have any further questions or need additional analysis, "
            "feel free to ask The Prism."
        )
        if "feel free to ask The Prism" not in final_report:
            final_report = final_report.rstrip() + "\n\n" + closing_line

        if not _looks_strict(final_report):
            log_error_event("SCHEMA_MISMATCH", "/analyze", 422, "Non-compliant schema output")
            st.error("Veritas produced a non-compliant output. Please retry.")
            st.stop()

        public_id = _gen_public_report_id()
        internal_id = _gen_internal_report_id()
        log_analysis(public_id, internal_id, final_report)

        # --- Flag Red Team input in DB if applicable ---
        try:
            con = sqlite3.connect(DB_PATH)
            cur = con.cursor()
            cur.execute(
                "UPDATE analyses SET redteam_flag=? WHERE internal_report_id=?",
                (redteam_flag, internal_id)
            )
            con.commit()
            con.close()
        except Exception as e:
            log_error_event("REDTEAM_FLAG", "/analyze", 500, repr(e))

        prog.progress(100, text="Analysis complete ✓")
        st.success(f"✅ Report generated — ID: {public_id}")
        st.markdown(final_report)
        st.session_state["last_reply"] = final_report
        st.session_state["history"].append({"role": "assistant", "content": final_report})

    except Exception as e:
        log_error_event("MODEL_RESPONSE", "/analyze", 500, repr(e))
        st.error("⚠️ There was an issue retrieving the Veritas report.")
        st.stop()

else:
    st.caption("Paste text or upload a document, then click **Engage Veritas**.")
    
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
            with open(FEEDBACK_CSV, "w", newline="", encoding="utf-8") as f:
                pass
        except Exception:
            pass
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
                                headers={"Authorization": f"Bearer {sup_cfg['api_key']}","Content-Type":"application/json"},
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
- Each login, you must acknowledge **Privacy Policy & Terms of Use** (admins bypass).
        """
    )

# -------------------- Admin Tab (only for authenticated admins) --------------------
if st.session_state.get("is_admin", False):
    with tabs[-1]:
        st.write("### Admin")
        st.success("✅ Admin block is active")

        if st.button("Exit Admin"):
            st.session_state["is_admin"] = False
            _safe_rerun()

        sub1, sub2, sub3, sub4, sub5 = st.tabs([
            "🕘 History", 
            "📂 Data Explorer", 
            "🧹 Maintenance", 
            "🎨 Branding", 
            "🧪 Red Team Tracker"
        ])

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

        # ---- Red Team Tracker ----
        with sub5:
            st.write("#### 🧪 Red Team Tracker — Phase 1")
            st.caption("Monitor and export all Red Team test sessions, including tester ID, IP address, inputs, and Veritas outputs.")

            try:
                con = sqlite3.connect(DB_PATH)
                cur = con.cursor()
                cur.execute("PRAGMA table_info(analyses)")
                cols = [r[1] for r in cur.fetchall()]
                if "redteam_flag" not in cols:
                    cur.execute("ALTER TABLE analyses ADD COLUMN redteam_flag INTEGER DEFAULT 0;")
                    con.commit()
                con.close()
            except Exception as e:
                st.warning(f"Schema check failed: {e}")

            try:
                con = sqlite3.connect(DB_PATH)
                df = pd.read_sql_query("""
                    SELECT timestamp_utc, login_id, remote_addr, conversation_json
                    FROM analyses
                    WHERE conversation_json LIKE '%assistant_reply%' AND redteam_flag=1
                    ORDER BY id DESC
                    LIMIT 500
                """, con)
                con.close()
            except Exception as e:
                st.error(f"DB load error: {e}")
                df = pd.DataFrame()

            if not df.empty:
                def parse_conv(js):
                    try:
                        d = json.loads(js)
                        return d.get("user_prompt",""), d.get("assistant_reply","")
                    except Exception:
                        return "",""
                df[["Input","Output"]] = df["conversation_json"].apply(lambda x: pd.Series(parse_conv(x)))
                df.drop(columns=["conversation_json"], inplace=True)

                st.write(f"**Total Logged Red Team Tests:** {len(df)}")
                st.dataframe(
                    df[["timestamp_utc","login_id","remote_addr","Input","Output"]],
                    use_container_width=True,
                    hide_index=True,
                    height=500
                )

                csv_data = df.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Download Red Team Tracker CSV",
                    data=csv_data,
                    file_name="redteam_tracker.csv",
                    mime="text/csv"
                )
            else:
                st.info("No Red Team test data found yet. Once testers begin submitting analyses, they will appear here.")

# ====== Footer ======
st.markdown(
    "<div id='vFooter'>Copyright 2025 AI Excellence &amp; Strategic Intelligence Solutions, LLC.</div>",
    unsafe_allow_html=True
)



































