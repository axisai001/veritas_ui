# refusal_router.py — Veritas refusal router (single source of truth)
# Purpose: Detect disallowed/safety-restricted requests before model invocation.
# Returns a compact refusal response that:
# - Does not include per-report disclaimers (governance requirement)
# - Is suitable for end-user display
#
# You can expand category mappings as your governance program evolves.

from dataclasses import dataclass
import re
from typing import Optional


@dataclass
class RefusalResult:
    should_refuse: bool
    category: str = "restricted_request"
    reason: str = ""


# -----------------------------------------------------------------------------
# Detection rules (conservative, high-signal patterns)
# -----------------------------------------------------------------------------
_RE_SELF_HARM = re.compile(r"\b(i\s*(want|plan|intend|am\s*going)\s*to\s*(kill|harm|hurt)\s*(myself|me))\b", re.I)
_RE_VIOLENCE_PLANNING = re.compile(r"\b(i\s*(plan|intend|will|want)\s*to\s*(attack|shoot|bomb|kill|harm))\b", re.I)

# Weapons construction / instructions (high-level)
_RE_WEAPON_INSTRUCTIONS = re.compile(
    r"\b(how\s*to\s*(make|build)\s*(a\s*)?(bomb|pipe\s*bomb|explosive|silencer))\b", re.I
)

# Illicit wrongdoing w/ intent (generic)
_RE_HACKING = re.compile(r"\b(how\s*to\s*(hack|phish|ddos)|write\s*(a\s*)?(keylogger|malware))\b", re.I)
_RE_FRAUD = re.compile(r"\b(how\s*to\s*(forge|counterfeit)|steal\s*(a\s*)?(identity|credit\s*card))\b", re.I)

# Sexual content involving minors (hard stop)
_RE_CSAM = re.compile(r"\b(minor|child|underage)\b.*\b(sex|nude|porn)\b|\b(sex|porn)\b.*\b(minor|child|underage)\b", re.I)


def check_refusal(text: str) -> RefusalResult:
    t = (text or "").strip()
    if not t:
        return RefusalResult(False)

    # Highest priority safety
    if _RE_CSAM.search(t):
        return RefusalResult(True, "sexual_content_minor", "The request appears to involve sexual content with a minor.")

    if _RE_SELF_HARM.search(t):
        return RefusalResult(True, "self_harm", "The content indicates self-harm intent.")

    if _RE_VIOLENCE_PLANNING.search(t):
        return RefusalResult(True, "violence_planning", "The content indicates potential real-world harm planning.")

    # Operationally restricted assistance
    if _RE_WEAPON_INSTRUCTIONS.search(t):
        return RefusalResult(True, "weapon_instructions", "The request appears to seek instructions for building a weapon.")

    if _RE_HACKING.search(t):
        return RefusalResult(True, "illicit_cyber", "The request appears to seek instructions for cyber wrongdoing.")

    if _RE_FRAUD.search(t):
        return RefusalResult(True, "illicit_fraud", "The request appears to seek instructions for fraud or forgery.")

    return RefusalResult(False)


def render_refusal(analysis_id: str, category: str, reason: str) -> str:
    # Keep it short, neutral, and governance-safe (no disclaimers; no policy lectures).
    # Provide crisis resources only for self-harm, as a safety necessity.
    base = [
        "Objective Findings",
        f"- This request cannot be processed. (Category: {category})",
        "",
        "Advisory Guidance",
    ]

    if category == "self_harm":
        base.append("- If you are in immediate danger or thinking about harming yourself, call or text 988 in the U.S. or contact your local emergency number.")
        base.append("- If outside the U.S., consider contacting local crisis services or a trusted professional support line.")

    else:
        base.append("- Consider revising the input to focus on organizational or academic content suitable for analysis.")
        base.append("- If you believe this was flagged in error, submit a Support ticket with the Analysis ID for review.")

    # Analysis ID is app-level metadata; including it here is acceptable because it's not a disclaimer,
    # and it supports customer support workflows.
    base.append("")
    base.append(f"(Analysis ID: {analysis_id})")

    return "\n".join(base)
