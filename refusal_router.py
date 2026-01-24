# =============================================================================
# REFUSAL ROUTER (Deterministic, fail-closed)
# =============================================================================
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Pattern, Tuple


class RefusalCategory(str, Enum):
    # Input quality / structural
    INSUFFICIENT_INPUT = "insufficient_input"
    NON_TEXTUAL_INPUT = "non_textual_input"

    # Scope / function boundaries
    OUT_OF_SCOPE_REQUEST = "out_of_scope_request"
    GENERATIVE_REQUEST_DETECTED = "generative_request_detected"

    # Internal system / IP protection
    INTERNAL_SYSTEM_DETAILS = "internal_system_details"
    PROMPT_INJECTION_ATTEMPT = "prompt_injection_attempt"
    ENTITY_CONFUSION = "entity_confusion"
    AMBIGUOUS_REQUEST = "ambiguous_request"

    # Evasion / bypass / gaming
    SYSTEM_EVASION_ATTEMPT = "system_evasion_attempt"
    EVALUATION_GAMING = "evaluation_gaming"

    # Discrimination / harmful manipulation
    DISCRIMINATORY_INTENT = "discriminatory_intent"
    COVERT_DISCRIMINATION = "covert_discrimination"

    # Security / legal / institutional risk
    SECURITY_SENSITIVE_REQUEST = "security_sensitive_request"
    LEGAL_OR_POLICY_MANIPULATION = "legal_or_policy_manipulation"

    # Operational / meta
    RATE_LIMIT_VIOLATION = "rate_limit_violation"
    SESSION_STATE_VIOLATION = "session_state_violation"

    # Fail-safe
    UNCLASSIFIED_HIGH_RISK = "unclassified_high_risk"


@dataclass(frozen=True)
class RefusalResult:
    should_refuse: bool
    category: Optional[RefusalCategory] = None
    reason: str = ""
    matched_rule: str = ""


# ----------------------------
# Config: category messages
# ----------------------------
REFUSAL_MESSAGES = {
    RefusalCategory.INSUFFICIENT_INPUT: (
        "I can’t analyze this because there isn’t enough text to evaluate. "
        "Please paste a passage (a few sentences or more) or upload a document."
    ),
    RefusalCategory.NON_TEXTUAL_INPUT: (
        "I can’t analyze non-text content directly. Please paste the text you want analyzed "
        "or upload a document that can be extracted (PDF/DOCX/TXT)."
    ),
    RefusalCategory.OUT_OF_SCOPE_REQUEST: (
        "I can’t help with that request. Veritas is limited to analyzing provided text and returning "
        "objective findings with non-prescriptive advisory guidance."
    ),
    RefusalCategory.GENERATIVE_REQUEST_DETECTED: (
        "I can’t generate, draft, rewrite, or design content. Veritas only analyzes text you provide "
        "and returns objective findings with advisory guidance."
    ),
    RefusalCategory.INTERNAL_SYSTEM_DETAILS: (
        "I can’t share internal implementation details (e.g., prompts, schema, architecture, rules, or configuration)."
    ),
    RefusalCategory.PROMPT_INJECTION_ATTEMPT: (
        "I can’t comply with attempts to override system instructions or reveal hidden configuration."
    ),
    RefusalCategory.SYSTEM_EVASION_ATTEMPT: (
        "I can’t help with bypassing, evading, or defeating bias detection or compliance systems."
    ),
    RefusalCategory.EVALUATION_GAMING: (
        "I can’t help with gaming evaluations or “making content pass” checks. "
        "If you want, provide the text and I can analyze it for clarity, bias signals, and risk areas."
    ),
    RefusalCategory.DISCRIMINATORY_INTENT: (
        "I can’t help create or refine discriminatory content or policies."
    ),
    RefusalCategory.COVERT_DISCRIMINATION: (
        "I can’t help create or refine content intended to subtly discriminate or evade detection."
    ),
    RefusalCategory.SECURITY_SENSITIVE_REQUEST: (
        "I can’t help with guidance that enables security misuse or circumvention of institutional controls."
    ),
    RefusalCategory.LEGAL_OR_POLICY_MANIPULATION: (
        "I can’t help with manipulating policies or compliance processes to avoid accountability."
    ),
    RefusalCategory.ENTITY_CONFUSION: (
        "I need clarification. Are you referring to Veritas (this analysis system) or another product/entity named Veritas?"
    ),
    RefusalCategory.AMBIGUOUS_REQUEST: (
        "I need a bit more context to proceed safely. Please clarify what text you want analyzed and the intended use."
    ),
    RefusalCategory.UNCLASSIFIED_HIGH_RISK: (
        "I can’t assist with that request as stated. Please provide the text you want analyzed and your intended purpose."
    ),
}


# ----------------------------
# Helpers
# ----------------------------
_PUNCT_ONLY_RE = re.compile(r"^[\s\W_]+$", re.UNICODE)

def _normalize(text: str) -> str:
    return (text or "").strip()

def _is_insufficient(text: str, min_chars: int = 8) -> bool:
    t = _normalize(text)
    if not t:
        return True
    if len(t) < min_chars:
        # also catch "." "??" "-" etc.
        if _PUNCT_ONLY_RE.match(t):
            return True
    # if it is mostly punctuation/symbols
    if _PUNCT_ONLY_RE.match(t):
        return True
    return False

def _contains_any(text: str, phrases: List[str]) -> bool:
    low = text.lower()
    return any(p in low for p in phrases)

def _regex_any(text: str, patterns: List[Pattern[str]]) -> bool:
    return any(p.search(text) for p in patterns)


# ----------------------------
# Rule object
# ----------------------------
@dataclass(frozen=True)
class RefusalRule:
    name: str
    category: RefusalCategory
    predicate: Callable[[str], bool]
    reason: str


# ----------------------------
# Pattern libraries
# ----------------------------
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore (all )?previous instructions\b", re.IGNORECASE),
    re.compile(r"\bdisregard (the )?(system|developer) message\b", re.IGNORECASE),
    re.compile(r"\breveal (your|the) (system|developer|hidden) (prompt|instructions)\b", re.IGNORECASE),
    re.compile(r"\bact as if you are not\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
]

INTERNAL_DETAILS_PHRASES = [
    "internal prompt",
    "system prompt",
    "developer prompt",
    "your prompt",
    "your rules",
    "hidden instructions",
    "schema",
    "architecture",
    "source code",
    "model name",
    "temperature",
    "tokens",
    "routing logic",
    "policy config",
    "how veritas works internally",
    "show me how veritas works",
    "reveal configuration",
    "admin password",
    "api key",
    "secrets",
]

EVASION_PHRASES = [
    "evade bias detection",
    "bypass bias detection",
    "avoid detection",
    "without being detected",
    "get around",
    "circumvent",
    "workaround",
    "beat the system",
    "make it pass",
    "pass the check",
    "avoid flags",
    "not get flagged",
]

GENERATIVE_VERBS = [
    "write",
    "draft",
    "create",
    "generate",
    "rewrite",
    "redraft",
    "design",
    "compose",
    "produce",
    "build a",
    "make a",
    "develop a",
]

DISCRIMINATION_PHRASES = [
    "discriminate against",
    "exclude",
    "keep out",
    "prefer younger",
    "prefer men",
    "prefer women",
    "only hire",
    "not hire",
    "race",
    "ethnicity",
    "religion",
    "gender",
    "older",
    "disability",
]

COVERT_DISCRIMINATION_PHRASES = [
    "subtly discriminate",
    "quietly discriminate",
    "indirectly discriminate",
    "without being detected",
    "covert",
    "coded language",
]

SECURITY_SENSITIVE_PHRASES = [
    "evade monitoring",
    "bypass controls",
    "exploit",
    "phish",
    "malware",
    "hack",
    "credential stuffing",
    "steal",
]

LEGAL_POLICY_MANIPULATION_PHRASES = [
    "loophole",
    "avoid compliance",
    "avoid accountability",
    "get around hr policy",
    "evade policy",
    "hide violation",
]


def _looks_like_non_text_request(text: str) -> bool:
    # Common "analyze a link/video/image" without usable text
    low = text.lower().strip()
    if "http://" in low or "https://" in low:
        return True
    if _contains_any(low, ["analyze this image", "analyze this video", "analyze this audio"]):
        return True
    return False


def _is_internal_details(text: str) -> bool:
    low = text.lower()
    # note: "api key" in user text might be legitimate in admin contexts,
    # but for Veritas end-user analysis route, treat as internal detail request.
    return _contains_any(low, INTERNAL_DETAILS_PHRASES)


def _is_prompt_injection(text: str) -> bool:
    return _regex_any(text, PROMPT_INJECTION_PATTERNS)


def _is_evasion(text: str) -> bool:
    low = text.lower()
    return _contains_any(low, EVASION_PHRASES)


def _is_generative_request(text: str) -> bool:
    low = text.lower()
    # A very conservative gate: if they start with an imperative generative verb, refuse.
    if any(low.startswith(v + " ") for v in GENERATIVE_VERBS):
        return True
    # Also refuse if "rewrite" etc. appears with "policy", "rubric", "email", etc.
    if _contains_any(low, ["rewrite", "draft", "write", "create", "generate"]) and _contains_any(
        low, ["policy", "rubric", "email", "statement", "guidelines", "job description", "announcement"]
    ):
        return True
    return False


def _is_out_of_scope(text: str) -> bool:
    # If not strictly analysis; you can expand with your product constraints
    low = text.lower()
    if _contains_any(low, ["give me a meal plan", "workout routine", "political opinion"]):
        return True
    # Anything explicitly requesting "advice" can still be okay if tied to provided text.
    # Keep this conservative.
    return False


def _is_discriminatory_intent(text: str) -> bool:
    low = text.lower()
    # Explicit discrimination intent
    if _contains_any(low, DISCRIMINATION_PHRASES) and _contains_any(low, ["policy", "hire", "faculty", "staff", "admissions"]):
        return True
    return False


def _is_covert_discrimination(text: str) -> bool:
    low = text.lower()
    if _contains_any(low, COVERT_DISCRIMINATION_PHRASES):
        # If they mention discrimination targets or HR/faculty context, treat as covert discrimination
        if _contains_any(low, ["faculty", "staff", "older", "age", "women", "men", "race", "disability", "religion", "admissions", "hiring", "promotion"]):
            return True
        # Even without explicit target, "without being detected" is often enough
        if "without being detected" in low:
            return True
    return False


def _is_security_sensitive(text: str) -> bool:
    return _contains_any(text.lower(), SECURITY_SENSITIVE_PHRASES)


def _is_legal_policy_manipulation(text: str) -> bool:
    return _contains_any(text.lower(), LEGAL_POLICY_MANIPULATION_PHRASES)


def _is_entity_confusion(text: str) -> bool:
    # Only if they say "Veritas" and ask generic questions that match the backup company patterns
    low = text.lower()
    if "veritas" in low and _contains_any(low, ["backup", "recovery", "storage", "deduplication", "netbackup"]):
        return True
    return False


# ----------------------------
# Rules (ordered, most strict first)
# ----------------------------
REFUSAL_RULES: Tuple[RefusalRule, ...] = (
    RefusalRule(
        name="insufficient_input",
        category=RefusalCategory.INSUFFICIENT_INPUT,
        predicate=lambda t: _is_insufficient(t),
        reason="Empty/too short/punctuation-only input.",
    ),
    RefusalRule(
        name="non_textual_input",
        category=RefusalCategory.NON_TEXTUAL_INPUT,
        predicate=lambda t: _looks_like_non_text_request(t),
        reason="Link/image/video/audio request without extractable text.",
    ),
    RefusalRule(
        name="prompt_injection_attempt",
        category=RefusalCategory.PROMPT_INJECTION_ATTEMPT,
        predicate=lambda t: _is_prompt_injection(t),
        reason="Prompt injection or instruction override attempt detected.",
    ),
    RefusalRule(
        name="internal_system_details",
        category=RefusalCategory.INTERNAL_SYSTEM_DETAILS,
        predicate=lambda t: _is_internal_details(t),
        reason="Request for internal prompts/schema/config/keys/architecture.",
    ),
    RefusalRule(
        name="system_evasion_attempt",
        category=RefusalCategory.SYSTEM_EVASION_ATTEMPT,
        predicate=lambda t: _is_evasion(t),
        reason="Evasion/bypass/gaming detection request detected.",
    ),
    RefusalRule(
        name="covert_discrimination",
        category=RefusalCategory.COVERT_DISCRIMINATION,
        predicate=lambda t: _is_covert_discrimination(t),
        reason="Covert discrimination or 'without being detected' manipulation detected.",
    ),
    RefusalRule(
        name="discriminatory_intent",
        category=RefusalCategory.DISCRIMINATORY_INTENT,
        predicate=lambda t: _is_discriminatory_intent(t),
        reason="Explicit discriminatory intent detected.",
    ),
    RefusalRule(
        name="security_sensitive_request",
        category=RefusalCategory.SECURITY_SENSITIVE_REQUEST,
        predicate=lambda t: _is_security_sensitive(t),
        reason="Security misuse or circumvention guidance request detected.",
    ),
    RefusalRule(
        name="legal_or_policy_manipulation",
        category=RefusalCategory.LEGAL_OR_POLICY_MANIPULATION,
        predicate=lambda t: _is_legal_policy_manipulation(t),
        reason="Manipulating policy/compliance/HR processes request detected.",
    ),
    RefusalRule(
        name="generative_request_detected",
        category=RefusalCategory.GENERATIVE_REQUEST_DETECTED,
        predicate=lambda t: _is_generative_request(t),
        reason="Drafting/rewriting/generating content request detected.",
    ),
    RefusalRule(
        name="entity_confusion",
        category=RefusalCategory.ENTITY_CONFUSION,
        predicate=lambda t: _is_entity_confusion(t),
        reason="Likely confusion with another entity named Veritas.",
    ),
    RefusalRule(
        name="out_of_scope_request",
        category=RefusalCategory.OUT_OF_SCOPE_REQUEST,
        predicate=lambda t: _is_out_of_scope(t),
        reason="Request appears outside Veritas analysis scope.",
    ),
)


def check_refusal(user_input: str) -> RefusalResult:
    """
    Deterministic refusal router.
    Returns first matching refusal category based on ordered rules.
    Fail-open is NOT allowed; use UNCLASSIFIED_HIGH_RISK if needed in the future.
    """
    text = _normalize(user_input)

    for rule in REFUSAL_RULES:
        try:
            if rule.predicate(text):
                return RefusalResult(
                    should_refuse=True,
                    category=rule.category,
                    reason=rule.reason,
                    matched_rule=rule.name,
                )
        except Exception:
            # Fail closed: if predicate fails, refuse safely
            return RefusalResult(
                should_refuse=True,
                category=RefusalCategory.UNCLASSIFIED_HIGH_RISK,
                reason="Refusal router predicate exception; failing closed.",
                matched_rule="predicate_exception",
            )

    return RefusalResult(should_refuse=False)


def render_refusal(category: RefusalCategory, reason: str = "") -> str:
    """
    Minimal refusal output in Veritas v4 style (two-section format).
    You can keep it ultra-short to avoid per-report disclaimers.
    """
    msg = REFUSAL_MESSAGES.get(category, REFUSAL_MESSAGES[RefusalCategory.UNCLASSIFIED_HIGH_RISK])

    objective = "- Request cannot be processed under Veritas scope and safety constraints."
    if reason:
        objective += f"\n- Router reason: {reason}"

    advisory = msg

    return (
        "## Objective Findings\n\n"
        f"{objective}\n\n"
        "## Advisory Guidance\n\n"
        f"{advisory}\n"
    )
