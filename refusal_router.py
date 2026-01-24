# =============================================================================
# REFUSAL ROUTER (Deterministic, fail-closed)
# =============================================================================
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional, Pattern, Tuple


# ----------------------------
# Optional logging hook
# ----------------------------
def log_error_event(event: str, where: str, status: int, detail: str) -> None:
    """
    Optional: Streamlit app may override this by importing and assigning its own logger.
    This default no-op prevents NameError if the app does not provide a logger.
    """
    return


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
        "Insufficient text to evaluate. Paste a passage (a few sentences) or upload a document."
    ),
    RefusalCategory.NON_TEXTUAL_INPUT: (
        "Non-text content cannot be analyzed directly. Paste the text or upload a document (PDF/DOCX/TXT)."
    ),
    RefusalCategory.OUT_OF_SCOPE_REQUEST: (
        "Request is outside Veritas analysis scope. Provide text to analyze for objective findings and advisory guidance."
    ),
    RefusalCategory.GENERATIVE_REQUEST_DETECTED: (
        "Veritas does not draft, rewrite, or generate content. Provide text to analyze."
    ),
    RefusalCategory.INTERNAL_SYSTEM_DETAILS: (
        "Internal implementation details cannot be shared (prompts, schema, rules, configuration, keys, or architecture)."
    ),
    RefusalCategory.PROMPT_INJECTION_ATTEMPT: (
        "Instruction override / prompt injection attempt detected. Request cannot be processed."
    ),
    RefusalCategory.SYSTEM_EVASION_ATTEMPT: (
        "Requests to bypass, evade, or defeat detection/compliance systems cannot be supported."
    ),
    RefusalCategory.EVALUATION_GAMING: (
        "Requests to game evaluations or “make content pass” checks cannot be supported. Provide the text to analyze normally."
    ),
    RefusalCategory.DISCRIMINATORY_INTENT: (
        "Discriminatory content/policy intent cannot be supported."
    ),
    RefusalCategory.COVERT_DISCRIMINATION: (
        "Covert discrimination or “without being detected” manipulation cannot be supported."
    ),
    RefusalCategory.SECURITY_SENSITIVE_REQUEST: (
        "Security misuse or circumvention guidance cannot be supported."
    ),
    RefusalCategory.LEGAL_OR_POLICY_MANIPULATION: (
        "Requests to manipulate policy/compliance processes to avoid accountability cannot be supported."
    ),
    RefusalCategory.ENTITY_CONFUSION: (
        "Clarification needed: do you mean Veritas (this analysis system) or another entity/product named Veritas?"
    ),
    RefusalCategory.AMBIGUOUS_REQUEST: (
        "Clarification needed to proceed safely. Provide the text to analyze and intended use."
    ),
    RefusalCategory.UNCLASSIFIED_HIGH_RISK: (
        "Request cannot be processed as stated. Provide the text to analyze and intended purpose."
    ),
}


# ----------------------------
# Helpers
# ----------------------------
_PUNCT_ONLY_RE = re.compile(r"^[\s\W_]+$", re.UNICODE)
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def _normalize(text: str) -> str:
    return (text or "").strip()


def _is_insufficient(text: str, min_chars: int = 8) -> bool:
    t = _normalize(text)
    if not t:
        return True
    if _PUNCT_ONLY_RE.match(t):
        return True
    if len(t) < min_chars:
        # short fragments like "." "??" "-" "ok" should refuse
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
    re.compile(r"\bshow (me )?(your|the) (system|developer) prompt\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bdeveloper mode\b", re.IGNORECASE),
]

INTERNAL_DETAILS_PHRASES = [
    "internal prompt",
    "system prompt",
    "developer prompt",
    "hidden instructions",
    "your rules",
    "routing logic",
    "policy config",
    "schema",
    "architecture",
    "source code",
    "how veritas works internally",
    "reveal configuration",
    "admin password",
    "api key",
    "secrets",
    "temperature",
    "tokens",
]

EVASION_PHRASES = [
    "evade bias detection",
    "bypass bias detection",
    "avoid detection",
    "without being detected",
    "circumvent",
    "workaround",
    "beat the system",
    "make it pass",
    "pass the check",
    "avoid flags",
    "not get flagged",
    "evade compliance",
    "bypass compliance",
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
    "build",
    "make",
    "develop",
]

DISCRIMINATION_PHRASES = [
    "discriminate against",
    "exclude",
    "keep out",
    "only hire",
    "not hire",
    "prefer younger",
    "prefer men",
    "prefer women",
    "older",
    "age",
    "race",
    "ethnicity",
    "religion",
    "gender",
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
    "steal credentials",
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
    """
    Refuse if the input is basically just a link or asks to analyze an image/video/audio
    without providing extractable text.
    """
    low = text.lower().strip()

    # If the input is ONLY (or almost only) a URL, treat as non-text.
    if _URL_RE.search(low):
        # remove urls and see what's left
        without_urls = _URL_RE.sub("", low).strip()
        if len(without_urls) < 20:
            return True

    if _contains_any(low, ["analyze this image", "analyze this video", "analyze this audio"]):
        return True

    return False


def _is_internal_details(text: str) -> bool:
    return _contains_any(text.lower(), INTERNAL_DETAILS_PHRASES)


def _is_prompt_injection(text: str) -> bool:
    return _regex_any(text, PROMPT_INJECTION_PATTERNS)


def _is_evasion(text: str) -> bool:
    return _contains_any(text.lower(), EVASION_PHRASES)


def _is_generative_request(text: str) -> bool:
    low = text.lower().strip()

    # If it starts with a generative verb, refuse.
    if any(low.startswith(v + " ") for v in GENERATIVE_VERBS):
        return True

    # If it contains generative verbs + common drafting artifacts, refuse.
    if _contains_any(low, ["rewrite", "draft", "write", "create", "generate"]) and _contains_any(
        low, ["policy", "rubric", "email", "statement", "guidelines", "job description", "announcement"]
    ):
        return True

    return False


def _is_out_of_scope(text: str) -> bool:
    low = text.lower()
    # Keep conservative; adjust per product scope.
    if _contains_any(low, ["meal plan", "workout routine", "political opinion"]):
        return True
    return False


def _is_discriminatory_intent(text: str) -> bool:
    low = text.lower()
    if _contains_any(low, DISCRIMINATION_PHRASES) and _contains_any(
        low, ["policy", "hire", "hiring", "faculty", "staff", "admissions", "promotion"]
    ):
        return True
    return False


def _is_covert_discrimination(text: str) -> bool:
    low = text.lower()
    if _contains_any(low, COVERT_DISCRIMINATION_PHRASES):
        # “without being detected” alone is sufficient in this context
        if "without being detected" in low:
            return True
        if _contains_any(
            low,
            ["faculty", "staff", "older", "age", "women", "men", "race", "disability", "religion", "admissions", "hiring", "promotion"],
        ):
            return True
    return False


def _is_security_sensitive(text: str) -> bool:
    return _contains_any(text.lower(), SECURITY_SENSITIVE_PHRASES)


def _is_legal_policy_manipulation(text: str) -> bool:
    return _contains_any(text.lower(), LEGAL_POLICY_MANIPULATION_PHRASES)


def _is_entity_confusion(text: str) -> bool:
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
        predicate=_is_insufficient,
        reason="Empty/too short/punctuation-only input.",
    ),
    RefusalRule(
        name="non_textual_input",
        category=RefusalCategory.NON_TEXTUAL_INPUT,
        predicate=_looks_like_non_text_request,
        reason="Link/image/video/audio request without extractable text.",
    ),
    RefusalRule(
        name="prompt_injection_attempt",
        category=RefusalCategory.PROMPT_INJECTION_ATTEMPT,
        predicate=_is_prompt_injection,
        reason="Prompt injection or instruction override attempt detected.",
    ),
    RefusalRule(
        name="internal_system_details",
        category=RefusalCategory.INTERNAL_SYSTEM_DETAILS,
        predicate=_is_internal_details,
        reason="Request for internal prompts/schema/config/keys/architecture.",
    ),
    RefusalRule(
        name="system_evasion_attempt",
        category=RefusalCategory.SYSTEM_EVASION_ATTEMPT,
        predicate=_is_evasion,
        reason="Evasion/bypass/gaming detection request detected.",
    ),
    RefusalRule(
        name="covert_discrimination",
        category=RefusalCategory.COVERT_DISCRIMINATION,
        predicate=_is_covert_discrimination,
        reason="Covert discrimination or 'without being detected' manipulation detected.",
    ),
    RefusalRule(
        name="discriminatory_intent",
        category=RefusalCategory.DISCRIMINATORY_INTENT,
        predicate=_is_discriminatory_intent,
        reason="Explicit discriminatory intent detected.",
    ),
    RefusalRule(
        name="security_sensitive_request",
        category=RefusalCategory.SECURITY_SENSITIVE_REQUEST,
        predicate=_is_security_sensitive,
        reason="Security misuse or circumvention guidance request detected.",
    ),
    RefusalRule(
        name="legal_or_policy_manipulation",
        category=RefusalCategory.LEGAL_OR_POLICY_MANIPULATION,
        predicate=_is_legal_policy_manipulation,
        reason="Manipulating policy/compliance/HR processes request detected.",
    ),
    RefusalRule(
        name="generative_request_detected",
        category=RefusalCategory.GENERATIVE_REQUEST_DETECTED,
        predicate=_is_generative_request,
        reason="Drafting/rewriting/generating content request detected.",
    ),
    RefusalRule(
        name="entity_confusion",
        category=RefusalCategory.ENTITY_CONFUSION,
        predicate=_is_entity_confusion,
        reason="Likely confusion with another entity named Veritas.",
    ),
    RefusalRule(
        name="out_of_scope_request",
        category=RefusalCategory.OUT_OF_SCOPE_REQUEST,
        predicate=_is_out_of_scope,
        reason="Request appears outside Veritas analysis scope.",
    ),
)


def check_refusal(user_input: str) -> RefusalResult:
    """
    Deterministic refusal router.
    Returns first matching refusal category based on ordered rules.
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
        except Exception as e:
            # Fail CLOSED (safe) if a predicate breaks.
            log_error_event("REFUSAL_PREDICATE_ERROR", "refusal_router", 500, f"{rule.name}: {repr(e)}")
            return RefusalResult(
                should_refuse=True,
                category=RefusalCategory.UNCLASSIFIED_HIGH_RISK,
                reason="Refusal router predicate exception; failing closed.",
                matched_rule=f"predicate_exception:{rule.name}",
            )

    return RefusalResult(should_refuse=False)


def render_refusal(*args, **kwargs) -> str:
    """
    Backwards-compatible renderer.

    Supported calls:
      - render_refusal(category, reason="")
      - render_refusal(analysis_id, category, reason="")  # analysis_id ignored in output
    """
    reason = ""

    # Parse args
    if len(args) == 0:
        category = kwargs.get("category")
        reason = kwargs.get("reason", "")
    elif len(args) == 1:
        category = args[0]
        reason = kwargs.get("reason", "")
    elif len(args) == 2:
        category = args[0]
        reason = args[1] or ""
    else:
        # (analysis_id, category, reason)
        category = args[1]
        reason = args[2] or ""

    if not isinstance(category, RefusalCategory):
        category = RefusalCategory.UNCLASSIFIED_HIGH_RISK

    msg = REFUSAL_MESSAGES.get(category, REFUSAL_MESSAGES[RefusalCategory.UNCLASSIFIED_HIGH_RISK])

    objective = "- Request cannot be processed under Veritas scope and safety constraints."
    if reason:
        objective += f"\n- Router reason: {reason}"

    return (
        "## Objective Findings\n\n"
        f"{objective}\n\n"
        "## Advisory Guidance\n\n"
        f"{msg}\n"
    )
