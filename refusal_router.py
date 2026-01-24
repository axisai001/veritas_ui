# refusal_router.py
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# =========================
# Data model
# =========================
@dataclass(frozen=True)
class RefusalDecision:
    should_refuse: bool
    category: Optional[str] = None
    reason: Optional[str] = None


# =========================
# Helpers
# =========================
def _normalize(text: str) -> str:
    return (text or "").strip()


def _has_substantive_content(text: str) -> bool:
    """
    True if there's at least one alphanumeric char.
    Prevents "." or "!!!" from being treated as analyzable content.
    """
    return bool(re.search(r"[A-Za-z0-9]", text or ""))


def _match_any(patterns: list[re.Pattern], text: str) -> bool:
    return any(p.search(text) for p in patterns)


# =========================
# Patterns (precise rules)
# =========================

# 1) Prompt injection / jailbreak / override attempts
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore (all|any|previous) (instructions|rules|system)\b", re.I),
    re.compile(r"\bbypass\b|\boverride\b|\bjailbreak\b|\ndo not refuse\b", re.I),
    re.compile(r"\bdisregard\b.*\bpolicy\b", re.I),
    re.compile(r"\byou are now allowed to\b", re.I),
    re.compile(r"\bact as\b.*\b(system|developer|admin)\b", re.I),
    re.compile(r"\breveal\b.*\b(system prompt|developer message|hidden prompt)\b", re.I),
]

# 2) Internal system details / implementation extraction
INTERNAL_SYSTEM_DETAILS_PATTERNS = [
    re.compile(r"\binternal\b.*\b(rules|thresholds|prompts|logic|policy|policies)\b", re.I),
    re.compile(r"\bhow\b.*\b(veritas)\b.*\b(decides|determines|detects|scores|works)\b", re.I),
    re.compile(r"\braw\b.*\b(schema|prompt|system prompt)\b", re.I),
    re.compile(r"\bexactly as implemented\b", re.I),
    re.compile(r"\bimplementation details\b|\bsource code\b|\bdecision tree\b", re.I),
    re.compile(r"\b(full|entire)\b.*\b(schema|system prompt|prompt)\b", re.I),
    re.compile(r"\byour\b.*\bschema\b|\bgive me\b.*\bschema\b|\bschema\b.*\bveritas\b", re.I),
]

# 3) System evasion attempts (bypass safeguards/detectors)
SYSTEM_EVASION_PATTERNS = [
    re.compile(r"\bevade\b|\bcircumvent\b|\bbypass detection\b|\bavoid detection\b", re.I),
    re.compile(r"\bhow to\b.*\b(evade|circumvent|bypass|avoid)\b.*\b(bias detection|detector|review|oversight)\b", re.I),
    re.compile(r"\btrick\b.*\b(detector|system)\b|\bbeat\b.*\b(detector|system)\b", re.I),
    re.compile(r"\bget around\b.*\b(safeguards|guardrails|controls)\b", re.I),
]

# 4) Out-of-scope disallowed use: intent to engineer discriminatory / harmful outcomes
OUT_OF_SCOPE_DISALLOWED_USE_PATTERNS = [
    re.compile(r"\bsubtly\b.*\bdiscriminat(e|ion)\b", re.I),
    re.compile(r"\bwithout being detected\b", re.I),
    re.compile(r"\bmake it\b.*\b(discriminatory|exclusionary)\b", re.I),
    re.compile(r"\btarget\b.*\b(older|age|race|gender|religion|disability)\b", re.I),
    re.compile(r"\bhide\b.*\b(discrimination|bias)\b", re.I),
]


# =========================
# Router (precedence matters)
# =========================
def check_refusal(text: str) -> RefusalDecision:
    """
    Returns RefusalDecision with category + reason.
    Precedence is intentional:
      1) insufficient_input
      2) prompt_injection
      3) internal_system_details
      4) system_evasion_attempt
      5) out_of_scope_disallowed_use
    """
    t = _normalize(text)

    # 1) Insufficient input
    if not t or not _has_substantive_content(t):
        return RefusalDecision(
            should_refuse=True,
            category="insufficient_input",
            reason="Input is empty or lacks substantive content."
        )

    # 2) Prompt injection
    if _match_any(PROMPT_INJECTION_PATTERNS, t):
        return RefusalDecision(
            should_refuse=True,
            category="prompt_injection",
            reason="Prompt-injection or guardrail override attempt."
        )

    # 3) Internal system details extraction
    if _match_any(INTERNAL_SYSTEM_DETAILS_PATTERNS, t):
        return RefusalDecision(
            should_refuse=True,
            category="internal_system_details",
            reason="Request for internal system logic, prompts, thresholds, or schema."
        )

    # 4) System evasion attempts
    if _match_any(SYSTEM_EVASION_PATTERNS, t):
        return RefusalDecision(
            should_refuse=True,
            category="system_evasion_attempt",
            reason="Request to evade or circumvent institutional safeguard systems."
        )

    # 5) Out-of-scope disallowed use (engineering discriminatory outcomes)
    if _match_any(OUT_OF_SCOPE_DISALLOWED_USE_PATTERNS, t):
        return RefusalDecision(
            should_refuse=True,
            category="out_of_scope_disallowed_use",
            reason="Request seeks assistance to engineer discriminatory or deceptive outcomes."
        )

    return RefusalDecision(should_refuse=False)


# =========================
# Refusal messaging (v4-compatible: Objective Findings + Advisory Guidance)
# =========================
def render_refusal(*args, **kwargs) -> str:
    """
    Supports:
      - render_refusal(analysis_id, category, reason=None)
      - render_refusal(analysis_id=..., category=..., reason=...)

    Returns Markdown.
    """
    analysis_id = kwargs.get("analysis_id", args[0] if len(args) > 0 else None)
    category = kwargs.get("category", args[1] if len(args) > 1 else "restricted_request")
    reason = kwargs.get("reason", args[2] if len(args) > 2 else None)

    # Category-specific copy
    if category == "out_of_scope_disallowed_use":
        obj = (
            "This request seeks guidance to intentionally create, conceal, or optimize discriminatory outcomes.\n"
            "Veritas does not provide assistance intended to engineer harm, deception, or exclusion.\n"
            "Analysis stops here."
        )
        adv = (
            "If you want a compliant review, paste the policy as written and ask for inclusive, neutral revisions.\n"
            "You may also request identification of potentially exclusionary language and high-risk phrasing."
        )

    elif category == "system_evasion_attempt":
        obj = (
            "This request seeks guidance on evading or undermining institutional review or safeguard mechanisms.\n"
            "Veritas does not assist with bypassing, exploiting, or circumventing oversight systems.\n"
            "Analysis stops here."
        )
        adv = (
            "If your goal is compliance, paste the text you want evaluated and request risk-based clarity improvements.\n"
            "You may also ask for an assessment of ambiguous language that could be misinterpreted by reviewers."
        )

    elif category == "internal_system_details":
        obj = (
            "The request is for internal system details and is not eligible for content analysis.\n"
            "This information is restricted to protect security, integrity, and governance controls."
        )
        adv = (
            "If you need help using Veritas, describe your analysis goal and paste the text you want evaluated.\n"
            "If you are an authorized administrator requesting implementation documentation, use the internal support channel and reference the Analysis ID."
        )

    elif category == "prompt_injection":
        obj = (
            "The request attempts to override system safeguards and is not eligible for content analysis.\n"
            "This behavior is restricted to protect security, integrity, and governance controls."
        )
        adv = (
            "If you want an analysis, paste the text to be evaluated and specify the desired review focus.\n"
            "If you are performing authorized security testing, log this attempt and reference the Analysis ID internally."
        )

    elif category == "insufficient_input":
        obj = (
            "The input does not contain enough substantive content to analyze.\n"
            "No meaningful text or context was provided."
        )
        adv = (
            "Paste a paragraph, policy excerpt, or complete sentence for analysis.\n"
            "If you have a document, upload it and specify what you want evaluated (e.g., restrictive language, bias signals, clarity risks)."
        )

    else:
        obj = (
            "This request is not eligible for content analysis.\n"
            "Analysis stops here."
        )
        adv = (
            "Paste the content you want evaluated and describe your goal.\n"
            "If you are an authorized administrator, reference the Analysis ID in the internal support channel."
        )

    # Optional: include router's reason in internal logs only; keep UI clean
    # If you want it displayed, uncomment next two lines:
    # if reason:
    #     obj = obj + f"\n\nReason Code: `{category}` — {reason}"

    md = f"""Veritas Analysis ID: {analysis_id}

## Objective Findings
{obj}

## Advisory Guidance
{adv}
"""
    return md
