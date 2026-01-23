# refusal_router.py
import re
from dataclasses import dataclass
from typing import Optional, List, Tuple

@dataclass(frozen=True)
class RefusalResult:
    should_refuse: bool
    category: Optional[str] = None
    reason: Optional[str] = None

# Patterns to catch requests for internal config, secrets, or prompt injection
INTERNAL_INFO_PATTERNS: List[Tuple[str, str]] = [
    ("internal_schema", r"\b(schema|json schema|output schema|response schema)\b"),
    ("system_prompt", r"\b(system prompt|developer prompt|hidden prompt|instruction prompt)\b"),
    ("prompt_injection", r"\b(ignore (all|previous) instructions|bypass|override|jailbreak|reveal)\b"),
    ("secrets", r"\b(api key|secret key|token|credentials|password|private key)\b"),
    ("internal_config", r"\b(model id|temperature|top_p|tools? used|chain of thought)\b"),
    ("internal_docs", r"\b(internal policy|internal documentation|runbook|playbook)\b"),
]

VERITAS_INTERNAL_PATTERNS: List[Tuple[str, str]] = [
    ("internal_schema", r"\b(veritas schema|veritas output format|veritas prompt|veritas instructions)\b"),
    ("system_prompt", r"\b(show me veritas.*prompt|what prompt does veritas use)\b"),
]

def check_refusal(user_text: str) -> RefusalResult:
    text = (user_text or "").strip().lower()
    if not text:
        return RefusalResult(False)

    for category, pattern in (VERITAS_INTERNAL_PATTERNS + INTERNAL_INFO_PATTERNS):
        if re.search(pattern, text, flags=re.IGNORECASE):
            return RefusalResult(
                should_refuse=True,
                category=category,
                reason="Request is for internal configuration, security, or implementation details."
            )

    return RefusalResult(False)

def render_refusal(analysis_id: str, category: str) -> str:
    # Must remain two sections: Objective Findings + Advisory Guidance
    return (
        "Objective Findings\n\n"
        f"- The request is for internal system details ({category}) and is not eligible for content analysis.\n"
        "- This type of information is restricted to protect security, integrity, and customer governance controls.\n\n"
        "Advisory Guidance\n\n"
        "- If you need help using Veritas, describe your analysis goal (e.g., bias signals, restrictive language, clarity risks) and paste the text you want evaluated.\n"
        "- If you are an authorized administrator requesting implementation documentation, use the internal support channel and reference the Analysis ID.\n"
        f"- Analysis ID: {analysis_id}\n"
    )
