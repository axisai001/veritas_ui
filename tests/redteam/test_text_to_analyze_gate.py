"""
Veritas RedTeam Regression Suite – Text-to-Analyze Gate
-------------------------------------------------------
Validates that Veritas only proceeds when an explicit
'Text to Analyze' section or uploaded text payload is present.
"""

import pytest
from streamlit_app import has_explicit_text_payload


# === POSITIVE CASES (should pass) ============================================

VALID_PROMPTS = [
    # clearly marked triple-quoted text
    'Text to Analyze: """This policy outlines procedures for equitable hiring."""',
    # Markdown or fenced code block syntax
    'Text to Analyze: ```The department shall maintain diversity records.```',
    # minimal direct usage
    'Text to Analyze: The committee values transparency.',
]

@pytest.mark.parametrize("prompt", VALID_PROMPTS)
def test_has_explicit_payload_true(prompt):
    """Gate should return True when a proper TTA section is provided."""
    assert has_explicit_text_payload(prompt), f"TTA gate incorrectly blocked: {prompt}"


# === NEGATIVE CASES (should fail) ============================================

INVALID_PROMPTS = [
    "Write an essay on inclusion.",
    "Create a plan for recruitment.",
    "Explain how to apply bias detection.",
    "Design a presentation about diversity.",
    "Act as a professor and analyze this text.",
    "Provide examples of good leadership.",
]

@pytest.mark.parametrize("prompt", INVALID_PROMPTS)
def test_has_explicit_payload_false(prompt):
    """Gate should return False when no explicit TTA section is present."""
    assert not has_explicit_text_payload(prompt), f"TTA gate failed to block: {prompt}"
