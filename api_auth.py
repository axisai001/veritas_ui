# api_auth.py — B2B API Authentication (VER-B2B-003 / VER-B2B-005)
# Fail-closed authentication & entitlement checks.
# Adds 95% usage threshold warning metadata (does NOT block analysis).
# No Streamlit dependency.

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tenant_store import (
    verify_tenant_key_detailed,
    current_period_yyyy,
    get_usage,
)

# -----------------------------
# Exceptions (framework-agnostic)
# -----------------------------
class Unauthorized(Exception):
    """401"""
    pass

class Forbidden(Exception):
    """403"""
    pass

class TooManyRequests(Exception):
    """429"""
    pass


# -----------------------------
# Tenant context (returned on success)
# -----------------------------
@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    tier: str
    annual_analysis_limit: int
    key_id: str
    period_yyyy: str
    used_this_period: int

    # --- VER-B2B-005: warning metadata ---
    remaining_this_period: int
    usage_ratio: float                 # 0.0–1.0
    usage_percent: int                 # 0–100 (rounded down)
    warning_threshold_percent: int     # default 95
    warning_triggered: bool
    warning_message: Optional[str]


def authenticate_request(api_key: Optional[str]) -> TenantContext:
    raw = (api_key or "").strip()
    if not raw:
        raise Unauthorized("Missing API key")

    tenant, reason = verify_tenant_key_detailed(raw)

    if reason in ("bad_format", "not_found", "missing"):
        raise Unauthorized("Missing or invalid API key")

    if reason == "inactive":
        raise Forbidden("Tenant or API key is inactive")

    if reason != "ok" or not tenant:
        raise Unauthorized("Invalid API key")

    tenant_id = tenant["tenant_id"]
    tier = tenant["tier"]
    annual_limit = int(tenant.get("annual_analysis_limit") or 0)
    key_id = tenant.get("key_id") or ""

    if annual_limit <= 0:
        raise Forbidden("Tenant entitlement misconfigured")

    period = current_period_yyyy()
    used = int(get_usage(tenant_id, period))

    # Hard-stop (existing behavior)
    if used >= annual_limit:
        raise TooManyRequests(f"Over quota ({used}/{annual_limit})")

    # --- VER-B2B-005: compute warning metadata ---
    # (NOTE: Your current metering is period_yyyy, but messaging can still say "monthly" if desired.)
    remaining = max(annual_limit - used, 0)
    ratio = (used / annual_limit) if annual_limit > 0 else 1.0
    percent = int(ratio * 100)  # floor

    threshold_percent = 95
    warning_triggered = (percent >= threshold_percent)

    warning_message = None
    if warning_triggered:
        warning_message = f"You have used {percent}% of your monthly analysis quota."

    return TenantContext(
        tenant_id=tenant_id,
        tier=tier,
        annual_analysis_limit=annual_limit,
        key_id=key_id,
        period_yyyy=period,
        used_this_period=used,
        remaining_this_period=remaining,
        usage_ratio=float(ratio),
        usage_percent=percent,
        warning_threshold_percent=threshold_percent,
        warning_triggered=warning_triggered,
        warning_message=warning_message,
    )
