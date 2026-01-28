# api_auth.py — B2B API Authentication (VER-B2B-003)
# Fail-closed authentication & entitlement checks.
# No Streamlit dependency.

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tenant_store import (
    verify_tenant_key_detailed,
    current_period_yyyy,
    get_usage,
)

class Unauthorized(Exception):
    """401"""
    pass

class Forbidden(Exception):
    """403"""
    pass

class TooManyRequests(Exception):
    """429"""
    pass

@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    tier: str
    annual_analysis_limit: int
    key_id: str
    period_yyyy: str
    used_this_period: int

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

    if used >= annual_limit:
        raise TooManyRequests(f"Over quota ({used}/{annual_limit})")

    return TenantContext(
        tenant_id=tenant_id,
        tier=tier,
        annual_analysis_limit=annual_limit,
        key_id=key_id,
        period_yyyy=period,
        used_this_period=used,
    )
