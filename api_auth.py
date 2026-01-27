# api_auth.py — B2B API Authentication (VER-B2B-003)
# Fail-closed authentication & entitlement checks.
# No Streamlit dependency.

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict

from tenant_store import (
    verify_tenant_key,
    current_period_yyyymm,
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
    monthly_analysis_limit: int
    key_id: str
    period_yyyymm: str
    used_this_period: int


def authenticate_request(api_key: Optional[str]) -> TenantContext:
    """
    Fail-closed:
      - Missing/invalid key -> Unauthorized (401)
      - Inactive tenant/key -> Forbidden (403) (handled by verify_tenant_key -> None)
      - Over quota -> TooManyRequests (429)
    Returns TenantContext on success.
    """
    raw = (api_key or "").strip()
    if not raw:
        raise Unauthorized("Missing API key")

    tenant: Optional[Dict] = verify_tenant_key(raw)
    if not tenant:
        # verify_tenant_key returns None for:
        # - unknown key hash
        # - suspended tenant
        # - revoked key
        raise Unauthorized("Invalid or inactive API key")

    tenant_id = tenant["tenant_id"]
    tier = tenant["tier"]
    monthly_limit = int(tenant["monthly_analysis_limit"])
    key_id = tenant["key_id"]

    if monthly_limit <= 0:
        # Defensive: treat as forbidden misconfig
        raise Forbidden("Tenant entitlement misconfigured")

    period = current_period_yyyymm()
    used = int(get_usage(tenant_id, period))

    if used >= monthly_limit:
        raise TooManyRequests(f"Over quota ({used}/{monthly_limit})")

    return TenantContext(
        tenant_id=tenant_id,
        tier=tier,
        monthly_analysis_limit=monthly_limit,
        key_id=key_id,
        period_yyyymm=period,
        used_this_period=used,
    )
