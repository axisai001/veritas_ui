# api_fastapi_adapter.py — FastAPI integration for VER-B2B-003
# Purpose: Bind HTTP headers → api_auth.authenticate_request()
# Fail-closed. Framework adapter only.
#
# Supports:
#   - Authorization: Bearer vx_...
#   - Authorization: vx_...           (tolerated)
#   - X-API-Key: vx_...
#
# Notes:
# - Do NOT change TENANT_KEY_SALT between creating keys and validating keys.
# - Ensure DB_PATH is the same between Streamlit and FastAPI if both manage tenants.

from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException, Request  # <-- ADDED: Request (VER-B2B-008)

from api_auth import (
    authenticate_request,
    Unauthorized,
    Forbidden,
    TooManyRequests,
    TenantContext,
)

from tenant_store import rate_limit_check  # <-- ADDED (VER-B2B-008)

# -------------------------------------------------
# Header extraction
# -------------------------------------------------
def _clean_token(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    token = raw.strip()

    # Some shells/tools accidentally wrap values in quotes
    if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
        token = token[1:-1].strip()

    return token or None


def get_api_key(
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[str]:
    """
    Priority:
      1) Authorization: Bearer vx_...
      2) X-API-Key: vx_...
      3) Authorization: vx_...   (tolerated)
    Returns raw key string or None.
    """
    auth = _clean_token(authorization)
    if auth:
        low = auth.lower()
        if low.startswith("bearer "):
            token = _clean_token(auth.split(" ", 1)[1])
            if token:
                return token
        # tolerate direct token (no "Bearer ")
        if auth.startswith("vx_"):
            return auth

    token = _clean_token(x_api_key)
    if token:
        return token

    return None


# -------------------------------------------------
# Dependency used by API routes
# -------------------------------------------------
def require_tenant(
    request: Request,  # <-- ADDED (VER-B2B-008) for IP + route logging
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> TenantContext:
    api_key = get_api_key(authorization, x_api_key)

    # Missing key (explicit, helps Swagger/curl troubleshooting)
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    # Fail-fast key shape check (keeps logs/CPU lower)
    if not api_key.startswith("vx_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        tenant = authenticate_request(api_key)

        # =============================================================================
        # VER-B2B-008 — Per-tenant rate limiting (server-side, shared, audited)
        # Replace session-based rate limiting with tenant_id-based enforcement.
        # =============================================================================

        tenant_id = str(getattr(tenant, "tenant_id", "") or "").strip()
        key_id = str(getattr(tenant, "key_id", "") or "").strip()

        # Best-effort route + IP for audit (do NOT block if missing)
        route = ""
        try:
            route = str(getattr(request, "url", None).path or "")
        except Exception:
            route = ""
        ip = ""
        try:
            ip = str(getattr(getattr(request, "client", None), "host", "") or "")
        except Exception:
            ip = ""

        # Fail-closed: if tenant_id missing, deny (prevents unkeyed limiting)
        if not tenant_id:
            raise HTTPException(status_code=401, detail="Unauthorized")

        # Rule 1: 10 requests per minute per tenant (burst control)
        allowed_1, _, _, _ = rate_limit_check(
            tenant_id=tenant_id,
            rule="tenant_rpm_10",
            limit_val=10,
            window_sec=60,
            key_id=key_id,
            route=route,
            ip=ip,
            consume=1,
        )
        if not allowed_1:
            raise HTTPException(status_code=429, detail="Rate limit exceeded (tenant_rpm_10)")

        # Rule 2: 2 requests per second per tenant (sustained control)
        allowed_2, _, _, _ = rate_limit_check(
            tenant_id=tenant_id,
            rule="tenant_rps_2",
            limit_val=2,
            window_sec=1,
            key_id=key_id,
            route=route,
            ip=ip,
            consume=1,
        )
        if not allowed_2:
            raise HTTPException(status_code=429, detail="Rate limit exceeded (tenant_rps_2)")

        return tenant

    except TooManyRequests as e:
        raise HTTPException(status_code=429, detail=str(e))

    except Forbidden as e:
        raise HTTPException(status_code=403, detail=str(e))

    except Unauthorized as e:
        raise HTTPException(status_code=401, detail=str(e))

    # Catch-all fail-closed (avoid leaking unexpected errors)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")

