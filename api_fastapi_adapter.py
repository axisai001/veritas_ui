# api_fastapi_adapter.py — FastAPI integration for VER-B2B-003
# Purpose: Bind HTTP headers → api_auth.authenticate_request()
# Fail-closed. Framework adapter only.
#
# Supports:
#   - Authorization: Bearer vx_...
#   - X-API-Key: vx_...
#
# Optional strict prefix check (vx_) to fail fast before hashing.

from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException

from api_auth import (
    authenticate_request,
    Unauthorized,
    Forbidden,
    TooManyRequests,
    TenantContext,
)

# -------------------------------------------------
# Header extraction
# -------------------------------------------------
def get_api_key(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> Optional[str]:
    """
    Priority:
      1) Authorization: Bearer vx_...
      2) X-API-Key: vx_...
    Returns raw key string or None.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return token or None

    if x_api_key:
        token = x_api_key.strip()
        return token or None

    return None


# -------------------------------------------------
# Dependency used by API routes
# -------------------------------------------------
def require_tenant(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
) -> TenantContext:
    api_key = get_api_key(authorization, x_api_key)

    # Optional: fail-fast key shape check (keeps logs/CPU lower)
    if api_key and not api_key.startswith("vx_"):
        raise HTTPException(status_code=401, detail="Invalid API key")

    try:
        return authenticate_request(api_key)

    except Unauthorized as e:
        raise HTTPException(status_code=401, detail=str(e))

    except Forbidden as e:
        raise HTTPException(status_code=403, detail=str(e))

    except TooManyRequests as e:
        raise HTTPException(status_code=429, detail=str(e))

    # Optional: catch-all fail-closed (avoid leaking unexpected errors)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
