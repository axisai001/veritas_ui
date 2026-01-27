# api_fastapi_adapter.py — FastAPI integration for VER-B2B-003
# Purpose: Bind HTTP headers → api_auth.authenticate_request()
# Fail-closed. Framework adapter only.

from __future__ import annotations

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
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> str | None:
    """
    Priority:
      1. Authorization: Bearer vx_...
      2. X-API-Key: vx_...
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        return token or None

    if x_api_key:
        return x_api_key.strip()

    return None


# -------------------------------------------------
# Dependency used by API routes
# -------------------------------------------------
def require_tenant(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
) -> TenantContext:
    api_key = get_api_key(authorization, x_api_key)

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

