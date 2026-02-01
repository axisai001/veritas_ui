# api_app.py — minimal FastAPI app (with quota consumption + 95% warning)

from __future__ import annotations

import uuid
from fastapi import FastAPI, Depends

from api_fastapi_adapter import require_tenant
from api_auth import TenantContext
from tenant_store import increment_usage, try_set_95_warning_once  # meters quota + warning flag

WARNING_THRESHOLD = 0.95  # VER-B2B-005

app = FastAPI()


@app.post("/analyze")
def analyze(payload: dict, tenant: TenantContext = Depends(require_tenant)):
    """
    Behavior:
    - require_tenant() authenticates and hard-stops if already over quota (429).
    - We consume quota AFTER successful request handling.
    - We return a 95% usage warning as non-blocking metadata.
    """

    # API-level analysis identifier (metadata; safe to return)
    analysis_id = f"VTX-{uuid.uuid4().hex[:12].upper()}"

    # Compute warning based on the *projected* usage after consuming this call.
    # tenant.used_this_period is the usage BEFORE this request.
    used_before = int(getattr(tenant, "used_this_period", 0) or 0)
    limit = int(getattr(tenant, "annual_analysis_limit", 0) or 0)

    projected_used = used_before + 1
    ratio = (projected_used / limit) if limit > 0 else 0.0

    warning_msg = None
    if limit > 0 and ratio >= WARNING_THRESHOLD:
        # Fire warning only once per tenant+period
        if try_set_95_warning_once(tenant.tenant_id, tenant.period_yyyy):
            pct = int(round(ratio * 100))
            warning_msg = f"You have used {pct}% of your monthly analysis quota."

    # Consume quota (metering)
    increment_usage(tenant.tenant_id, tenant.period_yyyy)

    # Response (structured, non-blocking warning)
    resp = {
        "tenant_id": tenant.tenant_id,
        "analysis_id": analysis_id,
        "ok": True,
    }

    # Include warning only when triggered (keeps response clean)
    if warning_msg:
        resp["warning"] = warning_msg

    # OPTIONAL: include usage metadata for transparency/debugging
    resp["usage"] = {
        "used_before": used_before,
        "used_after": projected_used,
        "limit": limit,
        "period": tenant.period_yyyy,
        "threshold_percent": int(WARNING_THRESHOLD * 100),
    }

    return resp
