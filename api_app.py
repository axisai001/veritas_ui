# api_app.py — minimal FastAPI app (with quota consumption + 95% warning)

from __future__ import annotations

import uuid
from fastapi import FastAPI, Depends

from api_fastapi_adapter import require_tenant
from api_auth import TenantContext
from tenant_store import (
    increment_usage,      # meters quota
    has_warned_95,        # VER-B2B-005 (fire once)
    mark_warned_95,       # VER-B2B-005 (fire once)
)

WARNING_THRESHOLD = 0.95  # VER-B2B-005

app = FastAPI()


@app.post("/analyze")
def analyze(payload: dict, tenant: TenantContext = Depends(require_tenant)):
    """
    Behavior:
    - require_tenant() authenticates and hard-stops if already over quota (429).
    - We consume quota AFTER successful request handling.
    - We return a 95% usage warning as non-blocking metadata.
    - Warning fires ONCE per tenant per period.
    """

    # API-level analysis identifier (metadata; safe to return)
    analysis_id = f"VTX-{uuid.uuid4().hex[:12].upper()}"

    # Compute warning based on the *projected* usage after consuming this call.
    used_before = int(getattr(tenant, "used_this_period", 0) or 0)
    limit = int(getattr(tenant, "annual_analysis_limit", 0) or 0)

    projected_used = used_before + 1
    ratio = (projected_used / limit) if limit > 0 else 0.0

    warning_msg = None
    should_mark_warned = False

    if limit > 0 and ratio >= WARNING_THRESHOLD:
        # fire once per tenant per period
        if not has_warned_95(tenant.tenant_id, tenant.period_yyyy):
            pct = int(round(ratio * 100))
            warning_msg = f"You have used {pct}% of your monthly analysis quota."
            should_mark_warned = True

    # Consume quota (metering)
    increment_usage(tenant.tenant_id, tenant.period_yyyy)

    # Persist the "warned once" flag AFTER successful handling
    if should_mark_warned:
        mark_warned_95(tenant.tenant_id, tenant.period_yyyy)

    # Response (structured, non-blocking warning)
    resp = {
        "tenant_id": tenant.tenant_id,
        "analysis_id": analysis_id,
        "ok": True,
        "usage": {
            "used_before": used_before,
            "used_after": projected_used,
            "limit": limit,
            "period": tenant.period_yyyy,
            "threshold_percent": int(WARNING_THRESHOLD * 100),
        },
    }

    if warning_msg:
        resp["warning"] = warning_msg

    return resp

