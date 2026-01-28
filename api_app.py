# api_app.py — minimal FastAPI app (with quota consumption)

from fastapi import FastAPI, Depends
from api_fastapi_adapter import require_tenant
from api_auth import TenantContext

from tenant_store import increment_usage  # <-- meters quota

app = FastAPI()

@app.post("/analyze")
def analyze(payload: dict, tenant: TenantContext = Depends(require_tenant)):
    # If we got here, tenant is authenticated AND under quota.
    # Consume quota after successful request handling.
    increment_usage(tenant.tenant_id, tenant.period_yyyy)
    return {"tenant_id": tenant.tenant_id, "ok": True}
