# api_app.py — minimal FastAPI app

from fastapi import FastAPI, Depends
from api_fastapi_adapter import require_tenant
from api_auth import TenantContext

app = FastAPI()

@app.post("/analyze")
def analyze(payload: dict, tenant: TenantContext = Depends(require_tenant)):
    # tenant is resolved + under quota
    return {"tenant_id": tenant.tenant_id, "ok": True}
