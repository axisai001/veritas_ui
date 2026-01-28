# api_app.py — minimal FastAPI app (with quota telemetry for testing)

from fastapi import FastAPI, Depends
from pydantic import BaseModel
from api_fastapi_adapter import require_tenant
from api_auth import TenantContext

app = FastAPI()

class AnalyzeRequest(BaseModel):
    text: str

@app.post("/analyze")
def analyze(payload: AnalyzeRequest, tenant: TenantContext = Depends(require_tenant)):
    return {
        "tenant_id": tenant.tenant_id,
        "ok": True,
        "period_yyyy": tenant.period_yyyy,
        "used_this_period": tenant.used_this_period,
        "limit": tenant.annual_analysis_limit,  # name kept for compatibility
    }
