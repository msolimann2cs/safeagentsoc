from __future__ import annotations

from fastapi import FastAPI

from safeagentsoc.api.case_routes import router as case_router
from safeagentsoc.api.routes_alerts import router as alerts_router
from safeagentsoc.api.context_routes import router as context_router
from safeagentsoc.api.graph_routes import router as graph_router
from safeagentsoc.api.routes_eval import router as eval_router
from safeagentsoc.api.routes_evidence import router as evidence_router
from safeagentsoc.api.routes_metrics import router as metrics_router
from safeagentsoc.api.reason_routes import router as reason_router
from safeagentsoc.api.timeline_routes import router as timeline_router


app = FastAPI(
    title="SafeAgentSOC Runtime API",
    version="0.8.0",
    description="Runtime query API for normalized, evidence-linked SafeAgentSOC alerts.",
)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "safeagentsoc-runtime-api"}


app.include_router(context_router)
app.include_router(case_router)
app.include_router(timeline_router)
app.include_router(reason_router)
app.include_router(graph_router)
app.include_router(alerts_router)
app.include_router(evidence_router)
app.include_router(metrics_router)
app.include_router(eval_router)
