"""
Vakros Agent API
FastAPI server exposing the SOC agent as a REST endpoint.

Run:
    uvicorn api.main:app --reload --port 8000

Endpoints:
    POST /query   — Run the SOC agent on a security question
    GET  /health  — Health check
    GET  /docs    — Swagger UI (auto-generated)
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional
import os
import time

from agent.soc_agent import run_agent
from integrations.docuseal.routes import router as docuseal_router

app = FastAPI(
    title="Vakros SOC Agent API",
    description="Agentic Security Operations Center — powered by Claude + Supabase pgvector",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.environ.get("VAKROS_API_KEY", "dev-key-change-in-production")

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(docuseal_router)

# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return x_api_key


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class QueryRequest(BaseModel):
    query: str = Field(
        ...,
        description="Security question, alert description, or threat to investigate.",
        examples=["We're seeing unusual outbound traffic on port 443 from 3 internal hosts. Could this be C2?"]
    )
    context: Optional[str] = Field(
        None,
        description="Optional context: asset names, environment, prior findings.",
    )
    collection: str = Field(
        default="threat_intel",
        description="Knowledge base collection to search.",
    )


class QueryResponse(BaseModel):
    summary: str
    severity: str
    findings: list[str]
    recommendations: list[str]
    escalated: bool
    latency_ms: int
    raw_response: Optional[str] = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vakros-soc-agent", "version": "0.1.0"}


@app.post("/query", response_model=QueryResponse)
def query_agent(
    request: QueryRequest,
    _: str = Depends(verify_api_key),
):
    """
    Run the Vakros SOC agent on a security query.

    The agent will:
    1. Search the knowledge base for relevant threat intel
    2. Reason over the findings using Claude
    3. Return a structured security assessment
    4. Auto-escalate if severity is CRITICAL
    """
    start = time.time()
    try:
        result = run_agent(
            query=request.query,
            context=request.context,
            collection=request.collection,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")

    latency_ms = int((time.time() - start) * 1000)

    return QueryResponse(
        summary=result.get("summary", ""),
        severity=result.get("severity", "UNKNOWN"),
        findings=result.get("findings", []),
        recommendations=result.get("recommendations", []),
        escalated=result.get("escalated", False),
        latency_ms=latency_ms,
        raw_response=result.get("raw_response"),
    )
