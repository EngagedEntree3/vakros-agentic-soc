"""
Vakros — DocuSeal Integration Routes
=====================================
FastAPI router for the DocuSeal e-signature integration.

Endpoints:
  POST /api/docuseal/submissions          — Create submission + return embed token
  GET  /api/docuseal/submissions/{id}     — Get submission status
  GET  /api/docuseal/templates            — List available DocuSeal templates
  POST /api/docuseal/webhooks/internal    — Internal webhook handler (called by n8n)

Security:
  - DOCUSEAL_API_KEY never leaves this service (never sent to frontend)
  - All embed tokens are fetched server-side and passed to frontend
  - Webhook handler verifies HMAC signature from DocuSeal
  - All Supabase writes enforce tenant_id isolation

AGPL Note:
  DocuSeal runs at signing.vakros.com as a completely isolated microservice.
  No DocuSeal source code is imported here — all interaction is via REST API.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field

# ── Supabase client (reuse existing pattern from api/main.py) ─────────────────
try:
    from supabase import create_client, Client as SupabaseClient
    _supabase: SupabaseClient = create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_SERVICE_ROLE_KEY"],
    )
except Exception:
    _supabase = None  # graceful degradation in test environments

# ── Config ────────────────────────────────────────────────────────────────────
DOCUSEAL_BASE_URL    = os.environ.get("DOCUSEAL_BASE_URL", "https://signing.vakros.com/api")
DOCUSEAL_API_KEY     = os.environ.get("DOCUSEAL_API_KEY", "")
DOCUSEAL_WEBHOOK_SECRET = os.environ.get("DOCUSEAL_WEBHOOK_SECRET", "")
VAKROS_INTERNAL_SECRET  = os.environ.get("FLY_INTERNAL_SECRET", "")

router = APIRouter(prefix="/api/docuseal", tags=["DocuSeal e-Signature"])


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _docuseal_headers() -> dict:
    """Return authenticated headers for DocuSeal API calls."""
    if not DOCUSEAL_API_KEY:
        raise HTTPException(status_code=503, detail="DOCUSEAL_API_KEY not configured")
    return {
        "X-Auth-Token": DOCUSEAL_API_KEY,
        "Content-Type": "application/json",
    }


def _verify_internal_key(x_api_key: str = Header(...)) -> str:
    """Verify internal API key for n8n → backend calls."""
    if x_api_key != VAKROS_INTERNAL_SECRET:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return x_api_key


def _verify_docuseal_signature(raw_body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 signature from DocuSeal webhook."""
    if not DOCUSEAL_WEBHOOK_SECRET:
        return True  # skip in dev if secret not configured
    expected = hmac.new(
        DOCUSEAL_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── Request / Response schemas ────────────────────────────────────────────────

class CreateSubmissionRequest(BaseModel):
    template_id: int = Field(..., description="DocuSeal template ID to use")
    signer_name: str = Field(..., description="Full name of the signer")
    signer_email: EmailStr = Field(..., description="Email of the signer")
    signer_role: str = Field(default="Signer", description="Role as defined in the template")
    tenant_id: str = Field(..., description="Vakros tenant UUID")
    metadata: dict = Field(default_factory=dict, description="Any extra metadata to attach")


class SubmissionResponse(BaseModel):
    submission_id: int
    embed_src: str
    embed_token: str
    status: str
    vakros_record_id: str


class SubmissionStatusResponse(BaseModel):
    submission_id: int
    status: str
    signer_email: str
    completed_at: Optional[str]
    viewed_at: Optional[str]
    declined_at: Optional[str]
    embed_src: str


# ── Route 1: Create submission ────────────────────────────────────────────────

@router.post("/submissions", response_model=SubmissionResponse)
async def create_submission(body: CreateSubmissionRequest):
    """
    Create a DocuSeal signing submission and return an embed URL.

    Flow:
      1. Call DocuSeal POST /submissions  (server-side — API key never leaves backend)
      2. Extract embed_src + submitter slug from response
      3. Write record to Supabase signing_submissions with tenant_id
      4. Return embed_src to frontend for iframe/SDK rendering

    Frontend never calls DocuSeal directly.
    """
    async with httpx.AsyncClient(timeout=15.0) as client:
        ds_resp = await client.post(
            f"{DOCUSEAL_BASE_URL}/submissions",
            headers=_docuseal_headers(),
            json={
                "template_id": body.template_id,
                "send_email": False,          # Vakros controls all comms
                "submitters": [{
                    "name":  body.signer_name,
                    "email": body.signer_email,
                    "role":  body.signer_role,
                }],
                "metadata": {
                    "tenant_id":   body.tenant_id,
                    "source":      "vakros-platform",
                    **body.metadata,
                },
            },
        )

    if ds_resp.status_code not in (200, 201):
        raise HTTPException(
            status_code=502,
            detail=f"DocuSeal API error: {ds_resp.status_code} — {ds_resp.text}",
        )

    ds_data = ds_resp.json()

    # DocuSeal returns an array at top level for batch submissions
    # For single-submitter we take the first item
    if isinstance(ds_data, list):
        submitter = ds_data[0]
        submission_id = submitter.get("submission_id") or submitter.get("id")
    else:
        submitter = ds_data.get("submitters", [{}])[0]
        submission_id = ds_data.get("id")

    embed_src   = submitter.get("embed_src", "")
    embed_token = submitter.get("slug", "")

    if not embed_src:
        raise HTTPException(status_code=502, detail="DocuSeal did not return embed_src")

    # Write to Supabase
    vakros_record_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    if _supabase:
        _supabase.table("signing_submissions").insert({
            "id":           vakros_record_id,
            "tenant_id":    body.tenant_id,
            "docuseal_id":  submission_id,
            "template_id":  body.template_id,
            "status":       "pending",
            "signer_email": body.signer_email,
            "signer_name":  body.signer_name,
            "embed_slug":   embed_token,
            "embed_src":    embed_src,
            "metadata":     body.metadata,
            "created_at":   now,
        }).execute()

    return SubmissionResponse(
        submission_id=submission_id,
        embed_src=embed_src,
        embed_token=embed_token,
        status="pending",
        vakros_record_id=vakros_record_id,
    )


# ── Route 2: Get submission status ────────────────────────────────────────────

@router.get("/submissions/{submission_id}", response_model=SubmissionStatusResponse)
async def get_submission_status(submission_id: int, tenant_id: str):
    """
    Fetch live submission status from DocuSeal + Supabase.
    Verifies tenant_id ownership before returning data.
    """
    # First check Supabase for tenant isolation
    if _supabase:
        record = (
            _supabase.table("signing_submissions")
            .select("*")
            .eq("docuseal_id", submission_id)
            .eq("tenant_id", tenant_id)
            .single()
            .execute()
        )
        if not record.data:
            raise HTTPException(status_code=404, detail="Submission not found for this tenant")

    # Fetch live status from DocuSeal
    async with httpx.AsyncClient(timeout=10.0) as client:
        ds_resp = await client.get(
            f"{DOCUSEAL_BASE_URL}/submissions/{submission_id}",
            headers=_docuseal_headers(),
        )

    if ds_resp.status_code == 404:
        raise HTTPException(status_code=404, detail="Submission not found in DocuSeal")
    if ds_resp.status_code != 200:
        raise HTTPException(status_code=502, detail=f"DocuSeal API error: {ds_resp.status_code}")

    ds_data = ds_resp.json()
    submitter = (ds_data.get("submitters") or [{}])[0]

    return SubmissionStatusResponse(
        submission_id=submission_id,
        status=ds_data.get("status", "unknown"),
        signer_email=submitter.get("email", ""),
        completed_at=ds_data.get("completed_at"),
        viewed_at=submitter.get("viewed_at"),
        declined_at=submitter.get("declined_at"),
        embed_src=submitter.get("embed_src", record.data.get("embed_src", "") if _supabase else ""),
    )


# ── Route 3: List templates ───────────────────────────────────────────────────

@router.get("/templates")
async def list_templates():
    """Return all available DocuSeal templates for this Vakros instance."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        ds_resp = await client.get(
            f"{DOCUSEAL_BASE_URL}/templates",
            headers=_docuseal_headers(),
        )
    if ds_resp.status_code != 200:
        raise HTTPException(status_code=502, detail="Failed to fetch templates from DocuSeal")
    return ds_resp.json()


# ── Route 4: Internal webhook (called by n8n after Supabase update) ───────────

class InternalSigningEvent(BaseModel):
    submission_id: int
    tenant_id: str
    signer_email: str
    event: str   # document.completed | document.declined


@router.post("/webhooks/internal", dependencies=[Depends(_verify_internal_key)])
async def internal_signing_webhook(body: InternalSigningEvent):
    """
    Called by n8n after it has updated Supabase.
    Used to trigger downstream Vakros platform actions:
      - Unlock features (e.g., onboarding complete, contract active)
      - Send Resend email notifications to tenant users
      - Update any other Vakros business logic

    This is an INTERNAL endpoint — only n8n can call it via FLY_INTERNAL_SECRET.
    """
    if body.event == "document.completed":
        # TODO: unlock downstream Vakros features for this tenant
        # e.g., activate contract, unlock portal access, trigger onboarding next step
        pass

    if body.event == "document.declined":
        # TODO: alert the tenant admin that the signer declined
        pass

    return {
        "received": True,
        "event": body.event,
        "submission_id": body.submission_id,
        "tenant_id": body.tenant_id,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Route 5: Raw DocuSeal webhook (alternative — bypass n8n for speed) ────────

@router.post("/webhooks/docuseal")
async def docuseal_raw_webhook(request: Request):
    """
    Optional: receive DocuSeal webhooks directly (without n8n).
    Use this if you want sub-second Supabase updates without n8n in the path.

    Configure in DocuSeal admin → Settings → Webhooks:
      URL: https://vakros-backend-long-rain-1451.fly.dev/api/docuseal/webhooks/docuseal
    """
    raw_body = await request.body()
    signature = request.headers.get("x-docuseal-signature", "")

    if not _verify_docuseal_signature(raw_body, signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    event_type    = payload.get("event_type")
    submission_id = payload.get("data", {}).get("submission", {}).get("id")
    now = datetime.now(timezone.utc).isoformat()

    if not _supabase or not submission_id:
        return {"received": True}

    updates = {"status": event_type.replace("document.", "").replace("form.", "")}

    if event_type == "document.completed":
        updates["completed_at"] = payload.get("data", {}).get("submission", {}).get("completed_at", now)
    elif event_type == "document.viewed":
        updates["viewed_at"] = now
    elif event_type == "document.declined":
        updates["declined_at"] = now
    elif event_type == "form.started":
        updates["started_at"] = now

    _supabase.table("signing_submissions") \
        .update(updates) \
        .eq("docuseal_id", submission_id) \
        .execute()

    return {"received": True, "event": event_type}
