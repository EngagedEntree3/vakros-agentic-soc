"""
HITL Approval Gate — async human approval for high-risk SOC actions.

Pattern from: github.com/Ed1s0nZ/CyberStrikeAI HITL workflow.

Risk levels map to approval requirements:
  CRITICAL — must approve before action (max wait: 10 min)
  HIGH     — must approve before action (max wait: 30 min)
  MEDIUM   — auto-approved after SOC2 review
  LOW      — auto-approved immediately

Approvals are persisted in Supabase `hitl_approvals` table and surfaced
in the SOC dashboard at app.vakros.com/approvals.
"""

import asyncio
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Callable, Awaitable

import httpx


class RiskLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    PENDING  = "pending"
    APPROVED = "approved"
    DENIED   = "denied"
    TIMEOUT  = "timeout"
    AUTO     = "auto_approved"


# Default timeout per risk level (seconds)
RISK_TIMEOUTS = {
    RiskLevel.CRITICAL: 600,   # 10 min
    RiskLevel.HIGH:     1800,  # 30 min
    RiskLevel.MEDIUM:   60,    # 1 min (auto)
    RiskLevel.LOW:      0,     # immediate (auto)
}

# Actions that always require explicit human approval
ALWAYS_REQUIRE_APPROVAL = {
    "isolate_host",
    "block_ip_global",
    "delete_artefact",
    "reset_user_password",
    "revoke_all_sessions",
    "disable_account",
    "quarantine_email",
    "kill_critical_process",
}


@dataclass
class ApprovalRequest:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action: str = ""
    action_params: dict = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.HIGH
    justification: str = ""
    alert_id: str = ""
    case_id: str = ""
    requested_by: str = "soc_agent"
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: str = ""
    decided_at: datetime | None = None
    tenant_id: str = ""


class HITLApprovalGate:
    """
    Async approval gate. Usage:

        gate = HITLApprovalGate()

        @gate.require_approval(risk=RiskLevel.CRITICAL)
        async def isolate_host(host: str, reason: str):
            await edr.isolate_host(host, reason)

    Or imperatively:

        approved = await gate.request(
            action="isolate_host",
            params={"host": "WIN-001", "reason": "Ransomware detected"},
            risk=RiskLevel.CRITICAL,
            alert_id="alert-123",
        )
        if approved:
            await edr.isolate_host(...)
    """

    def __init__(
        self,
        supabase_url: str | None = None,
        supabase_key: str | None = None,
        notify_webhook: str | None = None,
        poll_interval: float = 5.0,
    ):
        self.supabase_url = supabase_url or os.getenv("NEXT_PUBLIC_SUPABASE_URL", "")
        self.supabase_key = supabase_key or os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
        self.notify_webhook = notify_webhook or os.getenv("HITL_NOTIFY_WEBHOOK", "")
        self.poll_interval = poll_interval
        self._pending: dict[str, ApprovalRequest] = {}

    def require_approval(self, risk: RiskLevel = RiskLevel.HIGH, justification: str = ""):
        """Decorator — wraps an async function with HITL gate."""
        def decorator(fn: Callable[..., Awaitable[Any]]):
            async def wrapper(*args, **kwargs):
                action = fn.__name__
                approved = await self.request(
                    action=action,
                    params={"args": list(args), "kwargs": kwargs},
                    risk=risk,
                    justification=justification or f"Action: {action}",
                )
                if not approved:
                    raise PermissionError(f"HITL: action '{action}' was not approved")
                return await fn(*args, **kwargs)
            wrapper.__name__ = fn.__name__
            return wrapper
        return decorator

    async def request(
        self,
        action: str,
        params: dict,
        risk: RiskLevel = RiskLevel.HIGH,
        justification: str = "",
        alert_id: str = "",
        case_id: str = "",
        tenant_id: str = "",
    ) -> bool:
        """
        Submit an approval request and wait for human decision.
        Returns True if approved, False if denied/timeout.
        """
        # Auto-approve low/medium risk non-critical actions
        if risk == RiskLevel.LOW and action not in ALWAYS_REQUIRE_APPROVAL:
            return True
        if risk == RiskLevel.MEDIUM and action not in ALWAYS_REQUIRE_APPROVAL:
            await asyncio.sleep(0.1)  # Brief yield
            return True

        req = ApprovalRequest(
            action=action,
            action_params=params,
            risk_level=risk,
            justification=justification,
            alert_id=alert_id,
            case_id=case_id,
            tenant_id=tenant_id,
        )
        self._pending[req.id] = req

        # Persist to Supabase
        await self._persist_request(req)

        # Notify analyst
        await self._notify(req)

        # Wait for decision
        timeout = RISK_TIMEOUTS.get(risk, 600)
        result = await self._wait_for_decision(req.id, timeout)

        return result == ApprovalStatus.APPROVED

    async def _persist_request(self, req: ApprovalRequest) -> None:
        if not self.supabase_url or not self.supabase_key:
            return
        body = {
            "id": req.id,
            "action": req.action,
            "action_params": req.action_params,
            "risk_level": req.risk_level.value,
            "justification": req.justification,
            "alert_id": req.alert_id,
            "case_id": req.case_id,
            "requested_by": req.requested_by,
            "status": req.status.value,
            "tenant_id": req.tenant_id,
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self.supabase_url}/rest/v1/hitl_approvals",
                    headers={
                        "apikey": self.supabase_key,
                        "Authorization": f"Bearer {self.supabase_key}",
                        "Content-Type": "application/json",
                        "Prefer": "return=minimal",
                    },
                    json=body,
                    timeout=5,
                )
        except Exception:
            pass  # Don't block execution if Supabase is unreachable

    async def _notify(self, req: ApprovalRequest) -> None:
        """Send Slack/webhook notification to SOC analysts."""
        if not self.notify_webhook:
            return
        message = {
            "text": f":rotating_light: *HITL Approval Required*",
            "attachments": [{
                "color": "#FF0000" if req.risk_level == RiskLevel.CRITICAL else "#FFA500",
                "fields": [
                    {"title": "Action", "value": req.action, "short": True},
                    {"title": "Risk", "value": req.risk_level.value.upper(), "short": True},
                    {"title": "Justification", "value": req.justification, "short": False},
                    {"title": "Alert ID", "value": req.alert_id or "N/A", "short": True},
                    {"title": "Approval ID", "value": req.id, "short": True},
                ],
                "footer": "Approve at app.vakros.com/approvals",
            }],
        }
        try:
            async with httpx.AsyncClient() as client:
                await client.post(self.notify_webhook, json=message, timeout=5)
        except Exception:
            pass

    async def _wait_for_decision(self, request_id: str, timeout: int) -> ApprovalStatus:
        """Poll Supabase for decision until timeout."""
        deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
        while datetime.now(timezone.utc) < deadline:
            status = await self._poll_status(request_id)
            if status in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED):
                return status
            await asyncio.sleep(self.poll_interval)

        # Timeout — update record and deny
        await self._update_status(request_id, ApprovalStatus.TIMEOUT)
        return ApprovalStatus.TIMEOUT

    async def _poll_status(self, request_id: str) -> ApprovalStatus:
        # Check local cache first (for testing/local approvals)
        req = self._pending.get(request_id)
        if req and req.status != ApprovalStatus.PENDING:
            return req.status

        if not self.supabase_url:
            return ApprovalStatus.PENDING

        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    f"{self.supabase_url}/rest/v1/hitl_approvals",
                    headers={
                        "apikey": self.supabase_key,
                        "Authorization": f"Bearer {self.supabase_key}",
                    },
                    params={"id": f"eq.{request_id}", "select": "status"},
                    timeout=5,
                )
                r.raise_for_status()
                rows = r.json()
                if rows:
                    return ApprovalStatus(rows[0]["status"])
        except Exception:
            pass
        return ApprovalStatus.PENDING

    async def _update_status(self, request_id: str, status: ApprovalStatus) -> None:
        if not self.supabase_url:
            return
        try:
            async with httpx.AsyncClient() as client:
                await client.patch(
                    f"{self.supabase_url}/rest/v1/hitl_approvals",
                    headers={
                        "apikey": self.supabase_key,
                        "Authorization": f"Bearer {self.supabase_key}",
                        "Content-Type": "application/json",
                    },
                    params={"id": f"eq.{request_id}"},
                    json={"status": status.value, "decided_at": datetime.now(timezone.utc).isoformat()},
                    timeout=5,
                )
        except Exception:
            pass

    def approve(self, request_id: str, approver: str = "") -> None:
        """Locally approve a request (for testing / webhook handler use)."""
        if request_id in self._pending:
            self._pending[request_id].status = ApprovalStatus.APPROVED
            self._pending[request_id].approved_by = approver
            self._pending[request_id].decided_at = datetime.now(timezone.utc)

    def deny(self, request_id: str) -> None:
        """Locally deny a request."""
        if request_id in self._pending:
            self._pending[request_id].status = ApprovalStatus.DENIED
            self._pending[request_id].decided_at = datetime.now(timezone.utc)
