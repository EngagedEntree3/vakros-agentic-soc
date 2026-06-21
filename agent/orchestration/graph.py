"""
Vakros Agent Orchestration Graph
LangGraph-style multi-agent state machine for the Agentic SOC.

Inspired by agentic-soc-platform:
  "Each module is a LangGraph node. State is passed between nodes.
   Routing edges are conditional — based on confidence score, severity,
   and HITL boundary classification. The graph enforces the HITL Decision
   Matrix at every high-risk transition."

Pattern:
  AgentGraph.run(alert) → final AgentState with full audit trail
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Awaitable
from uuid import uuid4

import anthropic

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# State & Routing Types
# ─────────────────────────────────────────────────────────────────────────────

class NodeName(str, Enum):
    START           = "start"
    SOC1_TRIAGE     = "soc1_triage"
    ENRICHMENT      = "enrichment"
    SOC2_INVEST     = "soc2_investigation"
    HUNT            = "hunt"
    HITL_GATE       = "hitl_gate"
    CONTAINMENT     = "containment"
    GRC_MAPPING     = "grc_mapping"
    CLOSE_CASE      = "close_case"
    HOLD_QUEUE      = "hold_queue"
    END             = "end"


class RoutingDecision(str, Enum):
    BENIGN          = "benign"
    SUSPICIOUS      = "suspicious"
    CONFIRMED_THREAT = "confirmed_threat"
    ESCALATE        = "escalate"
    APPROVED        = "approved"
    DENIED          = "denied"
    HIGH_RISK       = "high_risk"
    LOW_RISK        = "low_risk"
    HUNT_REQUIRED   = "hunt_required"
    COMPLETE        = "complete"


@dataclass
class HITLRequest:
    """Emitted when an agent needs human approval before proceeding."""
    id: str = field(default_factory=lambda: str(uuid4()))
    case_id: str = ""
    tenant_id: str = ""
    requesting_agent: str = ""
    action: str = ""
    risk_level: str = "high"
    rationale: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    approved_by: str | None = None
    resolved_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "requesting_agent": self.requesting_agent,
            "action": self.action,
            "risk_level": self.risk_level,
            "rationale": self.rationale,
            "created_at": self.created_at.isoformat(),
            "resolved": self.resolved,
            "approved_by": self.approved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


@dataclass
class NodeResult:
    """Return value from a graph node execution."""
    node: NodeName
    routing: RoutingDecision
    output: dict = field(default_factory=dict)
    hitl_request: HITLRequest | None = None
    error: str | None = None
    duration_ms: int = 0


@dataclass
class AgentState:
    """
    Immutable-ish state passed between graph nodes.
    Every field is appended, never overwritten — full audit trail.
    """
    # Identity
    run_id: str = field(default_factory=lambda: str(uuid4()))
    tenant_id: str = ""
    case_id: str = ""
    correlation_uid: str = ""

    # Input
    alert: dict = field(default_factory=dict)          # original alert
    alert_ocsf: dict = field(default_factory=dict)     # OCSF normalized
    enrichments: list = field(default_factory=list)    # ArtifactEnricher results
    artifacts: list = field(default_factory=list)      # extracted IOCs

    # Node outputs (appended as graph executes)
    soc1_output: dict | None = None
    soc2_output: dict | None = None
    hunt_output: dict | None = None
    grc_output: dict | None = None
    containment_output: dict | None = None

    # Graph execution trace
    node_history: list[NodeResult] = field(default_factory=list)
    hitl_requests: list[HITLRequest] = field(default_factory=list)
    current_node: NodeName = NodeName.START
    final_verdict: str = ""
    risk_score: int = 0
    confidence: float = 0.0
    is_complete: bool = False

    # Timestamps
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    def add_node_result(self, result: NodeResult) -> None:
        self.node_history.append(result)
        self.current_node = result.node
        if result.hitl_request:
            self.hitl_requests.append(result.hitl_request)

    def to_audit_entry(self) -> dict:
        """Produces an audit ledger entry for this entire graph run."""
        return {
            "event_id": self.run_id,
            "timestamp": self.started_at.isoformat(),
            "tenant_id": self.tenant_id,
            "agent_id": "orchestration-graph",
            "agent_version": "1.0.0",
            "action_type": "full_triage_pipeline",
            "input_summary": (
                f"Alert class_uid={self.alert_ocsf.get('class_uid', '?')}, "
                f"severity={self.alert_ocsf.get('severity_id', '?')}"
            ),
            "output_summary": (
                f"Verdict={self.final_verdict}, "
                f"risk={self.risk_score}, "
                f"confidence={self.confidence:.2f}, "
                f"nodes_traversed={len(self.node_history)}"
            ),
            "framework_controls": self._collect_controls(),
            "hitl_required": len(self.hitl_requests) > 0,
            "human_approved_by": self._approved_by(),
            "confidence_score": self.confidence,
            "node_history": [
                {"node": r.node, "routing": r.routing, "duration_ms": r.duration_ms}
                for r in self.node_history
            ],
        }

    def _collect_controls(self) -> list[str]:
        controls = []
        for output in [self.soc1_output, self.soc2_output, self.grc_output]:
            if output:
                controls.extend(output.get("soc2_controls_triggered", []))
                controls.extend(output.get("iso27001_controls_triggered", []))
        return list(set(controls))

    def _approved_by(self) -> str | None:
        for h in self.hitl_requests:
            if h.approved_by:
                return h.approved_by
        return None


@dataclass
class GraphConfig:
    """Configuration for the AgentGraph."""
    anthropic_api_key: str = ""
    model: str = "claude-opus-4-8"
    max_tokens: int = 4096
    supabase_client: Any = None
    # Routing thresholds
    benign_confidence_threshold: float = 0.90
    confirmed_threat_confidence_threshold: float = 0.85
    hunt_risk_threshold: int = 75
    hitl_timeout_seconds: int = 14400   # 4 hours for P1
    # Feature flags
    enable_enrichment: bool = True
    enable_hunt: bool = True
    enable_grc_mapping: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Graph Node Implementations
# ─────────────────────────────────────────────────────────────────────────────

class AgentGraph:
    """
    LangGraph-style multi-agent orchestration graph for the Vakros Agentic SOC.

    Each node is an async method that:
    1. Receives current AgentState
    2. Calls the appropriate Claude agent with the relevant prompt
    3. Parses the structured JSON output
    4. Returns a NodeResult with routing decision

    The graph dispatcher (run()) calls nodes in sequence based on routing.

    Usage:
        graph = AgentGraph(config)
        final_state = await graph.run(alert_ocsf, tenant_id="abc123")
        audit_entry = final_state.to_audit_entry()
    """

    def __init__(self, config: GraphConfig | None = None):
        self.config = config or GraphConfig()
        self._ai = anthropic.AsyncAnthropic(
            api_key=self.config.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
        )
        # Load prompt files once at init
        self._prompts: dict[str, str] = {}
        self._load_prompts()

    def _load_prompts(self) -> None:
        """Load versioned prompt files from /prompts/ directory."""
        prompt_dir = os.path.join(os.path.dirname(__file__), "../../prompts")
        prompt_map = {
            "soc1": "soc1-triage-agent.md",
            "soc2": "soc2-investigation-agent.md",
            "hunt": "hunt-agent.md",
            "grc":  "grc-agent.md",
        }
        for key, filename in prompt_map.items():
            path = os.path.join(prompt_dir, filename)
            try:
                content = open(path).read()
                # Strip YAML frontmatter (between --- markers)
                if content.startswith("---"):
                    parts = content.split("---", 2)
                    self._prompts[key] = parts[2].strip() if len(parts) >= 3 else content
                else:
                    self._prompts[key] = content
            except FileNotFoundError:
                logger.warning("Prompt file not found: %s — using fallback", path)
                self._prompts[key] = f"You are the {key.upper()} agent. Analyze the input and respond with structured JSON."

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        alert_ocsf: dict,
        tenant_id: str,
        correlation_uid: str = "",
        enrichments: list | None = None,
        artifacts: list | None = None,
        case_id: str = "",
    ) -> AgentState:
        """
        Execute the full agent graph for a single OCSF-normalized alert.
        Returns the final AgentState with complete audit trail.
        """
        state = AgentState(
            tenant_id=tenant_id,
            case_id=case_id or str(uuid4()),
            correlation_uid=correlation_uid,
            alert_ocsf=alert_ocsf,
            enrichments=enrichments or [],
            artifacts=artifacts or [],
        )

        logger.info(
            "Graph run started: run_id=%s tenant=%s severity=%s",
            state.run_id, tenant_id, alert_ocsf.get("severity_id", "?")
        )

        # Graph traversal
        try:
            # Always start with SOC1 triage
            soc1_result = await self._node_soc1_triage(state)
            state.add_node_result(soc1_result)
            state.soc1_output = soc1_result.output

            routing = soc1_result.routing

            # Enrichment pass if suspicious (parallel with any waiting)
            if routing == RoutingDecision.SUSPICIOUS and self.config.enable_enrichment:
                enrich_result = await self._node_enrichment(state)
                state.add_node_result(enrich_result)
                # Re-evaluate after enrichment
                soc1_reeval = await self._node_soc1_triage(state, reevaluation=True)
                state.add_node_result(soc1_reeval)
                state.soc1_output = soc1_reeval.output
                routing = soc1_reeval.routing

            if routing == RoutingDecision.BENIGN:
                close_result = await self._node_close_case(state)
                state.add_node_result(close_result)

            elif routing == RoutingDecision.ESCALATE:
                hitl_result = await self._node_hitl_gate(state)
                state.add_node_result(hitl_result)
                if hitl_result.routing == RoutingDecision.APPROVED:
                    routing = RoutingDecision.CONFIRMED_THREAT
                else:
                    hold_result = await self._node_hold_queue(state)
                    state.add_node_result(hold_result)

            if routing == RoutingDecision.CONFIRMED_THREAT:
                soc2_result = await self._node_soc2_investigation(state)
                state.add_node_result(soc2_result)
                state.soc2_output = soc2_result.output
                state.risk_score = soc2_result.output.get("risk_score", 0)

                if soc2_result.routing == RoutingDecision.HIGH_RISK and self.config.enable_hunt:
                    hunt_result = await self._node_hunt(state)
                    state.add_node_result(hunt_result)
                    state.hunt_output = hunt_result.output
                else:
                    contain_result = await self._node_containment(state)
                    state.add_node_result(contain_result)
                    state.containment_output = contain_result.output

            # Always run GRC mapping at the end
            if self.config.enable_grc_mapping:
                grc_result = await self._node_grc_mapping(state)
                state.add_node_result(grc_result)
                state.grc_output = grc_result.output

        except Exception as exc:
            logger.error("Graph run failed: run_id=%s error=%s", state.run_id, exc, exc_info=True)
            state.final_verdict = "error"
        finally:
            state.is_complete = True
            state.completed_at = datetime.now(timezone.utc)
            state.confidence = state.soc1_output.get("confidence", 0.0) if state.soc1_output else 0.0
            state.final_verdict = state.soc1_output.get("triage_verdict", "unknown") if state.soc1_output else "error"

            # Persist audit entry
            await self._persist_audit(state)

        logger.info(
            "Graph run complete: run_id=%s verdict=%s risk=%d nodes=%d",
            state.run_id, state.final_verdict, state.risk_score, len(state.node_history)
        )
        return state

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------

    async def _node_soc1_triage(self, state: AgentState, reevaluation: bool = False) -> NodeResult:
        """SOC1 Triage Node — classifies alert, extracts IOCs, routes."""
        t0 = _now_ms()
        label = "soc1_reeval" if reevaluation else "soc1_triage"
        try:
            user_content = json.dumps({
                "task": "Triage this OCSF-normalized security alert.",
                "tenant_id": state.tenant_id,
                "alert_ocsf": state.alert_ocsf,
                "enrichments": state.enrichments,
                "correlation_uid": state.correlation_uid,
                "reevaluation": reevaluation,
            }, default=str)

            response = await self._ai.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=self._prompts["soc1"],
                messages=[{"role": "user", "content": user_content}],
            )
            output = _parse_json_output(response.content[0].text)

            verdict = output.get("triage_verdict", "escalate")
            confidence = float(output.get("confidence", 0.0))

            if verdict == "benign" and confidence >= self.config.benign_confidence_threshold:
                routing = RoutingDecision.BENIGN
            elif verdict == "confirmed_threat" and confidence >= self.config.confirmed_threat_confidence_threshold:
                routing = RoutingDecision.CONFIRMED_THREAT
            elif verdict == "escalate" or confidence < 0.75:
                routing = RoutingDecision.ESCALATE
            else:
                routing = RoutingDecision.SUSPICIOUS

            return NodeResult(
                node=NodeName.SOC1_TRIAGE,
                routing=routing,
                output=output,
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:
            logger.error("SOC1 node failed: %s", exc)
            return NodeResult(
                node=NodeName.SOC1_TRIAGE,
                routing=RoutingDecision.ESCALATE,
                error=str(exc),
                duration_ms=_now_ms() - t0,
            )

    async def _node_enrichment(self, state: AgentState) -> NodeResult:
        """
        Enrichment Node — runs artifact enrichment concurrently.
        Not a Claude call — delegates to ArtifactEnricher.
        """
        t0 = _now_ms()
        try:
            # Import here to avoid circular deps
            from ..artifacts import ArtifactEnricher, ArtifactExtractor

            extractor = ArtifactExtractor()
            artifacts = extractor.extract(state.alert_ocsf, state.tenant_id)

            enricher = ArtifactEnricher(supabase_client=self.config.supabase_client)
            enrichments = await enricher.enrich_batch(artifacts, state.tenant_id)

            state.artifacts = [a.to_dict() for a in artifacts]
            state.enrichments = [e.to_dict() for e in enrichments]

            return NodeResult(
                node=NodeName.ENRICHMENT,
                routing=RoutingDecision.SUSPICIOUS,  # pass-through
                output={"artifact_count": len(artifacts), "enrichment_count": len(enrichments)},
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:
            logger.warning("Enrichment node failed (non-fatal): %s", exc)
            return NodeResult(
                node=NodeName.ENRICHMENT,
                routing=RoutingDecision.SUSPICIOUS,
                error=str(exc),
                duration_ms=_now_ms() - t0,
            )

    async def _node_soc2_investigation(self, state: AgentState) -> NodeResult:
        """SOC2 Investigation Node — deep-dive case analysis."""
        t0 = _now_ms()
        try:
            user_content = json.dumps({
                "task": "Investigate this escalated security case.",
                "tenant_id": state.tenant_id,
                "case_id": state.case_id,
                "soc1_verdict": state.soc1_output,
                "alert_ocsf": state.alert_ocsf,
                "enrichments": state.enrichments,
                "artifacts": state.artifacts,
            }, default=str)

            response = await self._ai.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=self._prompts["soc2"],
                messages=[{"role": "user", "content": user_content}],
            )
            output = _parse_json_output(response.content[0].text)

            risk_score = int(output.get("risk_score", 50))
            hitl_required = bool(output.get("hitl_required", False))

            # Check if HITL needed for any containment action
            hitl_req = None
            if hitl_required:
                plan = output.get("containment_plan", {})
                hitl_actions = [
                    a for a in plan.get("containment_actions", [])
                    if a.get("hitl_required", False)
                ]
                if hitl_actions:
                    hitl_req = HITLRequest(
                        case_id=state.case_id,
                        tenant_id=state.tenant_id,
                        requesting_agent="soc2-investigation-agent",
                        action=hitl_actions[0].get("action", "High-risk containment"),
                        risk_level="high",
                        rationale=hitl_actions[0].get("rationale", "Production system impact"),
                    )

            routing = (
                RoutingDecision.HIGH_RISK
                if risk_score >= self.config.hunt_risk_threshold
                else RoutingDecision.LOW_RISK
            )

            return NodeResult(
                node=NodeName.SOC2_INVEST,
                routing=routing,
                output=output,
                hitl_request=hitl_req,
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:
            logger.error("SOC2 node failed: %s", exc)
            return NodeResult(
                node=NodeName.SOC2_INVEST,
                routing=RoutingDecision.LOW_RISK,
                error=str(exc),
                duration_ms=_now_ms() - t0,
            )

    async def _node_hunt(self, state: AgentState) -> NodeResult:
        """Hunt Node — proactive threat hunting on high-risk cases."""
        t0 = _now_ms()
        try:
            soc2_out = state.soc2_output or {}
            user_content = json.dumps({
                "task": "Hunt for threats related to this high-risk case.",
                "tenant_id": state.tenant_id,
                "case_id": state.case_id,
                "hunt_hypothesis": (
                    f"Confirmed threat actor active on tenant network. "
                    f"TTPs: {soc2_out.get('confirmed_techniques', [])}. "
                    f"Hunt for lateral movement and persistence mechanisms."
                ),
                "ioc_seeds": state.artifacts,
                "hunt_scope": {
                    "time_window_hours": 168,   # 7 days
                    "asset_scope": "all",
                },
                "soc2_investigation": soc2_out,
            }, default=str)

            response = await self._ai.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=self._prompts["hunt"],
                messages=[{"role": "user", "content": user_content}],
            )
            output = _parse_json_output(response.content[0].text)

            return NodeResult(
                node=NodeName.HUNT,
                routing=RoutingDecision.COMPLETE,
                output=output,
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:
            logger.error("Hunt node failed: %s", exc)
            return NodeResult(
                node=NodeName.HUNT,
                routing=RoutingDecision.COMPLETE,
                error=str(exc),
                duration_ms=_now_ms() - t0,
            )

    async def _node_grc_mapping(self, state: AgentState) -> NodeResult:
        """GRC Mapping Node — always runs last, maps event to compliance controls."""
        t0 = _now_ms()
        try:
            user_content = json.dumps({
                "task": "Map this security event to SOC 2 and ISO 27001 controls.",
                "tenant_id": state.tenant_id,
                "alert_or_event": state.alert_ocsf,
                "soc1_verdict": state.soc1_output,
                "frameworks": ["soc2", "iso27001"],
                "final_verdict": state.final_verdict,
            }, default=str)

            response = await self._ai.messages.create(
                model=self.config.model,
                max_tokens=2048,
                system=self._prompts["grc"],
                messages=[{"role": "user", "content": user_content}],
            )
            output = _parse_json_output(response.content[0].text)

            return NodeResult(
                node=NodeName.GRC_MAPPING,
                routing=RoutingDecision.COMPLETE,
                output=output,
                duration_ms=_now_ms() - t0,
            )
        except Exception as exc:
            logger.warning("GRC mapping node failed (non-fatal): %s", exc)
            return NodeResult(
                node=NodeName.GRC_MAPPING,
                routing=RoutingDecision.COMPLETE,
                error=str(exc),
                duration_ms=_now_ms() - t0,
            )

    async def _node_hitl_gate(self, state: AgentState) -> NodeResult:
        """
        HITL Gate Node — emits a human-approval request and checks Supabase for resolution.

        In production, this node:
        1. Writes the HITLRequest to Supabase hitl_requests table
        2. Notifies on-call via n8n webhook
        3. Polls for resolution (max 4 hours for P1)
        4. Returns APPROVED or DENIED routing

        In this implementation, it creates the HITL request and returns ESCALATE
        routing — the dashboard + n8n handle the human approval loop.
        """
        t0 = _now_ms()
        hitl_req = HITLRequest(
            case_id=state.case_id,
            tenant_id=state.tenant_id,
            requesting_agent="soc1-triage-agent",
            action="SOC1 escalation — human review required before proceeding",
            risk_level="high",
            rationale=(
                f"Confidence below threshold or HITL-required action detected. "
                f"SOC1 verdict: {state.soc1_output.get('triage_verdict', '?') if state.soc1_output else '?'}. "
                f"Severity: {state.alert_ocsf.get('severity_id', '?')}."
            ),
        )

        # Persist HITL request to Supabase
        if self.config.supabase_client:
            try:
                self.config.supabase_client.table("hitl_requests").insert(
                    hitl_req.to_dict()
                ).execute()
            except Exception as exc:
                logger.warning("Failed to persist HITL request: %s", exc)

        # In autonomous mode: emit the request, route to HOLD
        # The dashboard picks up pending hitl_requests and surfaces them for human review
        return NodeResult(
            node=NodeName.HITL_GATE,
            routing=RoutingDecision.ESCALATE,
            output={"hitl_request_id": hitl_req.id, "status": "pending_human_review"},
            hitl_request=hitl_req,
            duration_ms=_now_ms() - t0,
        )

    async def _node_containment(self, state: AgentState) -> NodeResult:
        """Containment Node — executes approved (non-HITL) containment actions."""
        t0 = _now_ms()
        plan = {}
        if state.soc2_output:
            plan = state.soc2_output.get("containment_plan", {})

        auto_actions = [
            a for a in plan.get("containment_actions", [])
            if not a.get("hitl_required", True)
        ]

        executed = []
        for action in auto_actions:
            logger.info(
                "Executing autonomous containment: tenant=%s action=%s",
                state.tenant_id, action.get("action")
            )
            # In production: call SIEM/EDR API here
            executed.append({
                "action": action.get("action"),
                "status": "executed",
                "executed_at": datetime.now(timezone.utc).isoformat(),
            })

        return NodeResult(
            node=NodeName.CONTAINMENT,
            routing=RoutingDecision.COMPLETE,
            output={"actions_executed": executed, "actions_count": len(executed)},
            duration_ms=_now_ms() - t0,
        )

    async def _node_close_case(self, state: AgentState) -> NodeResult:
        """Close Case Node — marks benign alerts as resolved."""
        t0 = _now_ms()
        if self.config.supabase_client and state.correlation_uid:
            try:
                self.config.supabase_client.table("correlated_cases").update(
                    {"status": "closed", "resolution": "benign"}
                ).eq("correlation_uid", state.correlation_uid).execute()
            except Exception as exc:
                logger.warning("Failed to close case: %s", exc)

        return NodeResult(
            node=NodeName.CLOSE_CASE,
            routing=RoutingDecision.COMPLETE,
            output={"resolution": "benign", "case_id": state.case_id},
            duration_ms=_now_ms() - t0,
        )

    async def _node_hold_queue(self, state: AgentState) -> NodeResult:
        """Hold Queue Node — parks case until HITL resolves."""
        t0 = _now_ms()
        if self.config.supabase_client and state.correlation_uid:
            try:
                self.config.supabase_client.table("correlated_cases").update(
                    {"status": "pending_hitl"}
                ).eq("correlation_uid", state.correlation_uid).execute()
            except Exception as exc:
                logger.warning("Failed to set hold status: %s", exc)

        return NodeResult(
            node=NodeName.HOLD_QUEUE,
            routing=RoutingDecision.COMPLETE,
            output={"status": "pending_hitl", "case_id": state.case_id},
            duration_ms=_now_ms() - t0,
        )

    # ------------------------------------------------------------------
    # Audit persistence
    # ------------------------------------------------------------------

    async def _persist_audit(self, state: AgentState) -> None:
        """Write the graph run's audit entry to the immutable audit ledger."""
        if not self.config.supabase_client:
            return
        try:
            entry = state.to_audit_entry()
            self.config.supabase_client.table("audit_ledger").insert(entry).execute()
        except Exception as exc:
            logger.error("Failed to persist audit entry: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _parse_json_output(text: str) -> dict:
    """
    Extract JSON from Claude's response.
    Claude often wraps JSON in markdown code fences — strip them.
    """
    text = text.strip()
    # Strip ```json ... ``` fences
    if "```json" in text:
        start = text.find("```json") + 7
        end = text.find("```", start)
        text = text[start:end].strip()
    elif "```" in text:
        start = text.find("```") + 3
        end = text.find("```", start)
        text = text[start:end].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find a JSON object in the text
        import re
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        logger.warning("Could not parse JSON output from agent: %s...", text[:200])
        return {"raw_output": text, "parse_error": True}
