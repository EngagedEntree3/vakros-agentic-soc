"""
Vakros Multi-Agent Orchestration Layer
LangGraph-style graph-based agent state machine.

Inspired by agentic-soc-platform's agent orchestration pattern:
  "Graph nodes are agents. Edges are routing decisions based on
   confidence, severity, and HITL boundary classification."

Architecture:
  Alert In
    └─ [SOC1 Triage Node]
         ├─ benign (conf ≥ 0.90)          → [Close Case Node]
         ├─ suspicious                     → [Enrichment Node] → [SOC1 re-eval]
         ├─ confirmed_threat (conf ≥ 0.85) → [SOC2 Investigation Node]
         │                                    ├─ risk < 75      → [Containment Node]
         │                                    └─ risk ≥ 75      → [Hunt Node]
         └─ escalate                       → [HITL Gate Node]
                                               ├─ approved       → [SOC2 Investigation]
                                               └─ denied/timeout → [Hold Queue]

The graph is fully async, tenant-isolated, and logs every state transition
to the immutable audit ledger.
"""

from .graph import (
    AgentGraph,
    AgentState,
    GraphConfig,
    NodeResult,
    RoutingDecision,
    HITLRequest,
)

__all__ = [
    "AgentGraph",
    "AgentState",
    "GraphConfig",
    "NodeResult",
    "RoutingDecision",
    "HITLRequest",
]
