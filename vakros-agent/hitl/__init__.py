"""
Vakros HITL — Human-In-The-Loop approval gate.
Inspired by CyberStrikeAI's HITL workflow pattern.

High-risk SOC actions (isolate host, block IP, delete artefact) must be
approved by a human analyst before execution. This module:
  - Stores pending approvals in Supabase
  - Exposes a REST endpoint via the MCP server / webhook
  - Provides async wait-for-approval with configurable timeout
  - Falls back to auto-deny on timeout
"""

from .approval import HITLApprovalGate, ApprovalRequest, ApprovalStatus, RiskLevel

__all__ = ["HITLApprovalGate", "ApprovalRequest", "ApprovalStatus", "RiskLevel"]
