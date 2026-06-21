"""
Vakros Agent Observability — Opik Tracing
Inspired by: https://github.com/patchy631/ai-engineering-hub/tree/main/eval-and-observability

Wraps the SOC agent loop with Opik traces so every tool call, retrieval,
and agent decision is logged and reviewable.

Usage:
    from eval.tracer import trace_agent_run
    result = trace_agent_run(alert_id="abc123", query="...", run_fn=run_agent)

Without Opik (dev mode):
    Falls back to structured console logging — no external dependency required.

Opik setup (optional but recommended for production):
    pip install opik
    opik configure   # enter API key from comet.com/opik
    export OPIK_PROJECT_NAME=vakros-soc-agent
"""

from __future__ import annotations

import os
import time
import json
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# ── Opik integration (graceful fallback) ─────────────────────────────────────

try:
    import opik
    from opik import track
    from opik.integrations.anthropic import track_anthropic

    OPIK_AVAILABLE = True
    OPIK_PROJECT = os.environ.get("OPIK_PROJECT_NAME", "vakros-soc-agent")
except ImportError:
    OPIK_AVAILABLE = False


# ── Span / trace data structures ─────────────────────────────────────────────

@dataclass
class ToolSpan:
    tool_name: str
    tool_input: dict
    tool_output: str = ""
    latency_ms: int = 0
    error: Optional[str] = None


@dataclass
class AgentTrace:
    trace_id: str
    alert_id: Optional[str]
    query: str
    tenant_id: Optional[str] = None
    iterations: int = 0
    tool_spans: list[ToolSpan] = field(default_factory=list)
    final_verdict: Optional[str] = None
    final_severity: Optional[str] = None
    confidence: Optional[float] = None
    escalated: bool = False
    total_latency_ms: int = 0
    error: Optional[str] = None
    model: str = "claude-sonnet-4-6"


# ── Console fallback logger ───────────────────────────────────────────────────

def _log_trace(trace: AgentTrace) -> None:
    """Structured console log when Opik is not available."""
    print(json.dumps({
        "event": "agent_trace",
        "trace_id": trace.trace_id,
        "alert_id": trace.alert_id,
        "tenant_id": trace.tenant_id,
        "iterations": trace.iterations,
        "tools_called": [s.tool_name for s in trace.tool_spans],
        "verdict": trace.final_verdict,
        "severity": trace.final_severity,
        "confidence": trace.confidence,
        "escalated": trace.escalated,
        "latency_ms": trace.total_latency_ms,
        "error": trace.error,
    }, default=str))


# ── Supabase trace persistence ────────────────────────────────────────────────

def _persist_trace(trace: AgentTrace) -> None:
    """Optionally write trace summary to Supabase query_log for dashboards."""
    try:
        from supabase import create_client
        sb = create_client(os.environ["SUPABASE_URL"], os.environ["SUPABASE_SERVICE_KEY"])
        sb.table("query_log").insert({
            "trace_id": trace.trace_id,
            "alert_id": trace.alert_id,
            "tenant_id": trace.tenant_id,
            "query": trace.query[:500],
            "severity": trace.final_severity,
            "verdict": trace.final_verdict,
            "confidence": trace.confidence,
            "escalated": trace.escalated,
            "iterations": trace.iterations,
            "tools_called": [s.tool_name for s in trace.tool_spans],
            "latency_ms": trace.total_latency_ms,
            "error": trace.error,
        }).execute()
    except Exception as e:
        print(f"[Tracer] Could not persist trace to Supabase: {e}")


# ── Instrumented tool executor ────────────────────────────────────────────────

class AgentTracer:
    """
    Wraps the agent's execute_tool calls with timing + logging.

    Usage:
        tracer = AgentTracer(alert_id="abc", query="...", tenant_id="tenant-1")
        result = tracer.call_tool("search_knowledge_base", {"query": "lateral movement"})
        tracer.finalize(result_dict)
    """

    def __init__(
        self,
        alert_id: Optional[str] = None,
        query: str = "",
        tenant_id: Optional[str] = None,
    ):
        import uuid
        self.trace = AgentTrace(
            trace_id=str(uuid.uuid4()),
            alert_id=alert_id,
            query=query,
            tenant_id=tenant_id,
        )
        self._start_time = time.time()

        if OPIK_AVAILABLE:
            self._opik_trace = opik.Trace(
                name=f"soc_agent:{alert_id or 'query'}",
                metadata={"alert_id": alert_id, "tenant_id": tenant_id},
                project_name=OPIK_PROJECT,
            )
        else:
            self._opik_trace = None

    def call_tool(self, tool_name: str, tool_input: dict, execute_fn: Callable) -> str:
        """Execute a tool call with timing and span logging."""
        span = ToolSpan(tool_name=tool_name, tool_input=tool_input)
        t0 = time.time()

        try:
            output = execute_fn(tool_name, tool_input)
            span.tool_output = str(output)[:2000]  # cap for storage
        except Exception as e:
            span.error = str(e)
            output = f"Tool error: {e}"
            traceback.print_exc()

        span.latency_ms = int((time.time() - t0) * 1000)
        self.trace.tool_spans.append(span)

        if self._opik_trace:
            try:
                self._opik_trace.log_span(
                    name=tool_name,
                    input={"input": tool_input},
                    output={"output": span.tool_output},
                    metadata={"latency_ms": span.latency_ms, "error": span.error},
                )
            except Exception:
                pass

        return output

    def increment_iteration(self) -> None:
        self.trace.iterations += 1

    def finalize(self, result: dict) -> AgentTrace:
        """Record final result and flush all traces."""
        self.trace.final_verdict = result.get("verdict") or result.get("severity")
        self.trace.final_severity = result.get("severity")
        self.trace.confidence = result.get("confidence")
        self.trace.escalated = result.get("escalated", False)
        self.trace.total_latency_ms = int((time.time() - self._start_time) * 1000)

        if self._opik_trace:
            try:
                self._opik_trace.update(
                    output={"verdict": self.trace.final_verdict, "severity": self.trace.final_severity},
                    metadata={
                        "escalated": self.trace.escalated,
                        "iterations": self.trace.iterations,
                        "latency_ms": self.trace.total_latency_ms,
                    },
                )
                self._opik_trace.end()
            except Exception:
                pass

        _log_trace(self.trace)
        _persist_trace(self.trace)

        return self.trace


# ── Convenience wrapper ───────────────────────────────────────────────────────

def trace_agent_run(
    run_fn: Callable,
    query: str,
    alert_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    **kwargs: Any,
) -> dict:
    """
    Run an agent function with full tracing.

    Example:
        from eval.tracer import trace_agent_run
        from agent.soc_agent import run_agent

        result = trace_agent_run(
            run_fn=run_agent,
            query="Suspicious PowerShell from finance workstation",
            alert_id="alert-uuid-123",
            tenant_id="tenant-abc",
        )
    """
    tracer = AgentTracer(alert_id=alert_id, query=query, tenant_id=tenant_id)
    try:
        result = run_fn(query=query, alert_id=alert_id, tenant_id=tenant_id, **kwargs)
    except Exception as e:
        result = {
            "summary": f"Agent error: {e}",
            "severity": "HIGH",
            "escalated": True,
            "error": str(e),
        }
    tracer.finalize(result)
    return result
