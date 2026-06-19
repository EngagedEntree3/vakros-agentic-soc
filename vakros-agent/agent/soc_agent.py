"""
Vakros SOC Agent — Core Agentic Loop  v0.4
Powered by Claude with tool use (search → reason → act).

New in v0.4 (ai-engineering-hub merge):
  - Corrective RAG: doc grading + query rewriting in search_knowledge_base
  - Agent Memory: recalls prior incidents for same host/IP before reasoning
  - Observability: Opik traces on every tool call + final verdict

Flow:
  1. Receive security question / alert
  2. Inject prior investigation memory as context
  3. Claude decides which tools to call
  4. Tools execute via AgentTracer (timed + logged)
  5. Claude synthesizes structured final response
  6. Store investigation summary in agent memory
  7. If CRITICAL or low confidence → escalate_incident fires
"""

import os
import json
from typing import Optional

import anthropic

from agent.tools import TOOLS, execute_tool
from agent.corrective_retriever import corrective_retrieve
from memory.agent_memory import AgentMemory, store_investigation
from memory.graph_memory import GraphMemory, build_graph_from_verdict
from eval.tracer import AgentTracer

ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
MODEL = "claude-sonnet-4-6"
MAX_ITERATIONS = 8

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """You are Vakros, an elite AI Security Operations Center (SOC) analyst.

Your job is to:
1. Analyze security questions, alerts, and threat intelligence
2. Search the knowledge base for relevant context before reasoning
3. Provide accurate, actionable security assessments
4. Escalate to human analysts when severity is CRITICAL or confidence is low

Rules:
- Always call search_knowledge_base before making security assertions
- Be precise: name specific TTPs, CVEs, MITRE ATT&CK techniques when relevant
- Structure your final response as JSON with fields:
    summary, severity, verdict, confidence, findings, recommendations, mitre_techniques, escalated
- verdict must be one of: true_positive, false_positive, benign, needs_investigation
- confidence is a float 0.0–1.0
- If you escalate, set escalated=true
- Do not hallucinate CVEs or threat actor names — only cite what you found
- Err on the side of caution: if unsure, set verdict=needs_investigation and escalate

Severity definitions:
- CRITICAL: Active exploitation, data breach risk, production system compromise
- HIGH: Significant vulnerability, likely exploitation path, compliance violation
- MEDIUM: Moderate risk, requires remediation within 30 days
- LOW: Informational, monitor only
"""


def run_agent(
    query: str,
    alert_id: Optional[str] = None,
    context: Optional[str] = None,
    collection: str = "threat_intel",
    tenant_id: Optional[str] = None,
    host: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> dict:
    """
    Run the Vakros SOC agent on a security query.

    Args:
        query:      The security question or alert description
        alert_id:   UUID of the alert (for memory + tracing)
        context:    Additional context (asset info, raw event data, etc.)
        collection: Default knowledge base collection
        tenant_id:  Tenant scope for memory recall/store
        host:       Source host name (used for memory recall)
        source_ip:  Source IP (used for memory recall)

    Returns:
        Structured dict with: summary, severity, verdict, confidence,
                               findings, recommendations, mitre_techniques,
                               escalated, raw_response
    """
    # ── Step 1: Build user message with prior memory + graph context ─────────
    memory_context = ""
    if tenant_id and (host or source_ip):
        mem = AgentMemory(tenant_id=tenant_id)
        gm = GraphMemory(tenant_id=tenant_id)

        if host:
            # Flat memory (prior verdicts)
            prior = mem.recall("host", host, limit=3)
            if prior:
                memory_context += f"\n\n[Prior investigations — {host}]:\n" + mem.format_for_agent(prior)
            # Graph memory (attack path)
            path = gm.query_attack_path("host", host, max_hops=2)
            if path:
                memory_context += f"\n\n{gm.format_for_agent(path)}"

        if source_ip:
            prior = mem.recall("ip", source_ip, limit=3)
            if prior:
                memory_context += f"\n\n[Prior investigations — {source_ip}]:\n" + mem.format_for_agent(prior)
            path = gm.query_attack_path("ip", source_ip, max_hops=2)
            if path:
                memory_context += f"\n\n{gm.format_for_agent(path)}"

    user_message = query
    if context:
        user_message += f"\n\nAdditional context:\n{context}"
    if memory_context:
        user_message += memory_context

    messages = [{"role": "user", "content": user_message}]

    # ── Step 2: Init tracer ───────────────────────────────────────────────────
    tracer = AgentTracer(alert_id=alert_id, query=query, tenant_id=tenant_id)

    # ── Step 3: Agentic loop ──────────────────────────────────────────────────
    result = None
    for iteration in range(MAX_ITERATIONS):
        tracer.increment_iteration()

        response = client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            tools=TOOLS,
            messages=messages,
        )

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            final_text = _extract_text(response.content)
            result = _parse_final_response(final_text)
            break

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    # Route search_knowledge_base through corrective retriever
                    if block.name == "search_knowledge_base":
                        output = tracer.call_tool(
                            block.name,
                            block.input,
                            execute_fn=_corrective_search_executor,
                        )
                    else:
                        output = tracer.call_tool(
                            block.name,
                            block.input,
                            execute_fn=execute_tool,
                        )
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": output,
                    })

            messages.append({"role": "user", "content": tool_results})

    # ── Step 4: Fallback if loop exhausted ───────────────────────────────────
    if result is None:
        result = {
            "summary": "Agent reached maximum iterations without conclusive answer.",
            "severity": "HIGH",
            "verdict": "needs_investigation",
            "confidence": 0.0,
            "findings": ["Agent loop exhausted — manual review required."],
            "recommendations": ["Escalate to human analyst immediately."],
            "mitre_techniques": [],
            "escalated": True,
        }

    # ── Step 5: Store investigation in flat memory + knowledge graph ─────────
    if tenant_id and result.get("verdict") not in (None, "needs_investigation"):
        mitre = result.get("mitre_techniques", [])
        entities = []
        if host:
            entities.append(("host", host))
        if source_ip:
            entities.append(("ip", source_ip))

        # Flat memory (fast recall)
        for etype, evalue in entities:
            store_investigation(
                tenant_id=tenant_id,
                entity_type=etype,
                entity_value=evalue,
                summary=result.get("summary", "")[:500],
                severity=result.get("severity"),
                verdict=result.get("verdict"),
                alert_ids=[alert_id] if alert_id else [],
                tags=mitre,
            )

        # Knowledge graph (temporal entity relationships)
        build_graph_from_verdict(
            tenant_id=tenant_id,
            alert_id=alert_id or "",
            host=host,
            source_ip=source_ip,
            mitre_techniques=mitre,
            verdict=result.get("verdict", "needs_investigation"),
            severity=result.get("severity", "UNKNOWN"),
            campaign=result.get("campaign"),
        )

    # ── Step 6: Finalize trace ────────────────────────────────────────────────
    tracer.finalize(result)
    result["raw_response"] = result.get("raw_response", "")
    return result


# ── Corrective search executor ────────────────────────────────────────────────

def _corrective_search_executor(tool_name: str, tool_input: dict) -> str:
    """
    Drop-in replacement for search_knowledge_base that uses corrective RAG.
    Grades retrieved docs, rewrites query if needed, falls back to MITRE.
    """
    query = tool_input.get("query", "")
    collection = tool_input.get("collection", "threat_intel")
    top_k = tool_input.get("top_k", 5)

    results = corrective_retrieve(
        query=query,
        collection=collection,
        top_k=top_k,
        enable_grading=True,
    )

    if not results:
        return "No relevant documents found in the knowledge base for this query."

    formatted = []
    for i, r in enumerate(results, 1):
        grade_tag = f"[{r.get('grade', '?').upper()}]"
        formatted.append(
            f"[{i}] {grade_tag} Source: {r.get('source', 'unknown')} "
            f"(similarity: {r.get('similarity', 0):.2f})\n{r['content']}"
        )
    return "\n\n---\n\n".join(formatted)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_text(content: list) -> str:
    for block in content:
        if hasattr(block, "type") and block.type == "text":
            return block.text
    return ""


def _parse_final_response(text: str) -> dict:
    """Try to parse structured JSON from Claude's response, fall back to raw."""
    import re
    json_match = re.search(r"```json\s*([\s\S]+?)\s*```", text)
    if json_match:
        try:
            parsed = json.loads(json_match.group(1))
            parsed["raw_response"] = text
            return parsed
        except json.JSONDecodeError:
            pass

    try:
        parsed = json.loads(text)
        parsed["raw_response"] = text
        return parsed
    except json.JSONDecodeError:
        pass

    return {
        "summary": text[:500] if text else "No response generated.",
        "severity": "UNKNOWN",
        "verdict": "needs_investigation",
        "confidence": 0.0,
        "findings": [],
        "recommendations": [],
        "mitre_techniques": [],
        "escalated": False,
        "raw_response": text,
    }
