"""
Vakros Corrective RAG Retriever
Inspired by: https://github.com/patchy631/ai-engineering-hub/tree/main/corrective-rag

Pattern:
  1. Retrieve candidate chunks from pgvector
  2. Grade each chunk: relevant / not_relevant / ambiguous
  3. If avg relevance is poor → rewrite the query and retry once
  4. If still poor → fall back to direct MITRE ATT&CK table lookup
  5. Return deduplicated, graded results to the agent

This replaces the naive top-k retrieval in retriever.py and materially
improves accuracy for ambiguous SOC queries (e.g. "port scan" could map
to T1046 Network Service Discovery or T1595 Active Scanning).
"""

from __future__ import annotations

import os
import json
from typing import Literal

import anthropic
from supabase import create_client, Client

from agent.retriever import retrieve, embed_query

ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

_claude = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
_sb: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

GradeLabel = Literal["relevant", "not_relevant", "ambiguous"]

GRADER_PROMPT = """You are a security document relevance grader.

Given a security analysis QUERY and a retrieved document CHUNK, decide if the chunk
contains information useful for answering the query.

Respond with JSON only:
{
  "grade": "relevant" | "not_relevant" | "ambiguous",
  "reason": "<one sentence>"
}

Rules:
- "relevant": chunk directly addresses the attack technique, IOC type, or procedure in the query
- "not_relevant": chunk is about a completely different topic
- "ambiguous": chunk is loosely related but may not help
"""

REWRITER_PROMPT = """You are a security query optimizer.

The original search query returned poor results from a security knowledge base.
Rewrite the query to be more specific and increase the chance of matching
MITRE ATT&CK techniques, CVEs, or threat actor TTPs.

Original query: {query}

Respond with the rewritten query only — no explanation, no quotes.
"""


# ── Grading ──────────────────────────────────────────────────────────────────

def _grade_chunk(query: str, chunk_content: str) -> GradeLabel:
    """Ask Claude to grade a single retrieved chunk for relevance."""
    try:
        response = _claude.messages.create(
            model="claude-haiku-4-5-20251001",  # fast + cheap for grading
            max_tokens=128,
            system=GRADER_PROMPT,
            messages=[
                {
                    "role": "user",
                    "content": f"QUERY: {query}\n\nCHUNK:\n{chunk_content[:800]}",
                }
            ],
        )
        text = response.content[0].text.strip()
        parsed = json.loads(text)
        return parsed.get("grade", "ambiguous")
    except Exception:
        return "ambiguous"


def _grade_results(query: str, results: list[dict]) -> list[dict]:
    """Add grade field to each result. Returns results with grade attached."""
    for r in results:
        r["grade"] = _grade_chunk(query, r.get("content", ""))
    return results


# ── Query rewriting ───────────────────────────────────────────────────────────

def _rewrite_query(original_query: str) -> str:
    """Rewrite a poor-performing query to improve retrieval."""
    try:
        response = _claude.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=128,
            messages=[
                {
                    "role": "user",
                    "content": REWRITER_PROMPT.format(query=original_query),
                }
            ],
        )
        return response.content[0].text.strip()
    except Exception:
        return original_query


# ── MITRE direct fallback ─────────────────────────────────────────────────────

def _mitre_fallback(query: str, top_k: int = 5) -> list[dict]:
    """
    Direct keyword search against the mitre_techniques table.
    Used when vector search returns no relevant results.
    """
    try:
        # Full-text search on technique name + description
        result = _sb.rpc(
            "search_mitre_techniques",
            {"search_query": query, "match_count": top_k},
        ).execute()
        rows = result.data or []
        return [
            {
                "content": f"[MITRE {r.get('technique_id', '')}] {r.get('name', '')}\n{r.get('description', '')}",
                "source": f"MITRE ATT&CK — {r.get('technique_id', '')}",
                "similarity": 0.6,
                "grade": "relevant",
                "metadata": r,
            }
            for r in rows
        ]
    except Exception:
        return []


# ── Public interface ──────────────────────────────────────────────────────────

def corrective_retrieve(
    query: str,
    collection: str = "threat_intel",
    top_k: int = 6,
    relevance_threshold: float = 0.5,
    enable_grading: bool = True,
) -> list[dict]:
    """
    Corrective RAG retrieval for the Vakros SOC agent.

    Steps:
      1. Initial vector retrieval
      2. Grade each chunk (if enable_grading)
      3. If <50% chunks are relevant → rewrite query + retry
      4. If still poor → MITRE direct fallback
      5. Return merged, deduplicated relevant results

    Args:
        query: The search query from the agent tool call
        collection: pgvector collection to search
        top_k: Max chunks to return
        relevance_threshold: Fraction of results that must be relevant to skip rewrite
        enable_grading: Set False in dev/test to skip LLM grading (saves cost)

    Returns:
        List of result dicts with content, source, similarity, grade
    """
    # Step 1: initial retrieval
    results = retrieve(query=query, collection=collection, top_k=top_k)

    if not results:
        # No results at all → skip grading, go straight to fallback
        mitre = _mitre_fallback(query, top_k=top_k)
        return mitre if mitre else []

    # Step 2: grade results
    if enable_grading:
        results = _grade_results(query, results)
        relevant_count = sum(1 for r in results if r["grade"] == "relevant")
        relevant_ratio = relevant_count / len(results)
    else:
        for r in results:
            r["grade"] = "relevant"
        relevant_ratio = 1.0

    # Step 3: rewrite + retry if quality is poor
    if relevant_ratio < relevance_threshold:
        rewritten = _rewrite_query(query)
        print(f"[CorrectiveRAG] Low relevance ({relevant_ratio:.0%}). Rewriting: '{query}' → '{rewritten}'")
        retry_results = retrieve(query=rewritten, collection=collection, top_k=top_k)

        if retry_results and enable_grading:
            retry_results = _grade_results(rewritten, retry_results)
            retry_relevant = sum(1 for r in retry_results if r["grade"] == "relevant")

            if retry_relevant > relevant_count:
                results = retry_results  # retry was better
            else:
                # Merge both, deduplicate by content hash
                seen = set()
                merged = []
                for r in results + retry_results:
                    h = hash(r["content"][:100])
                    if h not in seen:
                        seen.add(h)
                        merged.append(r)
                results = merged
        elif retry_results:
            results = retry_results

    # Step 4: MITRE fallback if still poor
    final_relevant = [r for r in results if r["grade"] in ("relevant", "ambiguous")]
    if not final_relevant:
        print(f"[CorrectiveRAG] No relevant results after retry. Using MITRE fallback.")
        mitre = _mitre_fallback(query, top_k=top_k)
        results = mitre if mitre else results  # keep original if MITRE also empty

    # Step 5: sort by grade priority + similarity, return top_k
    grade_order = {"relevant": 0, "ambiguous": 1, "not_relevant": 2}
    results.sort(key=lambda r: (grade_order.get(r.get("grade", "ambiguous"), 1), -r.get("similarity", 0)))

    return results[:top_k]
