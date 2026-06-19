"""
Vakros Vector Retriever
Queries Supabase pgvector for semantically similar chunks.
"""

import os
from typing import Optional
from supabase import create_client, Client

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def embed_query(query: str) -> list[float]:
    """Embed a query string using the same model as ingestion."""
    try:
        import voyageai
        vo = voyageai.Client(api_key=os.environ.get("VOYAGE_API_KEY"))
        result = vo.embed([query], model="voyage-3", input_type="query")
        return result.embeddings[0]
    except ImportError:
        from openai import OpenAI
        oai = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        response = oai.embeddings.create(input=[query], model="text-embedding-3-small")
        return response.data[0].embedding


def retrieve(
    query: str,
    collection: str = "threat_intel",
    top_k: int = 5,
    similarity_threshold: float = 0.7,
) -> list[dict]:
    """
    Retrieve top-k relevant chunks from Supabase pgvector.
    Returns list of {content, source, similarity, metadata}.

    Requires this SQL function in Supabase:

        CREATE OR REPLACE FUNCTION match_documents(
            query_embedding vector(1536),
            match_collection TEXT,
            match_count INT,
            match_threshold FLOAT
        )
        RETURNS TABLE (
            id TEXT,
            content TEXT,
            source TEXT,
            metadata JSONB,
            similarity FLOAT
        )
        LANGUAGE SQL STABLE AS $$
            SELECT id, content, source, metadata,
                   1 - (embedding <=> query_embedding) AS similarity
            FROM documents
            WHERE collection = match_collection
              AND 1 - (embedding <=> query_embedding) > match_threshold
            ORDER BY similarity DESC
            LIMIT match_count;
        $$;
    """
    query_embedding = embed_query(query)

    result = supabase.rpc(
        "match_documents",
        {
            "query_embedding": query_embedding,
            "match_collection": collection,
            "match_count": top_k,
            "match_threshold": similarity_threshold,
        },
    ).execute()

    return result.data or []
