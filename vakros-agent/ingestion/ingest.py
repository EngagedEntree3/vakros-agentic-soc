"""
Vakros Ingestion Pipeline
Chunks documents, embeds them, and upserts into Supabase pgvector.

Supported input: PDF, TXT, MD files from a local directory.
Usage:
    python ingestion/ingest.py --source ./docs --collection threat_intel
"""

import os
import argparse
import hashlib
from pathlib import Path
from typing import Generator

import anthropic
from supabase import create_client, Client

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
ANTHROPIC_API_KEY = os.environ["ANTHROPIC_API_KEY"]

CHUNK_SIZE = 800       # characters per chunk
CHUNK_OVERLAP = 150    # overlap between chunks
EMBED_MODEL = "voyage-3"  # Anthropic's recommended embedding model via Voyage AI
# Alternatively use "text-embedding-3-small" from OpenAI if preferred

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
anthropic_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


# ---------------------------------------------------------------------------
# Document loading
# ---------------------------------------------------------------------------

def load_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def load_pdf(path: Path) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError:
        raise ImportError("pypdf not installed. Run: pip install pypdf")


def load_document(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        return load_pdf(path)
    elif suffix in (".txt", ".md"):
        return load_text_file(path)
    else:
        print(f"  Skipping unsupported file type: {path.name}")
        return ""


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> Generator[str, None, None]:
    """Simple sliding window chunker."""
    text = text.strip()
    if not text:
        return
    start = 0
    while start < len(text):
        end = start + chunk_size
        yield text[start:end]
        start += chunk_size - overlap


# ---------------------------------------------------------------------------
# Embedding
# ---------------------------------------------------------------------------

def embed_chunks(chunks: list[str]) -> list[list[float]]:
    """
    Embed using Voyage AI via Anthropic-recommended path.
    Falls back to a simple mock if voyage not available (dev mode).
    """
    try:
        import voyageai
        vo = voyageai.Client(api_key=os.environ.get("VOYAGE_API_KEY", ANTHROPIC_API_KEY))
        result = vo.embed(chunks, model=EMBED_MODEL, input_type="document")
        return result.embeddings
    except ImportError:
        # Fallback: use OpenAI embeddings if available
        try:
            from openai import OpenAI
            oai = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            response = oai.embeddings.create(input=chunks, model="text-embedding-3-small")
            return [item.embedding for item in response.data]
        except Exception:
            raise RuntimeError(
                "No embedding provider available. "
                "Install voyageai (pip install voyageai) or set OPENAI_API_KEY."
            )


# ---------------------------------------------------------------------------
# Supabase upsert
# ---------------------------------------------------------------------------

def ensure_table(collection: str) -> None:
    """
    Run this SQL once in Supabase to create the vectors table:

        CREATE EXTENSION IF NOT EXISTS vector;

        CREATE TABLE IF NOT EXISTS documents (
            id          TEXT PRIMARY KEY,
            collection  TEXT NOT NULL,
            source      TEXT,
            chunk_index INTEGER,
            content     TEXT,
            embedding   vector(1536),
            metadata    JSONB DEFAULT '{}'
        );

        CREATE INDEX IF NOT EXISTS documents_embedding_idx
            ON documents USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100);
    """
    pass  # Table must be created manually via Supabase SQL editor or migration


def upsert_chunks(
    chunks: list[str],
    embeddings: list[list[float]],
    source: str,
    collection: str,
) -> None:
    rows = []
    for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
        doc_id = hashlib.md5(f"{source}:{i}:{chunk[:50]}".encode()).hexdigest()
        rows.append({
            "id": doc_id,
            "collection": collection,
            "source": source,
            "chunk_index": i,
            "content": chunk,
            "embedding": embedding,
            "metadata": {"source": source, "chunk_index": i},
        })
    # Upsert in batches of 50
    for i in range(0, len(rows), 50):
        batch = rows[i:i+50]
        supabase.table("documents").upsert(batch).execute()
    print(f"  Upserted {len(rows)} chunks from {source}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def ingest_directory(source_dir: str, collection: str) -> None:
    source_path = Path(source_dir)
    files = list(source_path.rglob("*.pdf")) + \
            list(source_path.rglob("*.txt")) + \
            list(source_path.rglob("*.md"))

    if not files:
        print(f"No supported files found in {source_dir}")
        return

    print(f"Found {len(files)} files. Ingesting into collection '{collection}'...")

    for file in files:
        print(f"Processing: {file.name}")
        text = load_document(file)
        if not text.strip():
            continue

        chunks = list(chunk_text(text))
        print(f"  {len(chunks)} chunks")

        embeddings = embed_chunks(chunks)
        upsert_chunks(chunks, embeddings, str(file), collection)

    print(f"\nDone. {len(files)} files ingested into '{collection}'.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vakros document ingestion pipeline")
    parser.add_argument("--source", required=True, help="Directory containing documents")
    parser.add_argument("--collection", default="threat_intel", help="Collection name in Supabase")
    args = parser.parse_args()
    ingest_directory(args.source, args.collection)
