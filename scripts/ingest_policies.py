#!/usr/bin/env python3
"""
OdinForge Security Policy Ingestion Utility

This script processes security policy documents (text, markdown, PDF) and
stores them in the PostgreSQL vector database with OpenAI embeddings for
semantic search capabilities.

Usage:
    python scripts/ingest_policies.py --dir policies/
    python scripts/ingest_policies.py --file policies/acceptable_use.pdf
    python scripts/ingest_policies.py --dir policies/ --policy-type rules_of_engagement
"""

import os
import sys
import argparse
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

import psycopg2
from psycopg2.extras import execute_values
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import (
    TextLoader,
    PyPDFLoader,
    UnstructuredMarkdownLoader,
)

POLICY_TYPES = [
    "rules_of_engagement",
    "acceptable_use", 
    "scope_definition",
    "escalation_procedure",
    "compliance_requirement",
    "risk_tolerance",
    "incident_response",
    "authorization_matrix",
    "other",
]

SUPPORTED_EXTENSIONS = {
    ".txt": TextLoader,
    ".md": UnstructuredMarkdownLoader,
    ".pdf": PyPDFLoader,
}


def get_db_connection():
    """Create database connection from environment variable."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise ValueError("DATABASE_URL environment variable not set")
    return psycopg2.connect(database_url)


def get_file_hash(filepath: Path) -> str:
    """Generate SHA256 hash of file contents."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def load_document(filepath: Path) -> List[Dict[str, Any]]:
    """Load document and return list of page contents with metadata."""
    ext = filepath.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        print(f"  [SKIP] Unsupported file type: {ext}")
        return []
    
    loader_class = SUPPORTED_EXTENSIONS[ext]
    try:
        loader = loader_class(str(filepath))
        documents = loader.load()
        return [{"content": doc.page_content, "metadata": doc.metadata} for doc in documents]
    except Exception as e:
        print(f"  [ERROR] Failed to load {filepath}: {e}")
        return []


def chunk_documents(
    documents: List[Dict[str, Any]], 
    chunk_size: int = 1000, 
    chunk_overlap: int = 200
) -> List[Dict[str, Any]]:
    """Split documents into chunks with overlap for context preservation."""
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        length_function=len,
        separators=["\n\n", "\n", ". ", " ", ""]
    )
    
    chunks = []
    for doc in documents:
        splits = text_splitter.split_text(doc["content"])
        for i, split in enumerate(splits):
            chunks.append({
                "content": split,
                "metadata": {
                    **doc.get("metadata", {}),
                    "chunkIndex": i,
                    "totalChunks": len(splits),
                }
            })
    return chunks


def generate_embeddings(chunks: List[Dict[str, Any]], embeddings_model: OpenAIEmbeddings) -> List[List[float]]:
    """Generate OpenAI embeddings for all chunks."""
    texts = [chunk["content"] for chunk in chunks]
    return embeddings_model.embed_documents(texts)


def upsert_policies(
    conn,
    chunks: List[Dict[str, Any]],
    embeddings: List[List[float]],
    filename: str,
    policy_type: str,
    organization_id: Optional[str] = None,
    source_hash: str = ""
):
    """Insert or update policies in the database."""
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM security_policies WHERE metadata->>'sourceHash' = %s",
            (source_hash,)
        )
        
        records = []
        for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
            metadata = {
                **chunk["metadata"],
                "filename": filename,
                "policyType": policy_type,
                "sourceHash": source_hash,
                "ingestedAt": datetime.utcnow().isoformat(),
            }
            
            embedding_str = "[" + ",".join(map(str, embedding)) + "]"
            
            records.append((
                chunk["content"],
                psycopg2.extras.Json(metadata),
                embedding_str,
                organization_id,
            ))
        
        execute_values(
            cur,
            """
            INSERT INTO security_policies (content, metadata, embedding, organization_id)
            VALUES %s
            """,
            records,
            template="(%s, %s, %s::vector, %s)"
        )
        
        conn.commit()
        return len(records)


def process_file(
    filepath: Path,
    embeddings_model: OpenAIEmbeddings,
    conn,
    policy_type: str = "other",
    organization_id: Optional[str] = None,
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
):
    """Process a single file: load, chunk, embed, and upsert."""
    print(f"Processing: {filepath.name}")
    
    source_hash = get_file_hash(filepath)
    print(f"  Hash: {source_hash[:16]}...")
    
    documents = load_document(filepath)
    if not documents:
        return 0
    print(f"  Loaded {len(documents)} document(s)")
    
    chunks = chunk_documents(documents, chunk_size, chunk_overlap)
    print(f"  Created {len(chunks)} chunks")
    
    print(f"  Generating embeddings...")
    embeddings = generate_embeddings(chunks, embeddings_model)
    
    print(f"  Upserting to database...")
    count = upsert_policies(
        conn, chunks, embeddings, 
        filepath.name, policy_type, organization_id, source_hash
    )
    print(f"  [OK] Inserted {count} policy chunks")
    
    return count


def process_directory(
    directory: Path,
    embeddings_model: OpenAIEmbeddings,
    conn,
    policy_type: str = "other",
    organization_id: Optional[str] = None,
    chunk_size: int = 1000,
    chunk_overlap: int = 200,
):
    """Process all supported files in a directory."""
    total = 0
    files = [f for f in directory.iterdir() if f.suffix.lower() in SUPPORTED_EXTENSIONS]
    
    if not files:
        print(f"No supported files found in {directory}")
        return 0
    
    print(f"Found {len(files)} file(s) to process")
    print("-" * 50)
    
    for filepath in sorted(files):
        count = process_file(
            filepath, embeddings_model, conn,
            policy_type, organization_id, chunk_size, chunk_overlap
        )
        total += count
        print()
    
    return total


def main():
    parser = argparse.ArgumentParser(
        description="Ingest security policy documents into OdinForge vector database"
    )
    parser.add_argument(
        "--dir", "-d", type=Path,
        help="Directory containing policy documents"
    )
    parser.add_argument(
        "--file", "-f", type=Path,
        help="Single policy file to process"
    )
    parser.add_argument(
        "--policy-type", "-t", 
        choices=POLICY_TYPES,
        default="other",
        help="Type of policy document (default: other)"
    )
    parser.add_argument(
        "--organization-id", "-o",
        help="Organization ID for multi-tenant isolation"
    )
    parser.add_argument(
        "--chunk-size", type=int, default=1000,
        help="Maximum chunk size in characters (default: 1000)"
    )
    parser.add_argument(
        "--chunk-overlap", type=int, default=200,
        help="Overlap between chunks in characters (default: 200)"
    )
    
    args = parser.parse_args()
    
    if not args.dir and not args.file:
        parser.error("Either --dir or --file must be specified")
    
    openai_api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("AI_INTEGRATIONS_OPENAI_API_KEY")
    if not openai_api_key:
        print("ERROR: No OpenAI API key found. Set OPENAI_API_KEY")
        sys.exit(1)
    
    print("=" * 50)
    print("OdinForge Policy Ingestion Utility")
    print("=" * 50)
    print()
    
    print("Initializing OpenAI embeddings...")
    embeddings_model = OpenAIEmbeddings(
        api_key=openai_api_key,
        model="text-embedding-ada-002",
    )
    
    print("Connecting to database...")
    conn = get_db_connection()
    
    try:
        if args.file:
            if not args.file.exists():
                print(f"ERROR: File not found: {args.file}")
                sys.exit(1)
            total = process_file(
                args.file, embeddings_model, conn,
                args.policy_type, args.organization_id,
                args.chunk_size, args.chunk_overlap
            )
        else:
            if not args.dir.exists():
                print(f"ERROR: Directory not found: {args.dir}")
                sys.exit(1)
            total = process_directory(
                args.dir, embeddings_model, conn,
                args.policy_type, args.organization_id,
                args.chunk_size, args.chunk_overlap
            )
        
        print("=" * 50)
        print(f"COMPLETE: Ingested {total} policy chunks")
        print("=" * 50)
        
    finally:
        conn.close()


if __name__ == "__main__":
    main()
