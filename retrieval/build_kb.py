"""
retrieval/build_kb.py — Phase 3: Build the RAG Knowledge Base

Loads threat intelligence documents from data/knowledge_base/,
splits them into chunks, embeds each chunk using sentence-transformers,
and stores them in a persistent ChromaDB vector database.

The knowledge base is queried in Phase 4 when the LLM needs context
to triage a suspicious alert — especially for hard cases like DDoS
where network features alone are insufficient.

Design decisions:
  - Embedding model: all-MiniLM-L6-v2 (fast, 384-dim, good quality)
    Chosen over larger models because: CPU-only machine, latency matters,
    and our documents are short enough that larger models add no benefit.
  - Chunk size: 400 characters with 80-char overlap
    Balances context completeness vs. retrieval precision.
  - ChromaDB: local persistent store (no server needed, zero cost)
  - Collection reset: always rebuild from scratch for reproducibility.

Run:
    python retrieval/build_kb.py
    python retrieval/build_kb.py --dry-run   (show what would be indexed)
"""

import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import cfg


# ── Logging ───────────────────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    cfg.LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("build_kb")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(cfg.LOGS_DIR / "build_kb.log", mode="w", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s"))
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ── Chunking ──────────────────────────────────────────────────────────────────
def chunk_text(
    text: str,
    chunk_size: int = 400,
    overlap: int = 80,
) -> list[str]:
    """
    Split text into overlapping chunks.
    Overlap ensures context is not lost at chunk boundaries.
    Splits on newlines where possible to avoid mid-sentence breaks.
    """
    lines = text.split("\n")
    chunks = []
    current = ""

    for line in lines:
        if len(current) + len(line) + 1 > chunk_size and current:
            chunks.append(current.strip())
            # Overlap: keep last 'overlap' characters as start of next chunk
            current = current[-overlap:] + "\n" + line if overlap > 0 else line
        else:
            current += ("\n" if current else "") + line

    if current.strip():
        chunks.append(current.strip())

    # Filter out chunks that are too short to be meaningful
    return [c for c in chunks if len(c) > 50]


# ── Document loader ───────────────────────────────────────────────────────────
def load_documents(kb_dir: Path, logger: logging.Logger) -> list[dict]:
    """
    Load all .txt documents from the knowledge base directory.
    Returns list of dicts with: doc_id, title, category, attack_type, text, chunks
    """
    txt_files = sorted(kb_dir.glob("*.txt"))
    if not txt_files:
        logger.error(f"No .txt files found in {kb_dir}")
        return []

    documents = []
    for fpath in txt_files:
        raw = fpath.read_text(encoding="utf-8")
        lines = raw.strip().split("\n")

        # Parse header fields (DOCUMENT_ID, CATEGORY, etc.)
        meta = {}
        body_start = 0
        for i, line in enumerate(lines):
            if ": " in line and not line.startswith("#") and i < 8:
                key, val = line.split(": ", 1)
                meta[key.strip()] = val.strip()
                body_start = i + 1
            elif line.startswith("#"):
                body_start = i
                break

        body = "\n".join(lines[body_start:]).strip()
        chunks = chunk_text(body)

        doc = {
            "doc_id":      meta.get("DOCUMENT_ID", fpath.stem),
            "title":       meta.get("TITLE", fpath.stem),
            "category":    meta.get("CATEGORY", "unknown"),
            "attack_type": meta.get("ATTACK_TYPE", "unknown"),
            "filename":    fpath.name,
            "text":        body,
            "chunks":      chunks,
        }
        documents.append(doc)
        logger.info(f"  Loaded: {fpath.name} -> {len(chunks)} chunks")

    return documents


# ── Build ChromaDB collection ─────────────────────────────────────────────────
def build_chromadb(
    documents: list[dict],
    logger: logging.Logger,
    dry_run: bool = False,
) -> dict:
    """
    Embed all document chunks and store in ChromaDB.
    Returns stats dict.
    """
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    from sentence_transformers import SentenceTransformer

    # Load embedding model
    logger.info(f"Loading embedding model: {cfg.EMBEDDING_MODEL}")
    model = SentenceTransformer(cfg.EMBEDDING_MODEL)
    embed_dim = model.get_embedding_dimension() if hasattr(model, 'get_embedding_dimension') else model.get_sentence_embedding_dimension()
    logger.info(f"  Model loaded. Embedding dimension: {embed_dim}")

    if dry_run:
        logger.info("Dry run — skipping ChromaDB write")
        total_chunks = sum(len(d["chunks"]) for d in documents)
        return {"documents": len(documents), "chunks": total_chunks, "dry_run": True}

    # Initialize ChromaDB — disable telemetry to prevent network calls on offline machines
    cfg.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    chroma_settings = ChromaSettings(anonymized_telemetry=False, allow_reset=True)
    client = chromadb.PersistentClient(path=str(cfg.CHROMA_DIR), settings=chroma_settings)

    # Delete and recreate collection for clean rebuild
    try:
        client.delete_collection(cfg.CHROMA_COLLECTION)
        logger.info(f"Deleted existing collection: {cfg.CHROMA_COLLECTION}")
    except Exception:
        pass  # Collection didn't exist yet

    collection = client.create_collection(
        name=cfg.CHROMA_COLLECTION,
        metadata={"hnsw:space": "cosine"},  # cosine similarity for semantic search
    )
    logger.info(f"Created collection: {cfg.CHROMA_COLLECTION}")

    # Embed and add all chunks
    total_chunks = 0
    all_ids, all_texts, all_metas = [], [], []

    for doc in documents:
        for chunk_idx, chunk_text in enumerate(doc["chunks"]):
            chunk_id = f"{doc['doc_id']}_chunk_{chunk_idx:03d}"
            all_ids.append(chunk_id)
            all_texts.append(chunk_text)
            all_metas.append({
                "doc_id":      doc["doc_id"],
                "title":       doc["title"],
                "category":    doc["category"],
                "attack_type": doc["attack_type"],
                "filename":    doc["filename"],
                "chunk_index": chunk_idx,
                "chunk_total": len(doc["chunks"]),
            })
            total_chunks += 1

    logger.info(f"Embedding {total_chunks} chunks...")
    embeddings = model.encode(all_texts, show_progress_bar=True, batch_size=32)
    logger.info(f"Embeddings computed: shape {embeddings.shape}")

    # Add to ChromaDB in one batch
    collection.add(
        ids=all_ids,
        documents=all_texts,
        embeddings=embeddings.tolist(),
        metadatas=all_metas,
    )
    logger.info(f"Stored {total_chunks} chunks in ChromaDB collection '{cfg.CHROMA_COLLECTION}'")

    # Save index manifest
    manifest = {
        "built_at": datetime.utcnow().isoformat() + "Z",
        "embedding_model": cfg.EMBEDDING_MODEL,
        "collection": cfg.CHROMA_COLLECTION,
        "total_documents": len(documents),
        "total_chunks": total_chunks,
        "documents": [
            {
                "doc_id": d["doc_id"],
                "title": d["title"],
                "attack_type": d["attack_type"],
                "chunks": len(d["chunks"]),
            }
            for d in documents
        ],
    }
    manifest_path = cfg.CHROMA_DIR / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Saved manifest -> {manifest_path}")

    return manifest


def main(args: argparse.Namespace, logger: logging.Logger) -> None:
    kb_dir = cfg.KNOWLEDGE_BASE_DIR
    if not kb_dir.exists():
        logger.error(f"Knowledge base directory not found: {kb_dir}")
        sys.exit(1)

    logger.info(f"Loading documents from: {kb_dir}")
    documents = load_documents(kb_dir, logger)

    if not documents:
        logger.error("No documents loaded. Exiting.")
        sys.exit(1)

    total_chunks = sum(len(d["chunks"]) for d in documents)
    logger.info(f"\nLoaded {len(documents)} documents, {total_chunks} total chunks")

    if args.dry_run:
        logger.info("\n-- DRY RUN: Showing chunk counts per document --")
        for d in documents:
            logger.info(f"  {d['filename']:45s}  {len(d['chunks']):3d} chunks  [{d['attack_type']}]")
        logger.info("\nDry run complete. Re-run without --dry-run to build ChromaDB.")
        return

    logger.info("\nBuilding ChromaDB vector store...")
    manifest = build_chromadb(documents, logger, dry_run=False)

    logger.info("")
    logger.info("=" * 55)
    logger.info("Phase 3 - Knowledge Base Build COMPLETE")
    logger.info(f"  Documents : {manifest['total_documents']}")
    logger.info(f"  Chunks    : {manifest['total_chunks']}")
    logger.info(f"  Model     : {manifest['embedding_model']}")
    logger.info(f"  Store     : {cfg.CHROMA_DIR}")
    logger.info("=" * 55)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build RAG knowledge base in ChromaDB")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be indexed without writing to ChromaDB")
    args = parser.parse_args()

    logger = setup_logging()
    logger.info("=" * 55)
    logger.info("Phase 3 - RAG Knowledge Base Builder")
    logger.info(f"  KB dir    : {cfg.KNOWLEDGE_BASE_DIR}")
    logger.info(f"  Model     : {cfg.EMBEDDING_MODEL}")
    logger.info(f"  Chroma    : {cfg.CHROMA_DIR}")
    logger.info("=" * 55)

    main(args, logger)
