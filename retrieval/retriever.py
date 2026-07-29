"""
retrieval/retriever.py — Phase 3: RAG Query Interface

The retriever is the bridge between an alert and the knowledge base.
Given an alert, it constructs a semantic query, searches ChromaDB,
and returns the top-k most relevant threat intelligence documents.

This is called by the LLM triage agent (Phase 4) before every LLM call:

    retriever = AlertRetriever()
    context_docs = retriever.retrieve(alert, k=3)
    # context_docs → included in the LLM prompt as grounding context

Design:
  - Lazy loading: ChromaDB and the embedding model are only loaded on
    first call (not at import time) to avoid startup cost.
  - Query construction: combines alert's notes_field + key numeric features
    into a natural language query string for best semantic match.
  - Deduplication: removes duplicate doc_id results (same document, different chunks)
  - Fallback: if ChromaDB is unavailable, returns empty context (LLM still runs)

Usage:
    from retrieval.retriever import AlertRetriever
    retriever = AlertRetriever()

    # Retrieve context for one alert
    docs = retriever.retrieve(alert, k=3)
    context = retriever.format_context(docs)

    # Or get a query string to inspect what would be searched
    query = retriever.build_query(alert)
"""

import sys
import json
import logging
from pathlib import Path
from dataclasses import dataclass

if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import cfg
from ingestion.schema import Alert

logger = logging.getLogger("retriever")


# ── Retrieved document ────────────────────────────────────────────────────────
@dataclass
class RetrievedDoc:
    doc_id: str
    title: str
    attack_type: str
    category: str
    chunk_text: str
    relevance_score: float  # 1 - cosine_distance (higher = more relevant)
    chunk_index: int

    def to_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "attack_type": self.attack_type,
            "relevance_score": round(self.relevance_score, 4),
            "chunk_text": self.chunk_text[:500],  # truncate for JSON safety
        }


class AlertRetriever:
    """
    RAG retriever for the SOC triage pipeline.
    Lazy-loads ChromaDB + embedding model on first call.
    Thread-safe for single-threaded use (one call at a time).
    """

    def __init__(self):
        self._collection = None
        self._model = None
        self._available = None  # None = not checked yet

    # ── Public API ────────────────────────────────────────────────────────────

    def retrieve(self, alert: Alert, k: int = 3) -> list[RetrievedDoc]:
        """
        Retrieve top-k relevant knowledge base chunks for an alert.

        Args:
            alert: The Alert object to find context for.
            k: Number of documents to retrieve (default 3).
               More = richer context but longer prompts (cost + latency).

        Returns:
            List of RetrievedDoc objects sorted by relevance (highest first).
            Empty list if KB is unavailable (pipeline degrades gracefully).
        """
        if not self._ensure_loaded():
            return []

        query = self.build_query(alert)
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=min(k * 2, 10),  # over-fetch then deduplicate
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.warning(f"ChromaDB query failed: {e}")
            return []

        docs = self._parse_results(results, k)
        logger.debug(
            f"Retrieved {len(docs)} docs for alert {alert.alert_id} "
            f"(attack_type={alert.attack_type})"
        )
        return docs

    def build_query(self, alert: Alert) -> str:
        """
        Construct a semantic search query from alert features.

        The query combines:
          1. The notes_field (natural language description)
          2. Key numeric features as text (helps match numeric patterns in KB)
          3. The attack type label if known from rule-based detection

        This multi-part query gives the best semantic match because the KB
        documents describe both symptoms and numeric thresholds.
        """
        parts = [alert.notes_field]

        # Add numeric features as descriptive text
        feature_desc = (
            f"Flow characteristics: {alert.fwd_packets} forward packets, "
            f"{alert.bwd_packets} backward packets, "
            f"{alert.flow_duration_us:.0f} microseconds duration, "
            f"{alert.packet_length_mean:.1f} bytes average packet size, "
            f"{alert.total_bytes} total bytes, "
            f"{alert.flow_bytes_per_sec:.1f} bytes per second throughput. "
            f"Protocol {alert.protocol} to port {alert.dst_port}."
        )
        parts.append(feature_desc)

        # Add severity context
        if alert.severity in ("critical", "high"):
            parts.append(f"High severity alert. Severity: {alert.severity}.")

        return " ".join(parts)

    def format_context(self, docs: list[RetrievedDoc]) -> str:
        """
        Format retrieved documents into a context block for the LLM prompt.

        Output format is designed for readability by the LLM — each document
        is clearly delimited with its source and relevance score.
        """
        if not docs:
            return "No relevant threat intelligence found in knowledge base."

        sections = []
        for i, doc in enumerate(docs, 1):
            sections.append(
                f"[CONTEXT {i} | Source: {doc.title} | Relevance: {doc.relevance_score:.2f}]\n"
                f"{doc.chunk_text}\n"
                f"[END CONTEXT {i}]"
            )

        header = (
            f"=== THREAT INTELLIGENCE CONTEXT ({len(docs)} documents retrieved) ===\n"
            "The following threat intelligence is provided to help classify this alert.\n\n"
        )
        return header + "\n\n".join(sections)

    def is_available(self) -> bool:
        """Check if the knowledge base is built and available."""
        return self._ensure_loaded()

    def get_stats(self) -> dict:
        """Return stats about the loaded knowledge base."""
        if not self._ensure_loaded():
            return {"available": False}
        try:
            count = self._collection.count()
            return {
                "available": True,
                "collection": cfg.CHROMA_COLLECTION,
                "chunk_count": count,
                "embedding_model": cfg.EMBEDDING_MODEL,
            }
        except Exception as e:
            return {"available": False, "error": str(e)}

    # ── Private methods ───────────────────────────────────────────────────────

    def _ensure_loaded(self) -> bool:
        """
        Lazy-load ChromaDB and embedding model.
        Returns True if successfully loaded, False if unavailable.
        """
        if self._available is not None:
            return self._available

        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            from sentence_transformers import SentenceTransformer

            if not cfg.CHROMA_DIR.exists():
                logger.warning(
                    f"ChromaDB not found at {cfg.CHROMA_DIR}. "
                    f"Run: python retrieval/build_kb.py"
                )
                self._available = False
                return False

            manifest_path = cfg.CHROMA_DIR / "manifest.json"
            if not manifest_path.exists():
                logger.warning("ChromaDB manifest not found. Run: python retrieval/build_kb.py")
                self._available = False
                return False

            # Disable telemetry: prevents network calls that cause timeouts on offline machines
            chroma_settings = ChromaSettings(anonymized_telemetry=False)
            client = chromadb.PersistentClient(
                path=str(cfg.CHROMA_DIR),
                settings=chroma_settings,
            )
            self._collection = client.get_collection(cfg.CHROMA_COLLECTION)
            self._model = SentenceTransformer(cfg.EMBEDDING_MODEL)

            count = self._collection.count()
            logger.info(f"Retriever loaded: {count} chunks in ChromaDB")
            self._available = True
            return True

        except Exception as e:
            logger.warning(f"Failed to load retriever: {e}")
            self._available = False
            return False

    def _parse_results(
        self,
        results: dict,
        k: int,
    ) -> list[RetrievedDoc]:
        """
        Parse ChromaDB query results into RetrievedDoc objects.
        Deduplicates by doc_id (keeps highest-relevance chunk per document).
        """
        if not results["ids"] or not results["ids"][0]:
            return []

        seen_doc_ids: set[str] = set()
        docs: list[RetrievedDoc] = []

        ids       = results["ids"][0]
        texts     = results["documents"][0]
        metas     = results["metadatas"][0]
        distances = results["distances"][0]

        for chunk_id, text, meta, dist in zip(ids, texts, metas, distances):
            doc_id = meta.get("doc_id", chunk_id)
            relevance = 1.0 - float(dist)  # cosine distance → similarity

            if doc_id in seen_doc_ids:
                continue  # deduplicate: keep first (highest relevance) chunk
            seen_doc_ids.add(doc_id)

            docs.append(RetrievedDoc(
                doc_id=doc_id,
                title=meta.get("title", "Unknown"),
                attack_type=meta.get("attack_type", "unknown"),
                category=meta.get("category", "unknown"),
                chunk_text=text,
                relevance_score=relevance,
                chunk_index=meta.get("chunk_index", 0),
            ))

            if len(docs) >= k:
                break

        return sorted(docs, key=lambda d: d.relevance_score, reverse=True)
