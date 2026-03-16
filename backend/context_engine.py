"""
SentinelAI v2.0 — Context & Memory Engine
Model: Phi-3.5-mini-instruct via Ollama (128K context window)
Embedding: all-MiniLM-L6-v2 via sentence-transformers
Used for: session memory compression, context summarization, verdict embedding storage
"""

import time
import hashlib

MODEL_NAME = "phi3.5"


class ContextEngine:
    """Manages session memory, context compression, and verdict embeddings."""

    def __init__(self, embedding_store=None):
        self.sessions = {}  # session_id -> compressed context
        self.embedding_store = embedding_store
        self._embedder = None

    def _get_embedder(self):
        """Lazy-load the sentence-transformers embedding model."""
        if self._embedder is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedder = SentenceTransformer("all-MiniLM-L6-v2")
                print("[ContextEngine] Loaded all-MiniLM-L6-v2 embedding model")
            except ImportError:
                print("[ContextEngine] sentence-transformers not installed — embeddings disabled")
            except Exception as e:
                print(f"[ContextEngine] Failed to load embedding model: {e}")
        return self._embedder

    def _embed_text(self, text: str) -> list:
        """Generate embedding vector for text."""
        embedder = self._get_embedder()
        if embedder is None:
            return []
        return embedder.encode(text).tolist()

    async def compress_session(self, session_id: str, events: list) -> str:
        """Compress a batch of scan events into a concise session summary."""
        event_text = "\n".join(
            f"- [{e.get('agent', '?')}] score={e.get('score', 0)}, threats={len(e.get('threats', []))}"
            for e in events[:20]
        )

        prompt = f"""Compress the following security scan session into a concise 2-3 sentence summary.
Preserve key threat indicators and risk levels.

Session events:
{event_text}

Summary:"""

        try:
            from backend.ollama_engine import generate_async, is_available
            if is_available():
                summary = await generate_async("context-engine", prompt, max_new_tokens=128)
                self.sessions[session_id] = {
                    "summary": summary,
                    "event_count": len(events),
                    "updated_at": time.time()
                }
                return summary
        except Exception:
            pass

        # Fallback: simple summary
        total_threats = sum(len(e.get("threats", [])) for e in events)
        max_score = max((e.get("score", 0) for e in events), default=0)
        fallback = f"Session {session_id}: {len(events)} scans, {total_threats} threats, max score {max_score}."
        self.sessions[session_id] = {"summary": fallback, "event_count": len(events), "updated_at": time.time()}
        return fallback

    async def store_verdict_embedding(self, verdict: dict, url: str):
        """Generate embedding for a verdict and store in ChromaDB."""
        if not self.embedding_store:
            return

        # Create text representation for embedding
        threat_text = "; ".join(
            f"{t['type']}: {t['detail']}"
            for t in verdict.get("all_threats", [])[:10]
        )
        text_for_embedding = f"URL: {url} | Score: {verdict.get('composite_score', 0)} | Level: {verdict.get('level', '?')} | Threats: {threat_text}"

        embedding = self._embed_text(text_for_embedding)
        if not embedding:
            return

        verdict_id = hashlib.sha256(f"{url}:{time.time()}".encode()).hexdigest()[:16]
        metadata = {
            "url": url,
            "score": verdict.get("composite_score", 0),
            "level": verdict.get("level", "unknown"),
            "threat_count": len(verdict.get("all_threats", [])),
            "timestamp": time.time()
        }

        try:
            self.embedding_store.store_verdict(verdict_id, embedding, metadata)
        except Exception as e:
            print(f"[ContextEngine] Failed to store verdict embedding: {e}")

    async def find_similar_verdicts(self, url: str, n_results: int = 5) -> list:
        """Find similar past verdicts using embedding similarity."""
        if not self.embedding_store:
            return []

        query_text = f"security analysis runtime hooks: {url}"
        embedding = self._embed_text(query_text)
        if not embedding:
            return []

        try:
            results = self.embedding_store.query_similar(embedding, n_results)
            return results.get("metadatas", [[]])[0] if results else []
        except Exception as e:
            print(f"[ContextEngine] Similarity search failed: {e}")
            return []

    def get_session(self, session_id: str) -> dict:
        return self.sessions.get(session_id, {})

    def cleanup_old_sessions(self, max_age_hours: int = 24):
        cutoff = time.time() - (max_age_hours * 3600)
        expired = [k for k, v in self.sessions.items() if v.get("updated_at", 0) < cutoff]
        for k in expired:
            del self.sessions[k]
