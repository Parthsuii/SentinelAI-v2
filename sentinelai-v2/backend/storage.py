"""
SentinelAI v2.0 — Storage Layer
Redis (ephemeral events, session state) + ChromaDB (verdict embeddings) + SQLite (user feedback).
"""

import time
import json
import sqlite3
import os
from typing import Optional

# ── Redis Wrapper (falls back to in-memory if Redis unavailable) ──

class EphemeralStore:
    """Redis-backed ephemeral store with in-memory fallback."""

    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self._memory = {}
        self._redis = None
        try:
            import redis
            self._redis = redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
            print("[Storage] Connected to Redis")
        except Exception:
            print("[Storage] Redis unavailable — using in-memory store")
            self._redis = None

    def set_event(self, key: str, data: dict, ttl_ms: int = 300):
        """Store ephemeral event with TTL (default 300ms)."""
        serialized = json.dumps(data)
        if self._redis:
            self._redis.set(key, serialized, px=ttl_ms)
        else:
            self._memory[key] = {
                "data": serialized,
                "expires": time.time() + (ttl_ms / 1000)
            }

    def get_event(self, key: str) -> Optional[dict]:
        if self._redis:
            val = self._redis.get(key)
            return json.loads(val) if val else None
        else:
            entry = self._memory.get(key)
            if entry and time.time() < entry["expires"]:
                return json.loads(entry["data"])
            elif entry:
                del self._memory[key]
            return None

    def set_session(self, session_id: str, data: dict, ttl_hours: int = 24):
        """Store session state (24h TTL)."""
        serialized = json.dumps(data)
        if self._redis:
            self._redis.set(f"session:{session_id}", serialized, ex=ttl_hours * 3600)
        else:
            self._memory[f"session:{session_id}"] = {
                "data": serialized,
                "expires": time.time() + (ttl_hours * 3600)
            }

    def get_session(self, session_id: str) -> Optional[dict]:
        return self.get_event(f"session:{session_id}")

    def cleanup_memory(self):
        """Remove expired in-memory entries."""
        now = time.time()
        expired = [k for k, v in self._memory.items() if now >= v.get("expires", 0)]
        for k in expired:
            del self._memory[k]


# ── ChromaDB Wrapper (verdict embeddings) ──

class VerdictEmbeddingStore:
    """ChromaDB-backed store for verdict embeddings."""

    def __init__(self, persist_dir: str = "./data/chromadb"):
        self._client = None
        self._collection = None
        try:
            import chromadb
            from chromadb.config import Settings
            self._client = chromadb.PersistentClient(
                path=persist_dir,
                settings=Settings(anonymized_telemetry=False)
            )
            self._collection = self._client.get_or_create_collection(
                name="sentinel_verdicts",
                metadata={"hnsw:space": "cosine"}
            )
            print(f"[Storage] ChromaDB initialized at {persist_dir}")
        except Exception as e:
            print(f"[Storage] ChromaDB unavailable: {e}")

    def store_verdict(self, verdict_id: str, embedding: list, metadata: dict):
        if self._collection:
            self._collection.add(
                ids=[verdict_id],
                embeddings=[embedding],
                metadatas=[metadata]
            )

    def query_similar(self, embedding: list, n_results: int = 5):
        if self._collection:
            return self._collection.query(
                query_embeddings=[embedding],
                n_results=n_results
            )
        return {"ids": [], "distances": [], "metadatas": []}


# ── SQLite Wrapper (user feedback, scan history, whitelist) ──

class PersistentStore:
    """SQLite-backed persistent store for user data."""

    def __init__(self, db_path: str = "./data/sentinel.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    hostname TEXT,
                    score REAL,
                    level TEXT,
                    threat_count INTEGER,
                    threats_json TEXT,
                    agent_breakdown_json TEXT,
                    location_info_json TEXT,
                    timestamp REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS whitelist (
                    hostname TEXT PRIMARY KEY,
                    added_at REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    verdict_id TEXT,
                    feedback TEXT,
                    is_correct INTEGER,
                    timestamp REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    hostname TEXT PRIMARY KEY,
                    hooks_json TEXT,
                    visit_count INTEGER DEFAULT 1,
                    last_seen REAL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation (
                    ip TEXT PRIMARY KEY,
                    risk_score REAL DEFAULT 0,
                    malicious_siblings TEXT,
                    last_updated REAL
                )
            """)
            existing_scan_history_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(scan_history)").fetchall()
            }
            if "location_info_json" not in existing_scan_history_columns:
                conn.execute("ALTER TABLE scan_history ADD COLUMN location_info_json TEXT")
            conn.commit()
        print(f"[Storage] SQLite initialized at {self.db_path}")

    def save_scan(self, url: str, hostname: str, score: float, level: str,
                  threat_count: int, threats: list, agent_breakdown: dict, location_info: dict = None):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO scan_history (url, hostname, score, level, threat_count, threats_json, agent_breakdown_json, location_info_json, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (url, hostname, score, level, threat_count, json.dumps(threats[:10]), json.dumps(agent_breakdown), json.dumps(location_info), time.time())
            )

    def get_history(self, limit: int = 100):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            results = []
            for r in rows:
                d = dict(r)
                if d.get("location_info_json"):
                    d["location_info"] = json.loads(d["location_info_json"])
                results.append(d)
            return results

    def clear_history(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM scan_history")

    def add_whitelist(self, hostname: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO whitelist (hostname, added_at) VALUES (?, ?)",
                (hostname, time.time())
            )

    def remove_whitelist(self, hostname: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM whitelist WHERE hostname = ?", (hostname,))

    def get_whitelist(self):
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT hostname FROM whitelist").fetchall()
            return [r[0] for r in rows]

    def save_feedback(self, url: str, verdict_id: str, feedback: str, is_correct: bool):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO user_feedback (url, verdict_id, feedback, is_correct, timestamp) VALUES (?, ?, ?, ?, ?)",
                (url, verdict_id, feedback, 1 if is_correct else 0, time.time())
            )

    def get_feedback(self, limit: int = 50):
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM user_feedback ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # v3 Baseline Methods
    def get_baseline(self, hostname: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM baselines WHERE hostname = ?", (hostname,)).fetchone()
            if row:
                res = dict(row)
                res["hooks_fired"] = json.loads(res["hooks_json"])
                return res
            return None

    def update_baseline(self, hostname: str, hook: str):
        existing = self.get_baseline(hostname)
        if not existing:
            hooks = [hook]
            count = 1
        else:
            hooks = existing["hooks_fired"]
            if hook not in hooks:
                hooks.append(hook)
            count = existing["visit_count"] + 1
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO baselines (hostname, hooks_json, visit_count, last_seen) VALUES (?, ?, ?, ?)",
                (hostname, json.dumps(hooks), count, time.time())
            )

    # v3 Reputation Methods
    def get_reputation(self, ip: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM reputation WHERE ip = ?", (ip,)).fetchone()
            if row:
                res = dict(row)
                res["malicious_siblings"] = json.loads(res["malicious_siblings"] or "[]")
                return res
            return None

    def update_reputation(self, ip: str, risk_score: float, malicious_siblings: list):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO reputation (ip, risk_score, malicious_siblings, last_updated) VALUES (?, ?, ?, ?)",
                (ip, risk_score, json.dumps(malicious_siblings), time.time())
            )

# ── Neo4j Wrapper (Threat campaign graph - Tier 3) ──
class GraphStore:
    """Neo4j-backed store for semantic threat graphs."""
    def __init__(self, uri="bolt://localhost:7687", user="neo4j", password="password"):
        self.driver = None
        try:
            from neo4j import GraphDatabase
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            print("[Storage] Neo4j connected.")
        except Exception as e:
            print(f"[Storage] Neo4j unavailable: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def add_threat_node(self, domain, ip, risk_score):
        if not self.driver: return
        query = '''
        MERGE (s:Site {domain: $domain})
        SET s.risk_score = $risk_score, s.last_seen = timestamp()
        MERGE (i:Infrastructure {ip: $ip})
        MERGE (s)-[:HOSTED_ON]->(i)
        '''
        with self.driver.session() as session:
            try:
                session.run(query, domain=domain, ip=ip, risk_score=risk_score)
            except Exception:
                pass
                
    def check_campaign(self, ip):
        """Find campaign siblings sharing infrastructure."""
        if not self.driver: return []
        query = '''
        MATCH (s:Site)-[:HOSTED_ON]->(i:Infrastructure {ip: $ip})<-[:HOSTED_ON]-(sibling:Site)
        WHERE sibling.risk_score > 70 AND s.domain <> sibling.domain
        RETURN sibling.domain as domain, sibling.risk_score as score
        '''
        with self.driver.session() as session:
            try:
                result = session.run(query, ip=ip)
                return [{"domain": record["domain"], "score": record["score"]} for record in result]
            except Exception:
                return []
