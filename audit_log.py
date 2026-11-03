"""
audit_log.py — SQLite audit trail + request metrics
=====================================================

Two tables, two purposes:

  audit_log     Security audit trail. Stores the (truncated) input text,
                but ONLY for inputs that were flagged (medium/high risk,
                or matched any rule). Used for investigation and governance.

  request_log   Operational metrics for EVERY request: risk level, method,
                tokens, cost, latency, cache hit. Stores a SHA-256 hash of
                the input instead of the text — privacy by design, clean
                user inputs are never persisted.
"""

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("AUDIT_DB_PATH", "audit_log.db")


@contextmanager
def get_db():
    """Open a connection, commit on success, roll back on error, always close."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def init_db():
    """Create tables if missing, and migrate audit_log from the v1 schema."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                input_text   TEXT NOT NULL,
                risk_level   TEXT NOT NULL,
                attack_type  TEXT NOT NULL,
                confidence   REAL NOT NULL,
                is_malicious INTEGER NOT NULL,
                reasoning    TEXT NOT NULL,
                method       TEXT NOT NULL
            )
        """)
        # v2 columns — added in place so existing databases keep working
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
        for col, ddl in (("request_id", "TEXT"), ("input_sha256", "TEXT"), ("rule_flags", "TEXT")):
            if col not in existing:
                conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {ddl}")  # column names are a fixed allow-list

        conn.execute("""
            CREATE TABLE IF NOT EXISTS request_log (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                request_id    TEXT,
                input_sha256  TEXT NOT NULL,
                input_chars   INTEGER NOT NULL,
                risk_level    TEXT NOT NULL,
                attack_type   TEXT NOT NULL,
                method        TEXT NOT NULL,
                llm_calls     INTEGER NOT NULL,
                input_tokens  INTEGER NOT NULL,
                output_tokens INTEGER NOT NULL,
                cost_usd      REAL NOT NULL,
                latency_ms    REAL NOT NULL,
                cache_hit     INTEGER NOT NULL
            )
        """)


def should_audit(result: dict) -> bool:
    return (result.get("risk_level") != "low"
            or bool(result.get("is_malicious"))
            or bool(result.get("rule_flags")))


def log_analysis(user_input: str, result: dict, request_id: str = None):
    """Write the request metrics row, plus an audit row if the input was flagged."""
    usage = result.get("usage", {})
    digest = _sha256(user_input)
    with get_db() as conn:
        conn.execute("""
            INSERT INTO request_log
            (timestamp, request_id, input_sha256, input_chars, risk_level, attack_type, method,
             llm_calls, input_tokens, output_tokens, cost_usd, latency_ms, cache_hit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _now(), request_id, digest, len(user_input),
            result.get("risk_level", "unknown"), result.get("attack_type", "unknown"),
            result.get("method", "unknown"),
            usage.get("llm_calls", 0), usage.get("input_tokens", 0), usage.get("output_tokens", 0),
            usage.get("cost_usd", 0.0), usage.get("latency_ms", 0.0),
            1 if usage.get("cache_hit") else 0,
        ))

        if not should_audit(result):
            return

        conn.execute("""
            INSERT INTO audit_log
            (timestamp, input_text, risk_level, attack_type, confidence, is_malicious,
             reasoning, method, request_id, input_sha256, rule_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _now(), user_input[:500],
            result.get("risk_level", "unknown"), result.get("attack_type", "unknown"),
            result.get("confidence", 0.0), 1 if result.get("is_malicious") else 0,
            result.get("reasoning", ""), result.get("method", "unknown"),
            request_id, digest, ",".join(result.get("rule_flags", [])),
        ))


def get_recent_flags(limit: int = 20) -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def get_stats() -> dict:
    with get_db() as conn:
        row = conn.execute("""
            SELECT COUNT(*) AS total,
                   SUM(risk_level = 'high')   AS high,
                   SUM(risk_level = 'medium') AS medium,
                   SUM(is_malicious = 1)      AS malicious
            FROM audit_log
        """).fetchone()
    return {
        "total_flagged": row["total"] or 0,
        "high_risk": row["high"] or 0,
        "medium_risk": row["medium"] or 0,
        "malicious_confirmed": row["malicious"] or 0,
    }


def _percentile(values: list, pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * len(ordered)) - 1))
    return round(ordered[idx], 2)


def get_metrics() -> dict:
    """Operational metrics over every request: volume, cost, latency, LLM offload."""
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT risk_level, method, llm_calls, input_tokens, output_tokens, "
            "cost_usd, latency_ms, cache_hit FROM request_log"
        ).fetchall()]

    n = len(rows)
    if n == 0:
        return {"total_requests": 0}

    no_llm = sum(1 for r in rows if r["llm_calls"] == 0)
    latencies = [r["latency_ms"] for r in rows]
    total_cost = sum(r["cost_usd"] for r in rows)
    by_risk, by_method = {}, {}
    for r in rows:
        by_risk[r["risk_level"]] = by_risk.get(r["risk_level"], 0) + 1
        by_method[r["method"]] = by_method.get(r["method"], 0) + 1

    return {
        "total_requests": n,
        "requests_without_llm_call_pct": round(100 * no_llm / n, 1),
        "rule_short_circuit_count": by_method.get("rule_short_circuit", 0),
        "cache_hit_rate_pct": round(100 * sum(r["cache_hit"] for r in rows) / n, 1),
        "llm_calls": sum(r["llm_calls"] for r in rows),
        "input_tokens": sum(r["input_tokens"] for r in rows),
        "output_tokens": sum(r["output_tokens"] for r in rows),
        "total_cost_usd": round(total_cost, 6),
        "avg_cost_per_request_usd": round(total_cost / n, 8),
        "latency_ms": {
            "avg": round(sum(latencies) / n, 2),
            "p50": _percentile(latencies, 50),
            "p95": _percentile(latencies, 95),
        },
        "by_risk_level": by_risk,
        "by_method": by_method,
    }
