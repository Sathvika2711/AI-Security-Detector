"""
audit_log.py — SQLite Audit Logger
====================================

WHAT THIS DOES:
  Logs every analysed input and its risk assessment to SQLite.
  This is a core Responsible AI requirement — you need an audit
  trail of what your AI system flagged and why.

  In an interview: "I built structured audit logging into the
  security detector so every flagged input is traceable — this
  is the kind of governance requirement EY would enforce on
  enterprise AI deployments."
"""

import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager

DB_PATH = "audit_log.db"


# ── CONTEXT MANAGER for DB connections ────────────────────────
# Using a context manager ensures the connection is always
# closed properly — even if an exception occurs inside the block

@contextmanager
def get_db():
    """
    Context manager for SQLite connections.
    Guarantees connection is closed after use.

    Usage:
        with get_db() as conn:
            conn.execute(...)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # return rows as dicts
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()   # always runs — same as __exit__


def init_db():
    """Create the audit log table if it doesn't exist"""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                input_text  TEXT NOT NULL,
                risk_level  TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                confidence  REAL NOT NULL,
                is_malicious INTEGER NOT NULL,
                reasoning   TEXT NOT NULL,
                method      TEXT NOT NULL
            )
        """)


def log_analysis(user_input: str, result: dict):
    """
    Log an analysis result to the audit trail.
    Only logs medium and high risk inputs to avoid noise.
    """
    # Only log medium/high risk — low risk is noise
    if result.get("risk_level") == "low" and not result.get("is_malicious"):
        return

    with get_db() as conn:
        conn.execute("""
            INSERT INTO audit_log
            (timestamp, input_text, risk_level, attack_type, confidence, is_malicious, reasoning, method)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            user_input[:500],  # cap stored input length
            result.get("risk_level", "unknown"),
            result.get("attack_type", "unknown"),
            result.get("confidence", 0.0),
            1 if result.get("is_malicious") else 0,
            result.get("reasoning", ""),
            result.get("method", "unknown")
        ))


def get_recent_flags(limit: int = 20) -> list:
    """Retrieve the most recent flagged inputs"""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT * FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_stats() -> dict:
    """Return summary statistics for the audit log"""
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        high  = conn.execute("SELECT COUNT(*) FROM audit_log WHERE risk_level='high'").fetchone()[0]
        med   = conn.execute("SELECT COUNT(*) FROM audit_log WHERE risk_level='medium'").fetchone()[0]
        malicious = conn.execute("SELECT COUNT(*) FROM audit_log WHERE is_malicious=1").fetchone()[0]

    return {
        "total_flagged": total,
        "high_risk": high,
        "medium_risk": med,
        "malicious_confirmed": malicious
    }
