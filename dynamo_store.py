"""
dynamo_store.py — DynamoDB storage for the AWS deployment
===========================================================

Same interface as audit_log.py (log_analysis / get_recent_flags /
get_stats / get_metrics), backed by a single DynamoDB table so the
service can run in Lambda, which has no persistent disk.

SINGLE-TABLE DESIGN
  pk                     sk                         contents
  REQ#2026-11-03         <iso-ts>#<request-id>      metrics for EVERY request (hash only, no text)
  AUDIT#2026-11-03       <iso-ts>#<request-id>      flagged inputs, incl. truncated text

  * Partition key is sharded by day, so writes spread across partitions
    instead of one hot "REQ" key, and "last N days" is N cheap Queries.
  * Sort key starts with the timestamp, so "most recent first" is a
    Query with ScanIndexForward=False — no Scan anywhere.
  * Every item has `expires_at` (DynamoDB TTL): request metrics are kept
    RETENTION_DAYS, then deleted automatically — data minimisation.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3
from boto3.dynamodb.conditions import Key

TABLE_NAME = os.environ.get("GUARDRAIL_TABLE", "ai-guardrail")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "90"))

_table = None


def table():
    global _table
    if _table is None:
        _table = boto3.resource("dynamodb").Table(TABLE_NAME)
    return _table


def reset():
    """Forget the cached table handle (used by tests)."""
    global _table
    _table = None


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _dec(x) -> Decimal:
    return Decimal(str(x))


def _plain(item: dict) -> dict:
    """DynamoDB returns Decimals; convert back to int/float for JSON."""
    out = {}
    for k, v in item.items():
        if isinstance(v, Decimal):
            out[k] = int(v) if v == v.to_integral_value() else float(v)
        else:
            out[k] = v
    return out


def should_audit(result: dict) -> bool:
    return (result.get("risk_level") != "low"
            or bool(result.get("is_malicious"))
            or bool(result.get("rule_flags")))


def log_analysis(user_input: str, result: dict, request_id: str, user: str = None, now: datetime = None):
    now = now or datetime.now(timezone.utc)
    day, ts = now.strftime("%Y-%m-%d"), now.isoformat()
    sk = f"{ts}#{request_id}"
    expires = int((now + timedelta(days=RETENTION_DAYS)).timestamp())
    usage = result.get("usage", {})
    digest = _sha256(user_input)

    table().put_item(Item={
        "pk": f"REQ#{day}", "sk": sk, "expires_at": expires,
        "request_id": request_id, "input_sha256": digest, "input_chars": len(user_input),
        "risk_level": result.get("risk_level", "unknown"), "method": result.get("method", "unknown"),
        "llm_calls": usage.get("llm_calls", 0),
        "input_tokens": usage.get("input_tokens", 0), "output_tokens": usage.get("output_tokens", 0),
        "cost_usd": _dec(usage.get("cost_usd", 0.0)), "latency_ms": _dec(usage.get("latency_ms", 0.0)),
        "cache_hit": bool(usage.get("cache_hit")),
    })

    if not should_audit(result):
        return

    table().put_item(Item={
        "pk": f"AUDIT#{day}", "sk": sk, "expires_at": expires,
        "timestamp": ts, "request_id": request_id, "user": user or "unknown",
        "input_text": user_input[:500], "input_sha256": digest,
        "risk_level": result.get("risk_level", "unknown"), "attack_type": result.get("attack_type", "unknown"),
        "confidence": _dec(result.get("confidence", 0.0)), "is_malicious": bool(result.get("is_malicious")),
        "reasoning": result.get("reasoning", ""), "method": result.get("method", "unknown"),
        "rule_flags": ",".join(result.get("rule_flags", [])),
    })


def _days(n: int, now: datetime = None):
    now = now or datetime.now(timezone.utc)
    return [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(n)]


def _query_all(pk: str, newest_first: bool = True, limit: int = None) -> list:
    items, kwargs = [], {"KeyConditionExpression": Key("pk").eq(pk), "ScanIndexForward": not newest_first}
    if limit:
        kwargs["Limit"] = limit
    while True:
        page = table().query(**kwargs)
        items.extend(page.get("Items", []))
        if (limit and len(items) >= limit) or "LastEvaluatedKey" not in page:
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    return items[:limit] if limit else items


def get_recent_flags(limit: int = 20, days: int = 30, now: datetime = None) -> list:
    flags = []
    for day in _days(days, now):
        flags.extend(_query_all(f"AUDIT#{day}", limit=limit - len(flags)))
        if len(flags) >= limit:
            break
    return [_plain(f) for f in flags[:limit]]


def get_stats(days: int = 30, now: datetime = None) -> dict:
    flags = [_plain(f) for day in _days(days, now) for f in _query_all(f"AUDIT#{day}")]
    return {
        "total_flagged": len(flags),
        "high_risk": sum(1 for f in flags if f["risk_level"] == "high"),
        "medium_risk": sum(1 for f in flags if f["risk_level"] == "medium"),
        "malicious_confirmed": sum(1 for f in flags if f["is_malicious"]),
        "window_days": days,
    }


def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * len(ordered)) - 1))
    return round(ordered[idx], 2)


def get_metrics(days: int = 7, now: datetime = None) -> dict:
    rows = [_plain(r) for day in _days(days, now) for r in _query_all(f"REQ#{day}")]
    n = len(rows)
    if n == 0:
        return {"total_requests": 0, "window_days": days}

    latencies = [r["latency_ms"] for r in rows]
    total_cost = sum(r["cost_usd"] for r in rows)
    by_risk, by_method = {}, {}
    for r in rows:
        by_risk[r["risk_level"]] = by_risk.get(r["risk_level"], 0) + 1
        by_method[r["method"]] = by_method.get(r["method"], 0) + 1

    return {
        "window_days": days,
        "total_requests": n,
        "requests_without_llm_call_pct": round(100 * sum(1 for r in rows if r["llm_calls"] == 0) / n, 1),
        "rule_short_circuit_count": by_method.get("rule_short_circuit", 0),
        "cache_hit_rate_pct": round(100 * sum(1 for r in rows if r["cache_hit"]) / n, 1),
        "llm_calls": sum(r["llm_calls"] for r in rows),
        "input_tokens": sum(r["input_tokens"] for r in rows),
        "output_tokens": sum(r["output_tokens"] for r in rows),
        "total_cost_usd": round(total_cost, 6),
        "avg_cost_per_request_usd": round(total_cost / n, 8),
        "latency_ms": {"avg": round(sum(latencies) / n, 2),
                       "p50": _percentile(latencies, 50), "p95": _percentile(latencies, 95)},
        "by_risk_level": by_risk,
        "by_method": by_method,
    }
