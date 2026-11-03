"""
lambda_handler.py — AWS Lambda entry point (API Gateway HTTP API, payload v2)
===============================================================================

ROUTES (all except /health require a Cognito JWT, checked by API Gateway
before Lambda is even invoked)
  GET  /health    liveness check                         (public)
  POST /analyse   screen one input                       (any signed-in user)
  GET  /metrics   cost / latency / LLM-offload metrics   (any signed-in user)
  GET  /stats     flagged-input counts                   (any signed-in user)
  GET  /audit     recent flagged inputs incl. text       (Cognito group "admins" only)

Authentication = API Gateway JWT authorizer (Cognito, OAuth 2.0 / OIDC).
Authorisation  = role check here, using the token's `cognito:groups` claim.

Every request emits CloudWatch EMF metrics (latency, cost, LLM calls,
blocked inputs) and is written to DynamoDB via dynamo_store.
"""

import json
import os

import dynamo_store as store
from detector import MAX_INPUT_CHARS
from graph import analyse_input_graph
from telemetry import emit_emf, get_logger, log_event

log = get_logger("lambda")

ADMIN_GROUP = os.environ.get("ADMIN_GROUP", "admins")
SERVICE = os.environ.get("SERVICE_NAME", "ai-guardrail")


# ── HELPERS ───────────────────────────────────────────────────

def respond(status: int, body: dict, request_id: str = "") -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": request_id,
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(body, default=str),
    }


def claims(event: dict) -> dict:
    return (event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})) or {}


def groups(event: dict) -> set:
    """API Gateway passes cognito:groups as a string like "[admins users]"."""
    raw = claims(event).get("cognito:groups", "")
    if isinstance(raw, list):
        return set(raw)
    return {g for g in raw.strip("[]").replace(",", " ").split() if g}


def query_int(event: dict, name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int((event.get("queryStringParameters") or {}).get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(lo, min(value, hi))


# ── ROUTES ────────────────────────────────────────────────────

def analyse(event: dict, request_id: str) -> dict:
    try:
        data = json.loads(event.get("body") or "")
    except (json.JSONDecodeError, TypeError):
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("input"), str):
        return respond(400, {"error": "Body must be JSON with a string 'input' field"}, request_id)

    user_input = data["input"].strip()
    if not user_input:
        return respond(400, {"error": "Input cannot be empty"}, request_id)
    if len(user_input) > MAX_INPUT_CHARS:
        return respond(413, {"error": f"Input exceeds {MAX_INPUT_CHARS} characters"}, request_id)

    result = analyse_input_graph(user_input)
    user = claims(event).get("email") or claims(event).get("sub")
    store.log_analysis(user_input, result, request_id, user=user)

    usage = result["usage"]
    emit_emf(
        metrics={
            "Requests": 1,
            "Blocked": 0 if result["safe_to_process"] else 1,
            "HighRisk": 1 if result["risk_level"] == "high" else 0,
            "LLMCalls": usage["llm_calls"],
            "CacheHits": 1 if usage["cache_hit"] else 0,
            "CostUSD": usage["cost_usd"],
            "LatencyMs": usage["latency_ms"],
        },
        units={"LatencyMs": "Milliseconds", "Requests": "Count", "Blocked": "Count", "HighRisk": "Count",
               "LLMCalls": "Count", "CacheHits": "Count"},
        dimensions={"Service": SERVICE},
        properties={"request_id": request_id, "method": result["method"], "risk_level": result["risk_level"]},
    )
    return respond(200, {"request_id": request_id, **result}, request_id)


def handler(event: dict, context=None) -> dict:
    request_id = event.get("requestContext", {}).get("requestId", "") or getattr(context, "aws_request_id", "")
    route = event.get("routeKey", "")
    try:
        if route == "GET /health":
            return respond(200, {"status": "ok", "service": SERVICE}, request_id)
        if route == "POST /analyse":
            return analyse(event, request_id)
        if route == "GET /metrics":
            return respond(200, store.get_metrics(days=query_int(event, "days", 7, 1, 30)), request_id)
        if route == "GET /stats":
            return respond(200, store.get_stats(), request_id)
        if route == "GET /audit":
            if ADMIN_GROUP not in groups(event):
                return respond(403, {"error": f"Requires the '{ADMIN_GROUP}' group"}, request_id)
            flags = store.get_recent_flags(limit=query_int(event, "limit", 20, 1, 100))
            return respond(200, {"total": len(flags), "flags": flags}, request_id)
        return respond(404, {"error": "Not found"}, request_id)
    except Exception:
        log.exception("unhandled_error", extra={"fields": {"request_id": request_id, "route": route}})
        return respond(500, {"error": "Internal server error", "request_id": request_id}, request_id)
    finally:
        log_event(log, "request", request_id=request_id, route=route)
