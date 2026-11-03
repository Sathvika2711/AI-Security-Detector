"""
app.py — Flask API for AI Prompt Injection Detector
=====================================================

ENDPOINTS
  POST /analyse   analyse one input                      (public)
  GET  /health    health check                           (public)
  GET  /audit     recent flagged inputs                  (admin — X-API-Key)
  GET  /stats     audit-log summary                      (admin — X-API-Key)
  GET  /metrics   cost / latency / LLM-offload metrics   (admin — X-API-Key)

CONFIG (environment variables)
  ANTHROPIC_API_KEY   required for llm / hybrid modes
  ADMIN_API_KEY       enables the admin endpoints; if unset they return 503
  DETECTOR_MODE       rules | llm | hybrid (default hybrid)
  FLASK_DEBUG         "1" to enable debug mode locally — never in production
"""

import hmac
import os
import uuid
from functools import wraps

from flask import Flask, g, jsonify, request

from audit_log import get_metrics, get_recent_flags, get_stats, init_db, log_analysis
from detector import MAX_INPUT_CHARS, analyse_input
from telemetry import get_logger, log_event

log = get_logger("api")


def require_admin(view):
    """Protect endpoints that expose logged user inputs or operational data."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        expected = os.environ.get("ADMIN_API_KEY", "")
        if not expected:
            return jsonify({"error": "Admin endpoints disabled: set ADMIN_API_KEY"}), 503
        supplied = request.headers.get("X-API-Key", "")
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            return jsonify({"error": "Unauthorised"}), 401
        return view(*args, **kwargs)
    return wrapper


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject huge request bodies early
    init_db()

    @app.before_request
    def assign_request_id():
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming[:64] if incoming else uuid.uuid4().hex

    @app.after_request
    def add_headers(resp):
        resp.headers["X-Request-ID"] = g.get("request_id", "")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(413)
    def too_large(_):
        return jsonify({"error": "Request body too large"}), 413

    @app.errorhandler(Exception)
    def unhandled(e):
        code = getattr(e, "code", 500)
        if isinstance(code, int) and code < 500:
            return jsonify({"error": getattr(e, "description", "Bad request")}), code
        log.exception("unhandled_error", extra={"fields": {"request_id": g.get("request_id")}})
        return jsonify({"error": "Internal server error", "request_id": g.get("request_id")}), 500

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "AI Prompt Injection Detector"})

    @app.route("/analyse", methods=["POST"])
    def analyse():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or "input" not in data:
            return jsonify({"error": "Request body must be JSON with an 'input' field"}), 400
        if not isinstance(data["input"], str):
            return jsonify({"error": "'input' must be a string"}), 400

        user_input = data["input"].strip()
        if not user_input:
            return jsonify({"error": "Input cannot be empty"}), 400
        if len(user_input) > MAX_INPUT_CHARS:
            return jsonify({"error": f"Input exceeds {MAX_INPUT_CHARS} characters"}), 413

        result = analyse_input(user_input)
        log_analysis(user_input, result, request_id=g.request_id)

        usage = result["usage"]
        log_event(log, "analysed", request_id=g.request_id, risk=result["risk_level"],
                  method=result["method"], llm_calls=usage["llm_calls"],
                  cost_usd=usage["cost_usd"], latency_ms=usage["latency_ms"],
                  cache_hit=usage["cache_hit"])

        return jsonify({"request_id": g.request_id, "input": user_input[:200], **result})

    @app.route("/audit", methods=["GET"])
    @require_admin
    def audit():
        limit = max(1, min(request.args.get("limit", 20, type=int), 100))
        flags = get_recent_flags(limit=limit)
        return jsonify({"total": len(flags), "flags": flags})

    @app.route("/stats", methods=["GET"])
    @require_admin
    def stats():
        return jsonify(get_stats())

    @app.route("/metrics", methods=["GET"])
    @require_admin
    def metrics():
        return jsonify(get_metrics())

    return app


app = create_app()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"
    print("\n" + "=" * 55)
    print("  AI Prompt Injection Detector")
    print("  Analyse: POST http://127.0.0.1:5000/analyse")
    print("  Metrics: GET  http://127.0.0.1:5000/metrics  (X-API-Key)")
    print("=" * 55 + "\n")
    app.run(host="127.0.0.1", port=5000, debug=debug)  # debug only when FLASK_DEBUG=1
