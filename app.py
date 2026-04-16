"""
app.py — Flask API for AI Prompt Injection Detector
=====================================================

ENDPOINTS:
  POST /analyse     — analyse a single input for threats
  GET  /audit       — view recent flagged inputs
  GET  /stats       — summary statistics
  GET  /health      — health check

HOW TO RUN:
  1. Set ANTHROPIC_API_KEY in your .env file
  2. On Windows: $env:ANTHROPIC_API_KEY="sk-ant-..."
  3. python app.py
  4. POST to http://localhost:5000/analyse
"""

import os
from flask import Flask, request, jsonify
from detector import analyse_input
from audit_log import init_db, log_analysis, get_recent_flags, get_stats

app = Flask(__name__)

# Initialise the database on startup
init_db()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "service": "AI Prompt Injection Detector"})


@app.route("/analyse", methods=["POST"])
def analyse():
    """
    Analyse a user input for prompt injection and security threats.

    Request body:
        { "input": "text to analyse" }

    Response:
        {
            "input": "original text",
            "risk_level": "low|medium|high",
            "attack_type": "none|prompt_injection|...",
            "confidence": 0.95,
            "is_malicious": false,
            "reasoning": "explanation",
            "safe_to_process": true
        }
    """
    data = request.get_json()

    if not data or "input" not in data:
        return jsonify({"error": "Request body must contain 'input' field"}), 400

    user_input = data["input"].strip()

    if not user_input:
        return jsonify({"error": "Input cannot be empty"}), 400

    # Run the detection
    result = analyse_input(user_input)

    # Log to audit trail if suspicious
    log_analysis(user_input, result)

    # Return result with original input for traceability
    return jsonify({
        "input": user_input[:200],  # truncate for response
        **result
    })


@app.route("/audit", methods=["GET"])
def audit():
    """
    View recent flagged inputs from the audit log.
    In production this would be protected by authentication.
    """
    limit = request.args.get("limit", 20, type=int)
    flags = get_recent_flags(limit=limit)
    return jsonify({
        "total": len(flags),
        "flags": flags
    })


@app.route("/stats", methods=["GET"])
def stats():
    """Summary statistics for the audit log"""
    return jsonify(get_stats())


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  AI Prompt Injection Detector")
    print("  Analyse: POST http://localhost:5000/analyse")
    print("  Audit:   GET  http://localhost:5000/audit")
    print("  Stats:   GET  http://localhost:5000/stats")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
