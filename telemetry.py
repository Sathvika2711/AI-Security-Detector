"""
telemetry.py — Cost, latency and structured logging helpers
============================================================

Keeps the observability concerns out of the detection logic:

  * token -> USD cost calculation (prices configurable via env vars)
  * a monotonic timer for latency measurement
  * a JSON-lines logger so every request produces one machine-readable
    log line that can be shipped to CloudWatch / ELK / Datadog as-is
"""

import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone

# ── PRICING ───────────────────────────────────────────────────
# USD per million tokens. Defaults are for Claude Haiku 4.5.
# Override with env vars if you switch models or prices change.
PRICE_INPUT_PER_MTOK = float(os.environ.get("DETECTOR_PRICE_INPUT_PER_MTOK", "1.00"))
PRICE_OUTPUT_PER_MTOK = float(os.environ.get("DETECTOR_PRICE_OUTPUT_PER_MTOK", "5.00"))


def token_cost_usd(input_tokens: int, output_tokens: int) -> float:
    """Convert a token count into a USD cost."""
    cost = (input_tokens * PRICE_INPUT_PER_MTOK + output_tokens * PRICE_OUTPUT_PER_MTOK) / 1_000_000
    return round(cost, 8)


def empty_usage() -> dict:
    """Usage block for a request that made no LLM call."""
    return {
        "llm_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_usd": 0.0,
        "latency_ms": 0.0,
        "cache_hit": False,
    }


class Timer:
    """Context manager that measures wall-clock time in milliseconds."""

    def __enter__(self):
        self._start = time.perf_counter()
        self.ms = 0.0
        return self

    def __exit__(self, *exc):
        self.ms = round((time.perf_counter() - self._start) * 1000, 2)
        return False


# ── STRUCTURED LOGGING ────────────────────────────────────────

class JsonFormatter(logging.Formatter):
    """Render each log record as a single JSON object."""

    def format(self, record):
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if extra:
            payload.update(extra)
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__
        return json.dumps(payload, default=str)


def get_logger(name: str = "detector") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)  # stdout is reserved for MCP stdio
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))
        logger.propagate = False
    return logger


def log_event(logger: logging.Logger, msg: str, **fields):
    """Log a structured event: log_event(log, "analysed", risk="high", ms=12.3)"""
    logger.info(msg, extra={"fields": fields})


# ── CLOUDWATCH EMBEDDED METRIC FORMAT (EMF) ───────────────────
# In Lambda, printing one JSON line in EMF format to stdout makes
# CloudWatch create real metrics from it — no API calls, no extra cost
# per PutMetricData, and the log line doubles as a structured log.

METRIC_NAMESPACE = os.environ.get("METRIC_NAMESPACE", "AIGuardrail")


def emf_record(metrics: dict, units: dict, dimensions: dict, properties: dict = None) -> dict:
    """Build an EMF document. metrics={"LatencyMs": 12.3}, units={"LatencyMs": "Milliseconds"}."""
    return {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [list(dimensions.keys())],
                "Metrics": [{"Name": k, "Unit": units.get(k, "None")} for k in metrics],
            }],
        },
        **dimensions,
        **metrics,
        **(properties or {}),
    }


def emit_emf(metrics: dict, units: dict, dimensions: dict, properties: dict = None):
    print(json.dumps(emf_record(metrics, units, dimensions, properties), default=str), flush=True)


# ── SAFE ERROR DETAILS ────────────────────────────────────────
# Error messages are what make incidents debuggable (e.g. Bedrock's
# "Model use case details have not been submitted"), but they can echo
# credentials. Redact anything key-like and cap the length before logging.

_SECRET_PATTERNS = [
    re.compile(r"sk-ant-[A-Za-z0-9_\-]+"),                 # Anthropic API keys
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),             # AWS access key IDs
    re.compile(r"(?i)(secret|token|password|signature)(\W{1,3})[^\s,;]+"),
]


def safe_error_detail(exc: BaseException, limit: int = 300) -> str:
    text = f"{type(exc).__name__}: {exc}"
    for rx in _SECRET_PATTERNS:
        text = rx.sub(lambda m: (m.group(1) + m.group(2) if m.lastindex and m.lastindex >= 2 else "") + "[REDACTED]", text)
    return text[:limit]
