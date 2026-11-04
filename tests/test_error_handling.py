"""
tests/test_error_handling.py — Failures are labelled correctly, logged with a
useful (redacted) reason, and ALWAYS fail closed — in both engines.
"""

import json
import logging

import pytest

import detector
from conftest import FakeLLM, verdict
from detector import analyse_input
from graph import analyse_input_graph
from telemetry import safe_error_detail

ENGINES = {"classic": analyse_input, "graph": analyse_input_graph}


class _Collector(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []

    def emit(self, record):
        self.records.append({"msg": record.getMessage(), **getattr(record, "fields", {})})


@pytest.fixture
def capfd():
    """Collect structured log records from the detector and graph loggers."""
    collector = _Collector()
    loggers = [logging.getLogger(n) for n in ("detector", "graph")]
    for lg in loggers:
        lg.addHandler(collector)
    yield collector
    for lg in loggers:
        lg.removeHandler(collector)


def log_lines(collector):
    return collector.records


@pytest.mark.parametrize("engine", ENGINES)
def test_client_creation_failure_fails_closed_and_is_labelled_as_call_failure(engine, monkeypatch, capfd):
    """e.g. missing botocore[crt] or bad credentials while building the Bedrock client."""
    def broken_client():
        raise ValueError("Could not load credentials to authenticate with AWS client")
    monkeypatch.setattr(detector, "get_llm", broken_client)

    result = ENGINES[engine]("What is my policy excess?", mode="llm")   # must not raise
    assert result["method"] == "error_fallback"
    assert result["safe_to_process"] is False

    logs = log_lines(capfd)
    assert any(l["msg"] == "llm_call_failed" for l in logs)
    assert not any(l["msg"] == "llm_output_invalid" for l in logs)    # the v3.0 mislabel
    assert "Could not load credentials" in next(l for l in logs if l["msg"] == "llm_call_failed")["detail"]


@pytest.mark.parametrize("engine", ENGINES)
def test_bedrock_refusal_reason_is_logged(engine, capfd):
    class ResourceNotFoundException(Exception):
        pass
    err = ResourceNotFoundException("Model use case details have not been submitted for this account.")
    ENGINES[engine]("hello", mode="llm", llm=FakeLLM(err))
    failed = next(l for l in log_lines(capfd) if l["msg"] == "llm_call_failed")
    assert failed["error"] == "ResourceNotFoundException"
    assert "use case details" in failed["detail"]


@pytest.mark.parametrize("engine", ENGINES)
def test_invalid_output_still_labelled_as_output_problem(engine, capfd):
    result = ENGINES[engine]("hello", mode="llm", llm=FakeLLM("definitely not json"))
    assert result["method"] == "llm_parse_fallback"
    assert any(l["msg"] == "llm_output_invalid" for l in log_lines(capfd))


@pytest.mark.parametrize("engine", ENGINES)
def test_secrets_in_error_messages_are_redacted_from_logs(engine, capfd):
    err = RuntimeError("401 invalid x-api-key sk-ant-api03-SECRETVALUE key AKIAABCDEFGHIJKLMNOP")
    ENGINES[engine]("hello", mode="llm", llm=FakeLLM(err))
    raw = json.dumps(capfd.records)
    assert "SECRETVALUE" not in raw and "AKIAABCDEFGHIJKLMNOP" not in raw
    assert "[REDACTED]" in raw


class TestSafeErrorDetail:

    def test_redacts_key_like_values_and_keeps_the_reason(self):
        out = safe_error_detail(RuntimeError("bad token=abc123xyz for sk-ant-api03-zzz"))
        assert "abc123xyz" not in out and "sk-ant-api03-zzz" not in out
        assert out.startswith("RuntimeError: bad token")

    def test_truncates(self):
        assert len(safe_error_detail(RuntimeError("x" * 5000))) == 300


def test_bedrock_client_uses_adaptive_retries(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setattr(detector, "LLM_PROVIDER", "bedrock")
    llm = detector._build_llm()
    retries = llm.client.meta.config.retries
    assert retries["mode"] == "adaptive"
    assert retries["total_max_attempts"] == 5      # first try + 4 retries
    assert llm.client.meta.config.read_timeout == 20
    assert llm.max_tokens == 300
