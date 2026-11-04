"""Shared test setup: import path, isolated DB, no real API key, clean cache."""

import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Point the module-level DB at a throwaway file before anything imports app.py
os.environ.setdefault("AUDIT_DB_PATH", os.path.join(tempfile.mkdtemp(), "import_time.db"))
# Tests must never call real services, whatever the developer's terminal has set
# (e.g. LLM_PROVIDER=bedrock left over from running the eval).
for _var in ("ANTHROPIC_API_KEY", "LLM_PROVIDER", "BEDROCK_MODEL_ID", "DETECTOR_MODE"):
    os.environ.pop(_var, None)

import pytest  # noqa: E402


class FakeResponse:
    def __init__(self, content, input_tokens=100, output_tokens=50):
        self.content = content
        self.usage_metadata = {"input_tokens": input_tokens, "output_tokens": output_tokens}


class FakeLLM:
    """
    Stand-in for ChatAnthropic. `reply` is either a string, an Exception,
    or a callable(prompt_text) -> string. Records every prompt it receives.
    """

    def __init__(self, reply):
        self.reply = reply
        self.prompts = []

    @property
    def calls(self):
        return len(self.prompts)

    def invoke(self, messages):
        text = "\n".join(m.content for m in messages)
        self.prompts.append(text)
        reply = self.reply(text) if callable(self.reply) else self.reply
        if isinstance(reply, Exception):
            raise reply
        return FakeResponse(reply)


def verdict(risk="low", attack="none", confidence=0.9, malicious=False, safe=True,
            reasoning="test verdict"):
    import json
    return json.dumps({"risk_level": risk, "attack_type": attack, "confidence": confidence,
                       "is_malicious": malicious, "reasoning": reasoning, "safe_to_process": safe})


@pytest.fixture(autouse=True)
def clear_cache():
    import detector
    detector.cache.clear()
    yield
    detector.cache.clear()


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    import audit_log
    path = str(tmp_path / "test_audit.db")
    monkeypatch.setattr(audit_log, "DB_PATH", path)
    audit_log.init_db()
    return path
