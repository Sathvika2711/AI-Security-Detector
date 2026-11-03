"""
graph.py — The guardrail pipeline as a LangGraph state machine
================================================================

Same detection logic as detector.analyse_input(), but each stage is an
explicit node in a LangGraph StateGraph, with routing decisions as
conditional edges:

    START -> screen -> rules --(rules mode)------> rules_verdict -> END
                         |---(strong rule, hybrid)-> block ------> END
                         '---(otherwise)---------> cache --(hit)--> END
                                                     '--(miss)--> classify
                                     classify --(ok)----> finalise ----> END
                                              '--(error)-> fail_closed -> END

Why a graph?
  * Every routing decision is visible and testable on its own.
  * New stages (PII redaction, output filtering, human review for
    high-risk actions) slot in as nodes without rewriting the pipeline.
  * The same compiled graph runs locally, in AWS Lambda, behind the
    MCP server, or on Bedrock AgentCore.

The LLM client is passed through LangGraph's `config["configurable"]`
rather than the state, so the state stays plain, serialisable data.
"""

import json
from typing import Optional, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError

import detector as d
from telemetry import Timer, empty_usage, get_logger, token_cost_usd

log = get_logger("graph")


class GuardState(TypedDict, total=False):
    text: str
    mode: str
    use_cache: bool
    rules: list            # list[detector.Rule]
    cache_key: str
    worst: dict            # worst LLM assessment across chunks
    tokens_in: int
    tokens_out: int
    llm_calls: int
    error: str             # "parse" | "call"
    result: dict           # final verdict (set by the terminal node)


# ── NODES ─────────────────────────────────────────────────────

def screen(state: GuardState) -> GuardState:
    text = state["text"]
    if not text or not text.strip():
        return {"result": d._result("low", "none", 1.0, False, "Empty input — nothing to analyse.",
                                    True, "empty_check")}
    if len(text) > d.MAX_INPUT_CHARS:
        return {"result": d._result("medium", "other", 0.5, False,
                                    f"Input exceeds {d.MAX_INPUT_CHARS} characters and was not fully analysed.",
                                    False, "size_limit")}
    return {}


def rules(state: GuardState) -> GuardState:
    return {"rules": d.match_rules(state["text"])}


def rules_verdict(state: GuardState) -> GuardState:
    return {"result": d._rules_only(state["rules"])}


def block(state: GuardState) -> GuardState:
    out = d._rules_only(state["rules"])
    out["method"] = "rule_short_circuit"
    return {"result": out}


def cache(state: GuardState) -> GuardState:
    key = d.TTLCache.key(state["mode"], state["text"])
    if state.get("use_cache", True):
        hit = d.cache.get(key)
        if hit is not None:
            out = json.loads(json.dumps(hit))
            out["usage"] = {**empty_usage(), "cache_hit": True}
            return {"cache_key": key, "result": out}
    return {"cache_key": key}


def classify(state: GuardState, config: RunnableConfig) -> GuardState:
    llm = (config or {}).get("configurable", {}).get("llm") or d.get_llm()
    rule_hits = state.get("rules", [])
    hint = "Not used." if state["mode"] == "llm" else (
        "Matched: " + ", ".join(r.name for r in rule_hits) if rule_hits else "No patterns matched.")

    tokens_in = tokens_out = calls = 0
    worst = None
    try:
        for chunk in d._chunks(state["text"]):
            assessment, i, o = d._call_llm(llm, chunk, hint)
            tokens_in, tokens_out, calls = tokens_in + i, tokens_out + o, calls + 1
            if worst is None or d.RISK_ORDER[assessment["risk_level"]] > d.RISK_ORDER[worst["risk_level"]]:
                worst = assessment
    except (ValidationError, ValueError, json.JSONDecodeError) as e:
        log.warning("llm_output_invalid", extra={"fields": {"error": type(e).__name__}})
        return {"error": "parse"}
    except Exception as e:  # network, auth, throttling, timeout...
        log.error("llm_call_failed", extra={"fields": {"error": type(e).__name__}})
        return {"error": "call"}

    return {"worst": worst, "tokens_in": tokens_in, "tokens_out": tokens_out, "llm_calls": calls}


def fail_closed(state: GuardState) -> GuardState:
    if state["error"] == "parse":
        return {"result": d._fail_closed(state.get("rules", []), "llm_parse_fallback",
                                         "LLM returned an invalid assessment.")}
    return {"result": d._fail_closed(state.get("rules", []), "error_fallback", "LLM analysis unavailable.")}


def finalise(state: GuardState) -> GuardState:
    w = state["worst"]
    out = d._result(w["risk_level"], w["attack_type"], w["confidence"], w["is_malicious"],
                    w["reasoning"], w["safe_to_process"], "langchain_claude", state.get("rules", []))
    out["usage"].update(
        llm_calls=state["llm_calls"],
        input_tokens=state["tokens_in"],
        output_tokens=state["tokens_out"],
        cost_usd=token_cost_usd(state["tokens_in"], state["tokens_out"]),
    )
    if state.get("use_cache", True):
        d.cache.set(state["cache_key"], out)
    return {"result": out}


# ── ROUTING ───────────────────────────────────────────────────

def after_screen(state: GuardState) -> str:
    return "done" if "result" in state else "rules"


def after_rules(state: GuardState) -> str:
    if state["mode"] == "rules":
        return "rules_verdict"
    hits = state["rules"]
    if state["mode"] == "hybrid" and hits and hits[0].strong:
        return "block"
    return "cache"


def after_cache(state: GuardState) -> str:
    return "done" if "result" in state else "classify"


def after_classify(state: GuardState) -> str:
    return "fail_closed" if state.get("error") else "finalise"


# ── BUILD ─────────────────────────────────────────────────────

def build_graph():
    g = StateGraph(GuardState)
    for name, fn in [("screen", screen), ("rules", rules), ("rules_verdict", rules_verdict),
                     ("block", block), ("cache", cache), ("classify", classify),
                     ("fail_closed", fail_closed), ("finalise", finalise)]:
        g.add_node(name, fn)

    g.add_edge(START, "screen")
    g.add_conditional_edges("screen", after_screen, {"done": END, "rules": "rules"})
    g.add_conditional_edges("rules", after_rules,
                            {"rules_verdict": "rules_verdict", "block": "block", "cache": "cache"})
    g.add_conditional_edges("cache", after_cache, {"done": END, "classify": "classify"})
    g.add_conditional_edges("classify", after_classify,
                            {"fail_closed": "fail_closed", "finalise": "finalise"})
    for terminal in ("rules_verdict", "block", "fail_closed", "finalise"):
        g.add_edge(terminal, END)
    return g.compile()


guard_graph = build_graph()


def analyse_input_graph(user_input: str, mode: Optional[str] = None, llm=None, use_cache: bool = True) -> dict:
    """Drop-in replacement for detector.analyse_input(), run through the graph."""
    mode = mode or d.DEFAULT_MODE
    if mode not in d.MODES:
        raise ValueError(f"mode must be one of {d.MODES}")

    with Timer() as t:
        state = guard_graph.invoke(
            {"text": user_input, "mode": mode, "use_cache": use_cache},
            config={"configurable": {"llm": llm}},
        )
    result = state["result"]
    result["usage"]["latency_ms"] = t.ms
    return result


def mermaid() -> str:
    """Mermaid source of the compiled graph — used to keep the README diagram honest."""
    return guard_graph.get_graph().draw_mermaid()
