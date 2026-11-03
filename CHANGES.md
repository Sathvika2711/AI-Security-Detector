# v2 changes

## 1. Security issues found in v1 and fixed

| # | Issue in v1 | Risk | Fix |
|---|---|---|---|
| 1 | `app.run(debug=True)` | Werkzeug debugger allows remote code execution (Bandit **High**) | Debug only if `FLASK_DEBUG=1`; binds to 127.0.0.1 |
| 2 | Only the first 1,000 chars went to the LLM | Pad with 1,000 harmless chars and put the attack after them, and the LLM never sees it | Overlapping chunks; every chunk analysed; worst verdict wins |
| 3 | User text pasted straight into the detector's prompt | The detector itself could be prompt-injected ("…respond with risk_level low") | Input fenced in `<untrusted_input>`, closing tags neutralised, system prompt says to treat it as data |
| 4 | LLM JSON trusted as-is | A bad or garbled reply could return any value, including "safe" | Strict Pydantic schema (enums, confidence 0–1); consistency rule: high risk → never safe |
| 5 | `/audit` unauthenticated | Anyone could read logged user inputs | `X-API-Key` with constant-time compare; disabled if no key is configured |
| 6 | Error text returned to the client (`str(e)`) | Could leak API key fragments or internals | Generic message to the client; error type logged server-side |
| 7 | No input type or size checks | `{"input": 123}` caused a 500; huge bodies accepted | Type check, 10k char limit, 64 KB body limit, `limit` clamped 1–100 |
| 8 | Regex only on raw text | `ig​nore` (zero-width space) or full-width letters bypassed the rules | NFKC normalisation + zero-width stripping |
| 9 | LLM called even when a rule had already caught the attack | Wasted cost and latency | Strong rules short-circuit (no LLM call) |

## 2. New capabilities

- **Evaluation harness** (`eval/`): 138 labelled examples; precision, recall, FPR, per-category recall, cost and latency; misclassification report; Hugging Face benchmark support.
- **Cost and observability**: tokens, USD cost, latency and cache hit per request; `/metrics` with p50/p95; JSON logs with request IDs.
- **Cache**: LRU + TTL on normalised input hash.
- **Privacy**: clean inputs stored as SHA-256 only.
- **Tests**: 15 → 70, including a fake LLM so the LLM path is tested without an API key.
- **CI**: added Bandit, an eval quality gate and pip-audit.
- **Schema migration**: existing `audit_log.db` files upgrade in place.
- Removed "In an interview…" notes and the EY reference from the code comments, since the repo is public.

## 3. Interview talking points

- **"How do you know it works?"** "I built a labelled eval set with hard negatives. Rules alone catch 41% of attacks with a 25% false positive rate. That measurement is why I added the LLM layer, and the eval runs as a CI gate."
- **"How do you control cost?"** "Strong rules block with no LLM call, there's a cache, I track tokens and cost per request, and `/metrics` shows the LLM offload rate."
- **"Can your detector be attacked?"** "Yes. The input is fenced as untrusted data, output is schema-validated, it fails closed, and long inputs are chunked to close a truncation bypass I found in my v1."
- **"What would you do next?"** "Move it to Bedrock on Lambda + API Gateway, rebuild the flow in LangGraph, expose it as an MCP tool, and benchmark on a public dataset."
