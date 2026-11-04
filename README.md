# AI Guardrail: Prompt-Injection Detection Service

![CI](https://github.com/Sathvika2711/AI-Security-Detector/actions/workflows/tests.yml/badge.svg)

A guardrail service that screens text **before it reaches an LLM or an agent**. It detects prompt injection, jailbreaks, role hijacking, system-prompt extraction, and instructions hidden inside documents, emails or tool outputs.

The detection pipeline is a **LangGraph** state machine: tiered rules first, then Claude. It runs in four places:

| Where | How |
|---|---|
| **AWS serverless** | API Gateway (Cognito JWT) → Lambda → **Amazon Bedrock**, with DynamoDB and CloudWatch, all defined in **AWS CDK (TypeScript)** |
| **Dashboard** | **Next.js + TypeScript** with **OAuth 2.0 / OIDC** login (Cognito, PKCE) |
| **AI agents** | A **Model Context Protocol (MCP)** server, so Claude Desktop, Claude Code or any MCP agent can call `scan_prompt` |
| **Local** | A Flask API with SQLite, for development |

Every change is measured: there's a labelled evaluation harness, a public benchmark, per-request cost and latency, and a quality gate in CI.

---

## Architecture

```mermaid
flowchart LR
    U[User] -->|OAuth 2.0 / OIDC + PKCE| COG[Amazon Cognito]
    U --> WEB[Next.js dashboard<br/>AWS Amplify]
    WEB -->|Bearer JWT| APIGW[API Gateway HTTP API<br/>JWT authorizer · throttling]
    AGENT[AI agent<br/>Claude Desktop / Code] -->|MCP stdio| MCP[MCP server<br/>scan_prompt]
    APIGW --> L[Lambda · Python 3.12<br/>LangGraph pipeline]
    MCP --> G[LangGraph pipeline]
    L -->|least-privilege IAM| BR[Amazon Bedrock<br/>Claude Haiku 4.5]
    L --> DDB[(DynamoDB<br/>single table · TTL)]
    L -->|EMF metrics| CW[CloudWatch<br/>dashboard · alarm]
```

### The LangGraph pipeline

```mermaid
flowchart TD
    S([start]) --> SC[screen<br/>empty / size limit]
    SC -->|invalid| E([end])
    SC --> R[rules<br/>NFKC + zero-width strip, tiered regex]
    R -->|rules mode| RV[rules_verdict] --> E
    R -->|strong rule, hybrid| B[block<br/>no LLM call, $0] --> E
    R --> C[cache]
    C -->|hit| E
    C -->|miss| CL[classify<br/>Claude, input fenced as untrusted, chunked]
    CL -->|invalid output / API error| F[fail_closed<br/>never 'safe'] --> E
    CL --> FI[finalise<br/>verdict + tokens + cost] --> E
```

Each routing decision is a separate, testable edge. New stages, such as PII redaction or human review for high-risk actions, slot in as nodes. `graph.py` is **verified identical** to the original detector on every example in the dataset, in all three modes (`tests/test_graph.py`).

---

## Security design

- **The detector resists injection itself.** Input is wrapped in `<untrusted_input>` tags and closing tags are neutralised. The model's JSON must pass a strict Pydantic schema, and a "high risk but safe" verdict is impossible.
- **Fails closed.** Bedrock errors, client setup failures, timeouts or malformed output always return `safe_to_process: false`. The reason is logged with secrets redacted.
- **No truncation bypass.** Long inputs are chunked with overlap, and every chunk is analysed.
- **Least-privilege IAM.** The Lambda role can invoke **one** Bedrock model and read/write **one** table. CDK tests enforce this.
- **No secrets in code.** Lambda reaches Bedrock through its IAM role. The browser uses short-lived Cognito tokens, the SPA uses the Authorization Code + PKCE flow, and GitHub deploys use OIDC rather than access keys.
- **Authentication and authorisation.** API Gateway validates the JWT before Lambda runs. `/audit` holds raw user inputs, so it is limited to the Cognito `admins` group, and the API enforces this.
- **Denial-of-wallet protection.** API throttling (10 requests/s, burst 20) caps Bedrock spend.
- **Data minimisation.** Clean inputs are stored only as SHA-256 hashes, and DynamoDB TTL deletes records after 90 days.
- **DevSecOps.** Bandit SAST, pip-audit, CDK security assertions, and an eval gate that fails the build when detection regresses.

---

## Evaluation

`eval/dataset.jsonl` holds **138 labelled examples**: 60 benign and 78 attacks across 9 categories. Half the benign set is deliberately hard: harmless requests that contain trigger words (*"How do I decode base64 in Python?"*, *"Act as my Spanish tutor"*).

```bash
python eval/run_eval.py --mode rules                       # no API key needed
python eval/run_eval.py --mode all                         # rules vs llm vs hybrid
python eval/run_eval.py --mode all --engine graph          # same, through the LangGraph pipeline
LLM_PROVIDER=bedrock python eval/run_eval.py --mode hybrid # same, on Amazon Bedrock
python eval/run_eval.py --hf deepset/prompt-injections --split test --mode hybrid   # public benchmark
```

### Results (in-house set)

| Mode | Precision | Recall | F1 | FPR | No-LLM requests | Cost / 1k req | p95 latency |
|---|---|---|---|---|---|---|---|
| rules | 68.1% | 41.0% | 0.512 | 25.0% | 100% | $0 | <1 ms |
| llm | 100.0% | 100.0% | 1.000 | 0.0% | 0% | $0.85 | 1.49 s |
| hybrid | 95.1% | 100.0% | 0.975 | 6.7% | 16.7% | $0.71 | 1.49 s |

### Independent benchmark

[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), test split (116 examples, not used for tuning):

| Mode | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| hybrid | 100.0% | 73.3% | 0.846 | 0.0% |

**What the numbers show:**
- **Regex alone catches only 41% of attacks.** It misses paraphrased overrides, injection hidden in documents, encodings, other languages and social engineering. Adding Claude lifts recall to **100%** on the in-house set.
- **Hybrid trades 4 false positives for 16% lower cost.** The false positives are users *quoting* attacks, and 17% of requests are resolved instantly by high-precision rules with no LLM call.
- **On unseen public data:** zero false positives, but recall drops to 73%. The in-house set overstates real-world recall, which is why both are reported.

### Limitations

- The in-house dataset is small and hand-written, and the rule tiers were calibrated on it once. Treat it as a development set.
- An LLM-based classifier can itself be attacked. Fencing, schema validation and failing closed reduce that risk but don't remove it.
- This is one layer of defence. It doesn't replace least-privilege tool access, output filtering, or human approval for high-impact actions.

---

## Use it from an AI agent (MCP)

`mcp_server.py` exposes two read-only tools:

| Tool | What it does |
|---|---|
| `scan_prompt(text, mode="hybrid")` | Returns a verdict: `safe_to_process`, risk level, attack type, reasoning, cost and latency |
| `list_detection_rules()` | Lists the rule layer and its tiers, for transparency |

**Claude Desktop:** add this to `claude_desktop_config.json`, using absolute paths:
```json
{
  "mcpServers": {
    "ai-guardrail": {
      "command": "C:\\path\\to\\AI-Security-Detector\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\AI-Security-Detector\\mcp_server.py"],
      "env": { "ANTHROPIC_API_KEY": "sk-ant-..." }
    }
  }
}
```
**Claude Code:** `claude mcp add ai-guardrail -- python /path/to/mcp_server.py`

---

## Run locally

```bash
pip install -r requirements-dev.txt
pytest                         # 119 tests: no API key, no AWS account needed
python app.py                  # local Flask API on http://127.0.0.1:5000
```
Set `ANTHROPIC_API_KEY` (Anthropic API) or `LLM_PROVIDER=bedrock` (uses your AWS credentials) for the LLM modes.

## Deploy to AWS

See **[DEPLOY.md](DEPLOY.md)** for the step-by-step guide: Bedrock access, `cdk deploy`, creating a user, then running the dashboard locally or on Amplify. Running cost is a few dollars a month at most. Lambda, API Gateway, Cognito and DynamoDB fit in the free tier, and Bedrock Haiku costs roughly $0.7 per 1,000 scans. `npx cdk destroy` removes everything.

---

## Project structure

```
├── detector.py            Rules, normalisation, prompt fencing, schema, Anthropic/Bedrock provider
├── graph.py               The pipeline as a LangGraph StateGraph
├── mcp_server.py          MCP server (scan_prompt, list_detection_rules)
├── lambda_handler.py      AWS Lambda entry point (API Gateway HTTP API v2, RBAC, EMF metrics)
├── dynamo_store.py        DynamoDB single-table store (day-sharded keys, TTL)
├── telemetry.py           Cost maths, timer, JSON logs, CloudWatch EMF
├── app.py / audit_log.py  Local Flask API + SQLite
├── scripts/build_lambda.py  Builds the Linux Lambda bundle (works from Windows, no Docker)
├── infra/                 AWS CDK app in TypeScript, plus Jest security tests
├── web/                   Next.js + TypeScript dashboard (Cognito OIDC login)
├── eval/                  Dataset, harness, results
├── tests/                 119 pytest tests (graph parity, MCP stdio, moto-mocked AWS…)
└── .github/workflows/     CI (Python, CDK, web) + manual OIDC deploy
```

## Tests and CI

| Suite | What it proves |
|---|---|
| `pytest` (119) | Rules, LLM path with a fake model, fail-closed behaviour, graph ≡ classic parity on all 138 examples × 3 modes, MCP over real stdio, Lambda + DynamoDB against mocked AWS, admin-only audit |
| `infra` Jest (7) | Least-privilege Bedrock IAM, JWT on every route except `/health`, throttling, Cognito hardening, DynamoDB TTL/PITR |
| `web` build | Type-safe dashboard that builds as a static export |
| Bandit, pip-audit, eval gate | SAST, dependency advisories, detection-quality regression gate |

---

## Screenshots

*(Captured with demo data.)*

| Scan | Metrics |
|---|---|
| ![Scan](docs/screenshots/scan.png) | ![Metrics](docs/screenshots/metrics.png) |

---

## Author

**Sathvika Mannepally**
Bachelor of Information Technology (AI & Cybersecurity), Macquarie University
GitHub: [@Sathvika2711](https://github.com/Sathvika2711) · Portfolio: [sathvika2711.github.io](https://sathvika2711.github.io)
