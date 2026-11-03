# v3 walkthrough: how it works and how to explain it

Read this file before any interview. Every claim below is backed by code and tests in this repo.

## 1. The 30-second pitch

> "I built a guardrail service that screens text for prompt injection before it reaches an LLM or an agent. The detection pipeline is a LangGraph state machine: high-precision rules block obvious attacks for free, and Claude on Amazon Bedrock classifies everything else. It runs serverless on Lambda behind API Gateway with Cognito OAuth, it's exposed to agents as an MCP tool, and it has a Next.js dashboard. All the infrastructure is CDK in TypeScript. On a public benchmark it had zero false positives and 73% recall, and every deploy is gated by tests, SAST and an evaluation threshold."

## 2. Request flow (follow one request)

1. **Browser.** The user signs in with Cognito using the Authorization Code + PKCE flow and gets an access token (JWT). `web/app/providers.tsx`
2. **API Gateway.** The JWT authorizer checks the token's signature, issuer, expiry and audience. A bad token gets a 401, and **Lambda never runs**. `infra/lib/guardrail-stack.ts`
3. **Lambda.** `lambda_handler.py` validates the body (type, size), then calls `analyse_input_graph()`.
4. **LangGraph.** `graph.py` runs the request through the nodes:
   - `screen` (empty or too long?)
   - `rules` (normalise the text, then regex)
   - `block` if a strong rule matched: high risk with **no LLM call**
   - `cache` (the same text recently: reuse the verdict for $0)
   - `classify`: Claude on Bedrock, with the input fenced as untrusted data
   - `finalise`, or `fail_closed` on any error or invalid output
5. **Storage.** `dynamo_store.py` writes a metrics row (a hash only) for every request, plus an audit row (with text) for flagged inputs. Both expire after 90 days.
6. **Metrics.** A one-line EMF JSON log becomes CloudWatch metrics (latency, cost, blocked) with no extra API calls.

## 3. Why each technology (one line each)

| Choice | Why |
|---|---|
| **LangGraph** | The routing logic becomes explicit nodes and edges, so it's testable, and new steps slot in as nodes |
| **Bedrock instead of the Anthropic API** | No API key to manage, because IAM handles access. Data stays in AWS, which matters in regulated industries |
| **Lambda + HTTP API** | Pay per request, scales to zero, and suits spiky screening traffic |
| **DynamoDB single table** | No servers. Keys are sharded by day so there's no hot partition, and TTL handles data retention |
| **Cognito + JWT authorizer** | Standard OAuth 2.0 / OIDC, and authentication happens before code runs |
| **MCP** | Any agent can call the guardrail as a tool, with no custom integration per agent |
| **CDK in TypeScript** | Infrastructure is reviewable, testable code, and the same stack deploys every time |
| **Next.js static export** | Just static files, hosted cheaply on Amplify with no server to secure |

## 4. Likely interview questions (short answers)

**Why not just use the LLM for everything?**
Cost and latency. Strong rules handle about 17% of requests instantly and for free. LLM-only was more accurate, so hybrid is a deliberate cost/accuracy trade-off, and I measured it.

**Can your detector itself be prompt-injected?**
It's possible, so I reduced the risk: the input is fenced in tags, closing tags are neutralised, the output must match a strict schema, and a "high risk but safe" verdict is impossible. If anything fails, the system fails closed.

**How do you know the LangGraph version is correct?**
A parity test runs all 138 examples in all 3 modes through both engines and requires identical results.

**How do you stop someone running up your Bedrock bill?**
API Gateway throttling (10 requests/s), auth required on every route, a cache, rule short-circuiting, and a $10 budget alarm.

**What's least privilege here?**
The Lambda role can invoke one Bedrock model and read/write one table. A CDK test fails the build if a wildcard permission appears.

**Authentication vs authorisation?**
Authentication: API Gateway validates the Cognito JWT. Authorisation: Lambda checks the `cognito:groups` claim, so only `admins` can read the audit log. Hiding the tab in the UI isn't the control; the API is.

**How do you handle PII and retention?**
Clean inputs are stored as SHA-256 hashes only. Flagged inputs are truncated to 500 characters, and DynamoDB TTL deletes everything after 90 days.

**Why did recall drop on the public benchmark?**
My own dataset was hand-written and the rules were tuned once against it. Public data is the honest number: 0% false positives, 73% recall. Next I'd tune on the benchmark's train split and only report on test.

**What would you do next?**
Deploy the graph to Bedrock AgentCore Runtime, add output screening (check the model's answers too), use Bedrock Guardrails as an extra layer, and run a red-team set in CI.

## 5. Things to actually do yourself (so you can talk about them)

- Deploy it (DEPLOY.md), sign in, and scan the four example chips.
- Watch a request in CloudWatch Logs and on the dashboard.
- Run the Bedrock eval and note the cost and latency against the Anthropic API.
- Hit `/analyse` without a token and see the 401. Use a non-admin user on the audit log and see the 403.
- Connect the MCP server to Claude Desktop and ask Claude to scan a suspicious email.
- Read `graph.py` top to bottom. It's about 200 lines, and it's the heart of the project.
