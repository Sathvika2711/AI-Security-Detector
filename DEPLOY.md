# Deploying to AWS: step by step (Windows / PowerShell)

Total time is about 1–2 hours the first time. Cost is a few dollars a month at most, and `npx cdk destroy` removes everything.

> **Never commit or paste AWS keys or tokens anywhere.** This guide uses AWS IAM Identity Center sign-in, so there are no long-lived keys on your laptop at all.

---

## 0. Install the tools (one time)

| Tool | How | Check with |
|---|---|---|
| Python 3.12+ | already installed | `python --version` |
| Node.js 20 LTS | nodejs.org → LTS installer | `node --version` |
| AWS CLI v2 | aws.amazon.com/cli → Windows installer | `aws --version` |

Close and reopen VS Code after installing, so the terminal picks them up.

---

## 1. Create and secure the AWS account

1. Create an account at **aws.amazon.com** (needs a card, which is only charged for usage beyond the free tier).
2. Turn on **MFA for the root user**: account menu (top right) → **Security credentials** → **Assign MFA device**.
3. Set up a **budget alarm**: search **Billing and Cost Management** → **Budgets** → **Create budget** → *Monthly cost budget* → **$10** → your email.
4. Create a day-to-day admin login, so you don't use the root user:
   - Search **IAM Identity Center** → **Enable** (choose region **Asia Pacific (Sydney)**).
   - **Users** → **Add user** → your email → finish the email invite and set a password plus MFA.
   - **AWS accounts** → tick your account → **Assign users or groups** → your user → **Create permission set** → *Predefined* → **AdministratorAccess** → finish.
   - Copy the **AWS access portal URL** from the Identity Center **Dashboard** (it looks like `https://d-xxxxxxxxxx.awsapps.com/start`).
5. Connect the CLI:
   ```powershell
   aws configure sso
   ```
   Give it the portal URL and region `ap-southeast-2`, approve in the browser, pick the account and AdministratorAccess, and call the profile **`guardrail`**.
6. Use that profile in this terminal:
   ```powershell
   $env:AWS_PROFILE = "guardrail"
   aws sts get-caller-identity
   ```
   You should see your account ID. When the session expires (after a few hours), run `aws sso login`.

---

## 2. Turn on Claude in Amazon Bedrock

1. Switch the console region (top right) to **Asia Pacific (Sydney) ap-southeast-2**.
2. Search **Amazon Bedrock**.
   - If there's a **Model access** page in the left menu, request access to **Anthropic → Claude Haiku 4.5**. The first time, Anthropic asks for a short use-case form ("portfolio project: prompt-injection detection").
   - If there's no Model access page, models are enabled automatically on first use.
3. Find the model ID to call: **Bedrock → Cross-region inference** (or **Inference profiles**) → find **Claude Haiku 4.5** → copy its **Inference profile ID**, e.g. `au.anthropic.claude-haiku-4-5-20251001-v1:0`.
4. Test it from your repo with the existing eval:
   ```powershell
   $env:LLM_PROVIDER = "bedrock"
   $env:BEDROCK_MODEL_ID = "PASTE-THE-ID"
   python eval/run_eval.py --mode hybrid --limit 5
   ```
   It works if a table prints with no `llm_call_failed` lines. If you get `AccessDeniedException`, model access isn't approved yet; wait a few minutes. A `ValidationException` means the model ID is wrong.

---

## 3. Configure and deploy the backend

1. Open `infra/cdk.json` and set:
   - `bedrockModelId`: the ID from step 2
   - `cognitoDomainPrefix`: must be globally unique, lowercase, letters, digits and hyphens, e.g. `ai-guardrail-sathvika2711`
   - `frontendUrls`: leave as `http://localhost:3000` for now
2. Build and deploy:
   ```powershell
   cd infra
   npm ci
   python ..\scripts\build_lambda.py
   npx cdk bootstrap        # first time only, per account/region
   npx cdk deploy
   ```
   Type `y` when it lists the IAM changes. This takes about 3–5 minutes.
3. At the end it prints **Outputs**. Copy them into a note:
   ```
   AiGuardrailStack.ApiUrl = https://xxxx.execute-api.ap-southeast-2.amazonaws.com
   AiGuardrailStack.UserPoolId = ap-southeast-2_XXXX
   AiGuardrailStack.UserPoolClientId = xxxxxxxx
   AiGuardrailStack.CognitoDomain = https://ai-guardrail-sathvika2711.auth.ap-southeast-2.amazoncognito.com
   AiGuardrailStack.DashboardUrl = https://ap-southeast-2.console.aws.amazon.com/cloudwatch/...
   ```
4. Quick check (no login needed):
   ```powershell
   Invoke-RestMethod "$((aws cloudformation describe-stacks --stack-name AiGuardrailStack --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text))/health"
   ```
   It should return `status: ok`.

---

## 4. Create your login (and make yourself admin)

Replace the pool ID and email:
```powershell
$POOL = "ap-southeast-2_XXXX"
$EMAIL = "you@example.com"
aws cognito-idp admin-create-user --user-pool-id $POOL --username $EMAIL --user-attributes Name=email,Value=$EMAIL Name=email_verified,Value=true
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username $EMAIL --group-name admins
```
You'll get an email with a temporary password, and you'll set a new one at first sign-in. To show RBAC working, create a second user and **don't** add them to `admins`. That user will see "Access restricted" on the Audit log tab.

---

## 5. Run the dashboard locally

```powershell
cd ..\web
copy .env.example .env.local
```
Open `web/.env.local` and paste in the values from step 3. Then:
```powershell
npm ci
npm run dev
```
Open **http://localhost:3000**, click **Sign in**, then try the **Scan** tab with the example chips, then **Metrics** and **Audit log**.

The first scan after a deploy can take a few seconds, because the Lambda cold start loads LangChain. After that, scans take about 1–2 s.

---

## 6. Put the dashboard online (AWS Amplify)

1. Push your code to GitHub first.
2. Console → **AWS Amplify** → **Create new app** → **GitHub** → authorise → pick `AI-Security-Detector` and the branch.
3. Tick **My app is a monorepo** → app root **`web`**. Amplify picks up `amplify.yml`.
4. **Advanced settings → Environment variables**: add the five `NEXT_PUBLIC_*` values from `.env.local`.
5. **Save and deploy**. You'll get a URL like `https://main.d1abc2def3.amplifyapp.com`.
6. Allow that URL to log in and call the API by adding it to `infra/cdk.json`:
   ```json
   "frontendUrls": "http://localhost:3000,https://main.d1abc2def3.amplifyapp.com"
   ```
   then redeploy:
   ```powershell
   cd infra
   npx cdk deploy
   ```

---

## 7. Record your Bedrock results

```powershell
$env:LLM_PROVIDER = "bedrock"
python eval/run_eval.py --mode all --engine graph
```
Add the rows to the README, then compare cost and latency with the Anthropic-API numbers.

## 8. Check the security controls (good for interviews)

First set `$API = "https://xxxx.execute-api.ap-southeast-2.amazonaws.com"` (your ApiUrl).

| Test | Expected |
|---|---|
| Call `/analyse` with no token (`Invoke-RestMethod -Method Post "$API/analyse"`) | **401 Unauthorized**, rejected by API Gateway before Lambda runs |
| Non-admin user opens Audit log | **403**, enforced by the API |
| CloudWatch → Dashboards → `ai-guardrail` | Requests, blocked, p50/p95 latency, cost |
| IAM → Roles → GuardrailFunction role | Bedrock permission scoped to one model only |

---

## Clean up

```powershell
cd infra
npx cdk destroy
```
Then delete the Amplify app in the console if you created one.

---

## Optional: deploy from GitHub Actions (OIDC, no stored keys)

1. IAM → **Identity providers** → **Add provider** → OpenID Connect → URL `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`.
2. IAM → **Roles** → **Create role** → *Web identity* → that provider → audience `sts.amazonaws.com` → GitHub organisation `Sathvika2711`, repository `AI-Security-Detector`, branch `main` → attach **AdministratorAccess** (or a tighter CDK deploy policy) → name it `github-deploy`.
3. GitHub repo → **Settings → Secrets and variables → Actions**:
   - Secret `AWS_DEPLOY_ROLE_ARN` = the role's ARN
   - Variable `FRONTEND_URLS` = `http://localhost:3000,https://main.xxxx.amplifyapp.com`
4. **Actions → Deploy → Run workflow.**

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `AccessDeniedException` calling Bedrock | Model access not approved yet, or the wrong region (must be Sydney) |
| `ValidationException ... model identifier is invalid` | Copy the exact inference profile ID from Bedrock → Cross-region inference |
| `cdk deploy` says the domain prefix exists | Pick another `cognitoDomainPrefix` |
| Browser console shows a **CORS** error | The page's URL isn't in `frontendUrls`. Add it and run `npx cdk deploy` |
| Cognito shows `redirect_mismatch` | Same fix: the URL must be in `frontendUrls` |
| `ExpiredToken` / `The SSO session has expired` | `aws sso login` |
| `This stack uses assets... run cdk bootstrap` | `npx cdk bootstrap` |
