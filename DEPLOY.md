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

1. **Use your existing AWS account if you have one.** If the sign-up page says *"Multi-session is not supported"* or *"You can't use your Builder ID to access existing accounts"*, you already have an account. Choose **Sign into an existing AWS account** and sign in as **Root user**. A Builder ID (used for Skill Builder) is **not** an AWS account.
   - No account yet? Create one at **aws.amazon.com**. The Free plan gives you credits and can't overcharge you.
2. Turn on **MFA for the root user**: account menu (top right) → **Security credentials** → **Assign MFA device** → **Authenticator app**.
3. Set a **budget alarm**: **Billing and Cost Management** → **Budgets** → **Create budget** → *Monthly cost budget* → **$10** → your email.
4. Create an **everyday admin user**, so you don't work as root:
   - **IAM** → **Users** → **Create user** → name `sathvika-admin` (names can't be changed later, so check the spelling).
   - Tick **Provide user access to the AWS Management Console** → **Custom password** → *untick* "must create a new password".
   - **Attach policies directly** → tick **AdministratorAccess** (the "AWS managed – job function" one).
   - Create the user, save the **Console sign-in URL**, then open the user → **Security credentials** → **Assign MFA device**.
   - **Don't create access keys.** `aws login` (next step) gives the CLI short-lived credentials instead.
5. Connect the CLI (AWS CLI 2.32 or newer):
   ```powershell
   pip install "botocore[crt]"      # Python needs this to read `aws login` credentials
   aws login                        # sign in as the IAM user, region ap-southeast-2
   aws sts get-caller-identity      # Arn must end in user/sathvika-admin, not root
   ```
   - If it says *"Profile 'default' is already configured with Access Key credentials"*, you have old keys saved. Run `aws sts get-caller-identity`: if it shows `InvalidClientTokenId` they're dead, so delete the `[default]` block in `%USERPROFILE%\.aws\credentials`. If they're live, also delete them in IAM.
   - If it logs you in as **root**, that's because the browser was signed in as root. Add an IAM-user session in the console (top-right menu → **Add session**), run `aws login` again, and pick that session (answer **y** to overwrite).
   - Sessions expire after a few hours. Just run `aws login` again.

## 2. Turn on Claude in Amazon Bedrock

1. Console region (top right): **Asia Pacific (Sydney) ap-southeast-2**.
2. **Amazon Bedrock** → **Model catalog** → **Claude Haiku 4.5** → **Submit use case details** (a one-time form Anthropic requires per account). Suggested answers: company *Personal project*, website your GitHub, intended users *Internal*, use case *"Portfolio project: a security guardrail that screens text for prompt injection before it reaches an AI application. Low-volume testing only."* Access starts within about 15 minutes.
3. Get the model ID from the CLI:
   ```powershell
   aws bedrock list-inference-profiles --region ap-southeast-2 --query "inferenceProfileSummaries[?contains(inferenceProfileId,'haiku-4-5')].inferenceProfileId" --output text
   ```
   Use the **`au.`** one (requests stay in Australian regions). Skip `global.`, which can route anywhere.
4. Test it:
   ```powershell
   $env:LLM_PROVIDER = "bedrock"
   $env:BEDROCK_MODEL_ID = "au.anthropic.claude-haiku-4-5-20251001-v1:0"
   python -c "import detector; print(detector._build_llm().invoke('Say hi').content)"
   ```
   A greeting means it works. For errors, see **Troubleshooting** at the end.

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
| `ResourceNotFoundException: Model use case details have not been submitted` | Submit the Anthropic form (Step 2.2) and wait 15 minutes |
| `AccessDeniedException: Your account is currently being verified` | New-account checks. Wait up to 2 hours; CloudFormation and CDK work meanwhile, so you can deploy anyway |
| `Missing Dependency: ... pip install "botocore[crt]"` | `pip install "botocore[crt]"`, which `aws login` credentials need |
| `ValidationException ... model identifier is invalid` | Use the exact `au.` ID from Step 2.3 (not a placeholder) |
| `AccessDeniedException` on the model after the form | Wrong region (must be Sydney), or IAM is missing `bedrock:InvokeModel` |
| Dashboard scans say **"LLM analysis unavailable"** | Bedrock is refusing calls, and the guardrail is correctly failing closed. Find the reason with `aws logs tail <log-group> --since 15m --filter-pattern llm_call_failed` (the `detail` field has the message) |
| `cdk deploy` says the domain prefix exists | Pick another `cognitoDomainPrefix` |
| Browser console shows a **CORS** error | The page's URL isn't in `frontendUrls`. Add it and run `npx cdk deploy` |
| Cognito shows `redirect_mismatch` | Same fix: the URL must be in `frontendUrls` |
| `ExpiredToken` / session expired | `aws login` |
| `This stack uses assets... run cdk bootstrap` | `npx cdk bootstrap` |
