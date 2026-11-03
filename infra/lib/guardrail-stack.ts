/**
 * guardrail-stack.ts — All AWS infrastructure for the AI Guardrail, as code.
 *
 *   Cognito (OAuth 2.0 / OIDC login)  ──JWT──>  API Gateway HTTP API (JWT authorizer, throttling)
 *                                                    │
 *                                                    ▼
 *                         Lambda (Python 3.12, LangGraph pipeline) ──> Amazon Bedrock (Claude Haiku)
 *                                                    │
 *                                     DynamoDB (single table, TTL)   CloudWatch (EMF metrics, alarm, dashboard)
 *
 * Security choices worth knowing for interviews:
 *   - Least-privilege IAM: Lambda may invoke ONE Bedrock model and read/write ONE table.
 *   - No secrets anywhere: Lambda uses its IAM role for Bedrock; the browser uses Cognito tokens.
 *   - Every route except /health needs a valid Cognito JWT, checked before Lambda runs.
 *   - API throttling caps request rate, which also caps LLM spend ("denial of wallet").
 *   - DynamoDB TTL deletes old records automatically; clean inputs are stored as hashes only.
 */
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import * as authorizers from 'aws-cdk-lib/aws-apigatewayv2-authorizers';
import * as integrations from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';

export interface GuardrailStackProps extends cdk.StackProps {
  /** Folder produced by scripts/build_lambda.py */
  lambdaCodePath: string;
  /** Bedrock model or cross-region inference profile ID, copied from the Bedrock console */
  bedrockModelId: string;
  /** Globally unique prefix for the Cognito hosted login domain */
  cognitoDomainPrefix: string;
  /** Where the dashboard runs, e.g. http://localhost:3000 and your Amplify URL */
  frontendUrls: string[];
}

const SERVICE = 'ai-guardrail';
const NAMESPACE = 'AIGuardrail';
const INFERENCE_PROFILE_PREFIXES = ['au.', 'apac.', 'us.', 'eu.', 'jp.', 'global.'];

export class GuardrailStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: GuardrailStackProps) {
    super(scope, id, props);

    // ── DynamoDB ────────────────────────────────────────────
    const table = new dynamodb.Table(this, 'GuardrailTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expires_at',
      encryption: dynamodb.TableEncryption.AWS_MANAGED,
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: cdk.RemovalPolicy.DESTROY, // portfolio project: `cdk destroy` removes everything
    });

    // ── Lambda ──────────────────────────────────────────────
    const logGroup = new logs.LogGroup(this, 'GuardrailLogs', {
      retention: logs.RetentionDays.TWO_WEEKS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const fn = new lambda.Function(this, 'GuardrailFunction', {
      runtime: lambda.Runtime.PYTHON_3_12,
      architecture: lambda.Architecture.X86_64,
      handler: 'lambda_handler.handler',
      code: lambda.Code.fromAsset(props.lambdaCodePath),
      memorySize: 1024,
      timeout: cdk.Duration.seconds(30),
      logGroup,
      environment: {
        GUARDRAIL_TABLE: table.tableName,
        LLM_PROVIDER: 'bedrock',
        BEDROCK_MODEL_ID: props.bedrockModelId,
        DETECTOR_MODE: 'hybrid',
        ADMIN_GROUP: 'admins',
        SERVICE_NAME: SERVICE,
        METRIC_NAMESPACE: NAMESPACE,
        RETENTION_DAYS: '90',
      },
    });

    table.grantReadWriteData(fn);

    // Least privilege: only the configured Claude model (and, for a cross-region
    // inference profile, the underlying foundation model in the regions it routes to).
    const isProfile = INFERENCE_PROFILE_PREFIXES.some((p) => props.bedrockModelId.startsWith(p));
    const baseModelId = isProfile
      ? props.bedrockModelId.substring(props.bedrockModelId.indexOf('.') + 1)
      : props.bedrockModelId;
    const bedrockResources = [`arn:aws:bedrock:*::foundation-model/${baseModelId}`];
    if (isProfile) {
      bedrockResources.push(`arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${props.bedrockModelId}`);
    }
    fn.addToRolePolicy(new iam.PolicyStatement({
      sid: 'InvokeConfiguredClaudeModelOnly',
      actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
      resources: bedrockResources,
    }));

    // ── Cognito (OAuth 2.0 / OIDC) ──────────────────────────
    const userPool = new cognito.UserPool(this, 'UserPool', {
      selfSignUpEnabled: false, // admins create users; no public sign-up
      signInAliases: { email: true },
      standardAttributes: { email: { required: true, mutable: false } },
      passwordPolicy: { minLength: 12, requireDigits: true, requireLowercase: true, requireUppercase: true, requireSymbols: true },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { otp: true, sms: false },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    new cognito.CfnUserPoolGroup(this, 'AdminsGroup', {
      userPoolId: userPool.userPoolId,
      groupName: 'admins',
      description: 'Can read the audit log (raw flagged inputs)',
    });

    const callbackUrls = props.frontendUrls.map((u) => u.replace(/\/?$/, '/'));
    const client = userPool.addClient('DashboardClient', {
      generateSecret: false, // browser app: public client using Authorization Code + PKCE
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls,
        logoutUrls: callbackUrls,
      },
      preventUserExistenceErrors: true,
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      refreshTokenValidity: cdk.Duration.days(1),
    });

    const domain = userPool.addDomain('HostedLogin', {
      cognitoDomain: { domainPrefix: props.cognitoDomainPrefix },
    });

    // ── API Gateway HTTP API ────────────────────────────────
    const api = new apigw.HttpApi(this, 'GuardrailApi', {
      apiName: SERVICE,
      corsPreflight: {
        allowOrigins: props.frontendUrls.map((u) => u.replace(/\/$/, '')),
        allowMethods: [apigw.CorsHttpMethod.GET, apigw.CorsHttpMethod.POST, apigw.CorsHttpMethod.OPTIONS],
        allowHeaders: ['Authorization', 'Content-Type'],
        maxAge: cdk.Duration.hours(1),
      },
    });

    const jwtAuth = new authorizers.HttpJwtAuthorizer('CognitoJwt',
      `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
      { jwtAudience: [client.userPoolClientId] });

    const integration = new integrations.HttpLambdaIntegration('GuardrailIntegration', fn);

    api.addRoutes({ path: '/health', methods: [apigw.HttpMethod.GET], integration });
    api.addRoutes({ path: '/analyse', methods: [apigw.HttpMethod.POST], integration, authorizer: jwtAuth });
    for (const path of ['/metrics', '/stats', '/audit']) {
      api.addRoutes({ path, methods: [apigw.HttpMethod.GET], integration, authorizer: jwtAuth });
    }

    // Throttling caps request rate — and therefore Bedrock spend.
    const stage = api.defaultStage!.node.defaultChild as apigw.CfnStage;
    stage.defaultRouteSettings = { throttlingRateLimit: 10, throttlingBurstLimit: 20 };

    // ── CloudWatch ──────────────────────────────────────────
    const emf = (metricName: string, statistic: string, label?: string) => new cloudwatch.Metric({
      namespace: NAMESPACE, metricName, statistic, label: label ?? metricName,
      dimensionsMap: { Service: SERVICE }, period: cdk.Duration.minutes(5),
    });

    new cloudwatch.Alarm(this, 'LambdaErrorsAlarm', {
      alarmDescription: 'Guardrail Lambda is erroring (requests are failing closed)',
      metric: fn.metricErrors({ period: cdk.Duration.minutes(5) }),
      threshold: 1,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    const dashboard = new cloudwatch.Dashboard(this, 'GuardrailDashboard', { dashboardName: SERVICE });
    dashboard.addWidgets(
      new cloudwatch.GraphWidget({ title: 'Requests vs blocked', left: [emf('Requests', 'Sum'), emf('Blocked', 'Sum')] }),
      new cloudwatch.GraphWidget({ title: 'Latency (ms)', left: [emf('LatencyMs', 'p50', 'p50'), emf('LatencyMs', 'p95', 'p95')] }),
      new cloudwatch.GraphWidget({ title: 'LLM calls & cache hits', left: [emf('LLMCalls', 'Sum'), emf('CacheHits', 'Sum')] }),
      new cloudwatch.GraphWidget({ title: 'Bedrock cost (USD)', left: [emf('CostUSD', 'Sum')] }),
    );

    // ── Outputs (paste these into web/.env.local) ───────────
    new cdk.CfnOutput(this, 'ApiUrl', { value: api.apiEndpoint });
    new cdk.CfnOutput(this, 'Region', { value: this.region });
    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: client.userPoolClientId });
    new cdk.CfnOutput(this, 'CognitoDomain', { value: domain.baseUrl() });
    new cdk.CfnOutput(this, 'TableName', { value: table.tableName });
    new cdk.CfnOutput(this, 'DashboardUrl', {
      value: `https://${this.region}.console.aws.amazon.com/cloudwatch/home?region=${this.region}#dashboards:name=${SERVICE}`,
    });
  }
}
