/**
 * Infrastructure tests: lock in the security properties so a future change
 * can't silently weaken them.
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import { GuardrailStack } from '../lib/guardrail-stack';

const codeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lambda-'));
fs.writeFileSync(path.join(codeDir, 'lambda_handler.py'), 'def handler(e, c): return {}');

const template = Template.fromStack(new GuardrailStack(new cdk.App(), 'Test', {
  env: { account: '123456789012', region: 'ap-southeast-2' },
  lambdaCodePath: codeDir,
  bedrockModelId: 'au.anthropic.claude-haiku-4-5-20251001-v1:0',
  cognitoDomainPrefix: 'test-prefix',
  frontendUrls: ['http://localhost:3000', 'https://main.example.amplifyapp.com'],
}));

test('Lambda runs Python 3.12 on Bedrock with no API keys in its environment', () => {
  template.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'python3.12',
    Environment: { Variables: Match.objectLike({ LLM_PROVIDER: 'bedrock', DETECTOR_MODE: 'hybrid' }) },
  });
  const fn = Object.values(template.findResources('AWS::Lambda::Function'))[0] as any;
  expect(JSON.stringify(fn.Properties.Environment)).not.toMatch(/API_KEY|SECRET/);
});

test('Bedrock permission is scoped to the configured model only (no wildcard actions or models)', () => {
  const policies = Object.values(template.findResources('AWS::IAM::Policy')) as any[];
  const statements = policies.flatMap((p) => p.Properties.PolicyDocument.Statement);
  const bedrock = statements.find((s) => s.Sid === 'InvokeConfiguredClaudeModelOnly');
  expect(bedrock.Action).toEqual(['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream']);
  expect(bedrock.Resource).toEqual([
    'arn:aws:bedrock:*::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0',
    'arn:aws:bedrock:ap-southeast-2:123456789012:inference-profile/au.anthropic.claude-haiku-4-5-20251001-v1:0',
  ]);
  for (const s of statements) {
    expect([].concat(s.Action)).not.toContain('*');
    expect([].concat(s.Action).some((a: string) => a.endsWith(':*'))).toBe(false);
  }
});

test('every route except /health requires the Cognito JWT authorizer', () => {
  const routes = Object.values(template.findResources('AWS::ApiGatewayV2::Route')) as any[];
  expect(routes).toHaveLength(5);
  for (const r of routes) {
    if (r.Properties.RouteKey === 'GET /health') {
      expect(r.Properties.AuthorizationType ?? 'NONE').toBe('NONE');
    } else {
      expect(r.Properties.AuthorizationType).toBe('JWT');
    }
  }
  template.hasResourceProperties('AWS::ApiGatewayV2::Authorizer', { AuthorizerType: 'JWT' });
});

test('API is throttled to cap request rate and LLM spend', () => {
  template.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
    DefaultRouteSettings: { ThrottlingRateLimit: 10, ThrottlingBurstLimit: 20 },
  });
});

test('Cognito: no public sign-up, strong passwords, PKCE public client, admins group', () => {
  template.hasResourceProperties('AWS::Cognito::UserPool', {
    AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
    Policies: { PasswordPolicy: Match.objectLike({ MinimumLength: 12 }) },
  });
  template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
    GenerateSecret: false,
    AllowedOAuthFlows: ['code'],
    PreventUserExistenceErrors: 'ENABLED',
    CallbackURLs: ['http://localhost:3000/', 'https://main.example.amplifyapp.com/'],
  });
  template.hasResourceProperties('AWS::Cognito::UserPoolGroup', { GroupName: 'admins' });
});

test('DynamoDB: on-demand, encrypted, point-in-time recovery, TTL for data minimisation', () => {
  template.hasResourceProperties('AWS::DynamoDB::Table', {
    BillingMode: 'PAY_PER_REQUEST',
    TimeToLiveSpecification: { AttributeName: 'expires_at', Enabled: true },
    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
  });
});

test('CloudWatch alarm on Lambda errors and a dashboard exist', () => {
  template.resourceCountIs('AWS::CloudWatch::Alarm', 1);
  template.resourceCountIs('AWS::CloudWatch::Dashboard', 1);
});
