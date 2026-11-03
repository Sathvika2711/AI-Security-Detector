#!/usr/bin/env node
/**
 * CDK app entry point. Settings come from cdk.json "context" and can be
 * overridden on the command line, e.g.
 *   npx cdk deploy -c bedrockModelId=au.anthropic.claude-haiku-4-5-20251001-v1:0
 */
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { GuardrailStack } from '../lib/guardrail-stack';

const app = new cdk.App();
const ctx = (key: string): string => {
  const value = app.node.tryGetContext(key);
  if (!value) throw new Error(`Missing CDK context value "${key}" (set it in cdk.json or with -c ${key}=...)`);
  return value;
};

new GuardrailStack(app, 'AiGuardrailStack', {
  env: { account: process.env.CDK_DEFAULT_ACCOUNT, region: ctx('region') }, // Sydney by default (cdk.json)
  lambdaCodePath: path.join(__dirname, '..', '..', 'build', 'lambda'),
  bedrockModelId: ctx('bedrockModelId'),
  cognitoDomainPrefix: ctx('cognitoDomainPrefix'),
  frontendUrls: ctx('frontendUrls').split(',').map((u) => u.trim()).filter(Boolean),
  description: 'AI Guardrail: LangGraph prompt-injection detector on Lambda + Bedrock, Cognito-protected API',
});
