/** Public, non-secret settings baked into the static build (all come from `cdk deploy` outputs). */
export const config = {
  apiUrl: (process.env.NEXT_PUBLIC_API_URL ?? '').replace(/\/$/, ''),
  region: process.env.NEXT_PUBLIC_COGNITO_REGION ?? 'ap-southeast-2',
  userPoolId: process.env.NEXT_PUBLIC_COGNITO_USER_POOL_ID ?? '',
  clientId: process.env.NEXT_PUBLIC_COGNITO_CLIENT_ID ?? '',
  cognitoDomain: (process.env.NEXT_PUBLIC_COGNITO_DOMAIN ?? '').replace(/\/$/, ''),
};

export const isConfigured = Boolean(config.apiUrl && config.userPoolId && config.clientId && config.cognitoDomain);

/** OIDC issuer for the Cognito user pool */
export const authority = `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`;
